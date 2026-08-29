package ccache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func kcmRequest(op uint16, args ...[]byte) []byte {
	request := []byte{2, 0, byte(op >> 8), byte(op)}
	for _, arg := range args {
		request = append(request, arg...)
	}
	return request
}

func TestKCMRoundTripAndCollection(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "kcm.sock")
	server := NewKCMServer(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeListener(listener)
	}()
	defer func() {
		_ = server.Close()
		<-done
		_ = os.Remove(socket)
	}()

	originalSocket := DefaultKCMSocketPath
	DefaultKCMSocketPath = socket
	defer func() { DefaultKCMSocketPath = originalSocket }()

	cache, err := Resolve("KCM:")
	if err != nil {
		t.Fatalf("resolve KCM: %v", err)
	}
	value := testCache()
	if err := cache.Write(value); err != nil {
		t.Fatalf("write KCM cache: %v", err)
	}
	got, err := cache.Read()
	if err != nil {
		t.Fatalf("read KCM cache: %v", err)
	}
	if got.DefaultPrincipal.Realm != value.DefaultPrincipal.Realm ||
		len(got.DefaultPrincipal.Components) != len(value.DefaultPrincipal.Components) ||
		got.DefaultPrincipal.Components[0] != value.DefaultPrincipal.Components[0] ||
		len(got.Credentials) != 1 {
		t.Fatalf("KCM cache = %#v, want %#v", got, value)
	}
	match := value.Credentials[0]
	retrieved, err := cache.Retrieve(match, 0)
	if err != nil || retrieved.Server.Realm != match.Server.Realm ||
		len(retrieved.Server.Components) != len(match.Server.Components) ||
		retrieved.Server.Components[0] != match.Server.Components[0] {
		t.Fatalf("KCM retrieve = %#v, %v", retrieved, err)
	}
	if err := cache.SetKDCOffset(-42); err != nil {
		t.Fatal(err)
	}
	offset, err := cache.KDCOffset()
	if err != nil || offset != -42 {
		t.Fatalf("KCM offset = %d, %v", offset, err)
	}

	other, err := Resolve("KCM:other")
	if err != nil {
		t.Fatal(err)
	}
	otherValue := testCache()
	otherValue.DefaultPrincipal = principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"bob"},
	}
	if err := other.Write(otherValue); err != nil {
		t.Fatal(err)
	}
	caches, err := cache.Collection()
	if err != nil {
		t.Fatalf("KCM collection: %v", err)
	}
	if len(caches) != 2 || caches[0].Name() != "KCM:default" {
		t.Fatalf("KCM collection = %#v", caches)
	}
}

func TestKCMWireFramingAndFlagMapping(t *testing.T) {
	var wire bytes.Buffer
	request := []byte{2, 0, 0, 7, 0xaa}
	if err := writeFrame(&wire, request); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(wire.Bytes()[:4]); got != uint32(len(request)) {
		t.Fatalf("request length = %d", got)
	}
	if !bytes.Equal(wire.Bytes()[4:], request) {
		t.Fatalf("request payload = %x", wire.Bytes()[4:])
	}
	reply := append([]byte{0, 0, 0, 0}, []byte("reply")...)
	var framed bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(reply)))
	_, _ = framed.Write(length[:])
	_, _ = framed.Write([]byte{0, 0, 0, 0})
	_, _ = framed.Write(reply)
	decoded, err := readFrame(&framed)
	if err != nil || !bytes.Equal(decoded, reply) {
		t.Fatalf("decoded reply = %x, %v", decoded, err)
	}
	flags := MITMatchTimes | MITMatchIsSKey | MITMatchServerName | MITMatchKeyType
	want := KCMMatchTimes | KCMMatchIsSKey | KCMMatchServerName | KCMMatchKeyType
	if got := MapTCFlags(flags); got != want {
		t.Fatalf("MapTCFlags = %#x, want %#x", got, want)
	}
}

func TestKCMMatchCredentialRoundTrip(t *testing.T) {
	value := testCache().Credentials[0]
	value.Enctype = 18
	value.Key = []byte{1, 2, 3, 4}
	value.Ticket = []byte("ticket")
	value.SecondTicket = []byte("second")
	value.Addresses = []Address{{Type: 2, Data: []byte{127, 0, 0, 1}}}
	value.AuthData = []AuthData{{Type: 128, Data: []byte("auth")}}
	wire, err := marshalMatchCredential(value)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalMatchCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, value) {
		t.Fatalf("match credential = %#v, want %#v", got, value)
	}
}

func TestKCMMatchingFlagsCompareFullServerAndAuthData(t *testing.T) {
	value := testCache().Credentials[0]
	tag := value
	tag.Server.Components = append([]string(nil), value.Server.Components...)
	tag.Server.Components = append(tag.Server.Components, "EXTRA")
	tag.Server.Components[1] = "OTHER"
	if credentialMatches(value, tag, kcmTCMatchSrvName) {
		t.Fatal("server-name-only matched a different server component")
	}
	tag = value
	tag.AuthData = append([]AuthData(nil), value.AuthData...)
	tag.AuthData = append(tag.AuthData, AuthData{Type: 1, Data: []byte("different")})
	if credentialMatches(value, tag, kcmTCMatchAuthData) {
		t.Fatal("authdata matching ignored contents")
	}
}

func TestKCMServerStableCredentialUUIDsAndMissingReads(t *testing.T) {
	server := NewKCMServer("")
	name := "cache"
	if _, code := server.dispatch(append([]byte{2, 0, 0, byte(kcmOpGetPrincipal)}, cstring(name)...)); code != kcmErrNoFile {
		t.Fatalf("missing principal status = %d", code)
	}
	if len(server.caches) != 0 {
		t.Fatal("missing read created a cache")
	}
	cache := testCache()
	principalBytes, err := marshalPrincipalBytes(cache.DefaultPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	initRequest := append([]byte{2, 0, 0, byte(kcmOpInitialize)}, append(cstring(name), principalBytes...)...)
	if _, code := server.dispatch(initRequest); code != 0 {
		t.Fatalf("initialize status = %d", code)
	}
	badStore := append([]byte{2, 0, 0, byte(kcmOpStore)}, append(cstring(name), 1, 2, 3)...)
	if _, code := server.dispatch(badStore); code != kcmErrInternal {
		t.Fatalf("malformed store status = %d", code)
	}
	for _, credential := range cache.Credentials[:1] {
		raw, err := marshalCredentialBytes(credential)
		if err != nil {
			t.Fatal(err)
		}
		storeRequest := append([]byte{2, 0, 0, byte(kcmOpStore)}, append(cstring(name), raw...)...)
		if _, code := server.dispatch(storeRequest); code != 0 {
			t.Fatalf("store status = %d", code)
		}
	}
	other := cache.Credentials[0]
	other.Server.Components = []string{"other"}
	raw, err := marshalCredentialBytes(other)
	if err != nil {
		t.Fatal(err)
	}
	storeRequest := append([]byte{2, 0, 0, byte(kcmOpStore)}, append(cstring(name), raw...)...)
	if _, code := server.dispatch(storeRequest); code != 0 {
		t.Fatalf("second store status = %d", code)
	}
	uuids, code := server.dispatch(append([]byte{2, 0, 0, byte(kcmOpGetCredUUIDList)}, cstring(name)...))
	if code != 0 || len(uuids) != 2*kcmUUIDLen {
		t.Fatalf("UUID list = %x, status %d", uuids, code)
	}
	match, err := marshalMatchCredential(cache.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	removeArgs := append(cstring(name), make([]byte, 4)...)
	removeArgs = append(removeArgs, match...)
	removeRequest := append([]byte{2, 0, 0, byte(kcmOpRemoveCred)}, removeArgs...)
	if _, code := server.dispatch(removeRequest); code != 0 {
		t.Fatalf("remove status = %d", code)
	}
	remaining, code := server.dispatch(append([]byte{2, 0, 0, byte(kcmOpGetCredUUIDList)}, cstring(name)...))
	if code != 0 || !bytes.Equal(remaining, uuids[kcmUUIDLen:]) {
		t.Fatalf("remaining UUID list = %x, want %x (status %d)", remaining, uuids[kcmUUIDLen:], code)
	}
}

func TestKCMServerPeerNamespaces(t *testing.T) {
	server := NewKCMServer("")
	server.IsolatePeers = true
	cacheName := "shared-name"
	cache := testCache()
	principalBytes, err := marshalPrincipalBytes(cache.DefaultPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	initRequest := kcmRequest(kcmOpInitialize, append(cstring(cacheName), principalBytes...))
	if _, code := server.dispatchPeer(initRequest, 1001); code != 0 {
		t.Fatalf("initialize status = %d", code)
	}
	raw, err := marshalCredentialBytes(cache.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpStore, append(cstring(cacheName), raw...)), 1001); code != 0 {
		t.Fatalf("store status = %d", code)
	}
	uuids, code := server.dispatchPeer(kcmRequest(kcmOpGetCredUUIDList, cstring(cacheName)), 1001)
	if code != 0 || len(uuids) != kcmUUIDLen {
		t.Fatalf("peer A UUID list = %x, status %d", uuids, code)
	}
	cacheUUIDs, code := server.dispatchPeer(kcmRequest(kcmOpGetCacheUUIDList), 1001)
	if code != 0 || len(cacheUUIDs) != kcmUUIDLen {
		t.Fatalf("peer A cache UUID list = %x, status %d", cacheUUIDs, code)
	}
	server.dispatchPeer(kcmRequest(kcmOpSetDefaultCache, cstring(cacheName)), 1001)

	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetPrincipal, cstring(cacheName)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer principal status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetCredList, cstring(cacheName)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer credential-list status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetCredUUIDList, cstring(cacheName)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer credential UUID-list status = %d", code)
	}
	credByUUIDArgs := append(cstring(cacheName), uuids[:kcmUUIDLen]...)
	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetCredByUUID, credByUUIDArgs), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer credential-by-UUID status = %d", code)
	}
	match, err := marshalMatchCredential(cache.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	retrieveArgs := append(cstring(cacheName), make([]byte, 4)...)
	retrieveArgs = append(retrieveArgs, match...)
	if _, code := server.dispatchPeer(kcmRequest(kcmOpRetrieve, retrieveArgs), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer retrieve status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpStore, append(cstring(cacheName), raw...)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer store status = %d", code)
	}
	removeArgs := append(cstring(cacheName), make([]byte, 4)...)
	removeArgs = append(removeArgs, match...)
	if _, code := server.dispatchPeer(kcmRequest(kcmOpRemoveCred, removeArgs), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer remove status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpDestroy, cstring(cacheName)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer destroy status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetKDCOffset, cstring(cacheName)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer offset status = %d", code)
	}
	offset := append(cstring(cacheName), make([]byte, 4)...)
	if _, code := server.dispatchPeer(kcmRequest(kcmOpSetKDCOffset, offset), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer set-offset status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpSetDefaultCache, cstring(cacheName)), 1002); code != kcmErrNoFile {
		t.Fatalf("cross-peer set-default status = %d", code)
	}
	cacheList, code := server.dispatchPeer(kcmRequest(kcmOpGetCacheUUIDList), 1002)
	if code != 0 || len(cacheList) != 0 {
		t.Fatalf("cross-peer cache list = %x, status %d", cacheList, code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetCacheByUUID, cacheUUIDs[:kcmUUIDLen]), 1002); code != kcmErrEnd {
		t.Fatalf("cross-peer credential UUID status = %d", code)
	}
	if _, code := server.dispatchPeer(kcmRequest(kcmOpGetDefaultCache), 1002); code != 0 {
		t.Fatalf("cross-peer default status = %d", code)
	}
	defaultName, _ := server.dispatchPeer(kcmRequest(kcmOpGetDefaultCache), 1002)
	if string(defaultName) != "default\x00" {
		t.Fatalf("cross-peer default = %q", defaultName)
	}
}

func startKCMTestServer(t *testing.T, isolate bool, peerUID func(net.Conn) (uint32, error)) (*KCMServer, string) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "kcm.sock")
	server := NewKCMServer(socket)
	server.IsolatePeers = isolate
	if peerUID != nil {
		server.peerUID = peerUID
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeListener(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
	return server, socket
}

func TestKCMServerSamePeerClientsShareNamespace(t *testing.T) {
	_, socket := startKCMTestServer(t, true, func(net.Conn) (uint32, error) {
		return 4242, nil
	})
	first, err := ResolveKCM("peer-shared", socket)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveKCM("peer-shared", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer second.Close()
	value := testCache()
	if err := first.Write(value); err != nil {
		t.Fatal(err)
	}
	got, err := second.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Credentials) != len(value.Credentials) ||
		got.DefaultPrincipal.Realm != value.DefaultPrincipal.Realm {
		t.Fatalf("same-peer cache = %#v, want %#v", got, value)
	}
	if err := first.SetDefault(); err != nil {
		t.Fatal(err)
	}
	defaultCache, err := ResolveKCM("", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer defaultCache.Close()
	if defaultCache.Name() != "KCM:peer-shared" {
		t.Fatalf("same-peer default cache = %q", defaultCache.Name())
	}
}

func TestKCMServerLinuxPeerCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-specific")
	}
	_, socket := startKCMTestServer(t, true, nil)
	first, err := ResolveKCM("linux-peer", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := ResolveKCM("linux-peer", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.Write(testCache()); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(); err != nil {
		t.Fatalf("same Linux peer UID could not share cache: %v", err)
	}
}

func TestKCMServerConcurrentPeerClients(t *testing.T) {
	_, socket := startKCMTestServer(t, true, func(net.Conn) (uint32, error) {
		return 777, nil
	})
	const clients = 8
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache, err := ResolveKCM(fmt.Sprintf("concurrent-%d", i), socket)
			if err != nil {
				errs <- err
				return
			}
			defer cache.Close()
			if err := cache.Write(testCache()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type kcmSingleConnListener struct {
	conn net.Conn
	done bool
}

func (l *kcmSingleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, errors.New("kcm test listener stopped")
	}
	l.done = true
	return l.conn, nil
}

func (l *kcmSingleConnListener) Close() error   { return nil }
func (l *kcmSingleConnListener) Addr() net.Addr { return &net.UnixAddr{Name: "kcm-test", Net: "unix"} }

func TestKCMServerRefusesUnavailablePeerCredentials(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := NewKCMServer("")
	server.IsolatePeers = true
	server.peerUID = func(net.Conn) (uint32, error) {
		return 0, errKCMPeerCredentialsUnavailable
	}
	listener := &kcmSingleConnListener{conn: serverConn}
	done := make(chan error, 1)
	go func() {
		done <- server.ServeListener(listener)
	}()
	select {
	case err := <-done:
		if err == nil || err.Error() != "kcm test listener stopped" {
			t.Fatalf("ServeListener error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not refuse unavailable peer")
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused peer connection remained open")
	}
}

func TestKCMServerCloseClosesActiveConnections(t *testing.T) {
	server, socket := startKCMTestServer(t, true, func(net.Conn) (uint32, error) {
		return 99, nil
	})
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		active := len(server.conns)
		server.mu.Unlock()
		if active != 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active KCM connection remained open after Close")
	}
}

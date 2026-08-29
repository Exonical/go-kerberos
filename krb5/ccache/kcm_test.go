package ccache

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

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

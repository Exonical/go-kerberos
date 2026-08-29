package ccache

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
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

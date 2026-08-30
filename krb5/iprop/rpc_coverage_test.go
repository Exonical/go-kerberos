package iprop

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestIPROPRPCWireHelpers(t *testing.T) {
	c := NewClient(nil, nil)
	if c.Timeout == 0 || c.Conn != nil {
		t.Fatalf("new client = %#v", c)
	}
	if err := c.ensureAuth(context.Background()); err == nil {
		t.Fatal("unauthenticated client accepted")
	}
	if err := c.ensureAuth(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := (*Client)(nil).Authenticate(context.Background()); err == nil {
		t.Fatal("nil client authenticated")
	}
	if err := c.Authenticate(context.Background()); err == nil {
		t.Fatal("incomplete client authenticated")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	cred := []byte{1, 2}
	prefix := c.rpcPrefix(7, ProcGetUpdates, authRPCSecGSS, cred)
	var suffix writer
	suffix.auth(authNone, nil)
	suffix.raw([]byte("body"))
	record := append(append([]byte(nil), prefix...), suffix.bytes()...)
	call, err := parseCall(record)
	if err != nil {
		t.Fatal(err)
	}
	if call.xid != 7 || call.proc != ProcGetUpdates || call.flavor != authRPCSecGSS ||
		string(call.credential) != string(cred) || string(call.body) != "body" {
		t.Fatalf("parsed RPC call = %#v", call)
	}
	if !bytesEqual([]byte{1, 2}, []byte{1, 2}) ||
		bytesEqual([]byte{1}, []byte{1, 2}) {
		t.Fatal("bytesEqual semantics changed")
	}
	if len(rpcReply(7, authRPCSecGSS, []byte{1}, []byte{2})) == 0 ||
		len(rpcError(7, 1)) == 0 || len(seqBytes(0x01020304)) != 4 {
		t.Fatal("RPC wire helper returned empty data")
	}
}

func TestIPROPRPCRecordFraming(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	want := []byte("record")
	done := make(chan error, 1)
	go func() { done <- writeRecord(left, want) }()
	got, err := readRecord(right)
	if err != nil || string(got) != string(want) {
		t.Fatalf("record round trip = %q/%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var bad [4]byte
	binary.BigEndian.PutUint32(bad[:], 1)
	go func() { _, _ = right.Write(bad[:]) }()
	if _, err := readRecord(left); err == nil {
		t.Fatal("non-final RPC fragment accepted")
	}
}

func TestIPROPDispatchAndServerUtilities(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	server := NewServer(db, nil)
	name, _ := principal.Parse("alice@EXAMPLE.COM")
	if got := server.dispatch(*name, ProcFullResyncExt, seqBytes(1)); len(got) == 0 {
		t.Fatal("full resync extension returned no response")
	}
	if result, err := UnmarshalFullResyncResult(server.dispatch(*name, ProcFullResyncExt, nil)); err != nil ||
		result.Ret != UpdateError {
		t.Fatalf("bad full resync extension = %#v/%v", result, err)
	}
	if server.dispatch(*name, ProcNull, []byte{1}) != nil ||
		server.dispatch(*name, 99, nil) != nil {
		t.Fatal("invalid dispatch returned a body")
	}
	if server.authorized(*name) {
		t.Fatal("unconfigured replica authorized")
	}
	server.AllowedReplicas = map[string]bool{name.String(): true}
	if !server.authorized(*name) {
		t.Fatal("configured replica denied")
	}
	server.Authorize = func(principal.Principal) bool { return true }
	if !server.authorized(principal.Principal{}) {
		t.Fatal("authorization callback ignored")
	}
	if _, err := (&Server{}).DumpWithMasterPassword("password"); err == nil {
		t.Fatal("nil database dump succeeded")
	}
	if _, err := server.DumpWithMasterPassword("password"); err != nil {
		t.Fatalf("database dump: %v", err)
	}
	if got := now(func() time.Time { return time.Unix(1, 0) }); !got.Equal(time.Unix(1, 0).UTC()) {
		t.Fatalf("configured now = %v", got)
	}
}

func TestIPROPNewClientCloseAndNilInputs(t *testing.T) {
	if err := (*Client)(nil).Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(nil, "127.0.0.1:1", nil); err == nil {
		t.Fatal("nil context dial succeeded")
	}
	if _, err := Dial(context.Background(), "bad-address", nil); err == nil {
		t.Fatal("invalid address dial succeeded")
	}
}

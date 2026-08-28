package kadm5

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestParseRPCCall(t *testing.T) {
	prefix := xdrWriter{}
	prefix.u32(0x11223344)
	prefix.u32(msgCall)
	prefix.u32(rpcVersion)
	prefix.u32(Program)
	prefix.u32(Version)
	prefix.u32(getPrincipal)
	prefix.opaqueAuth(rpcsecGSS, []byte{1, 2, 3})
	w := xdrWriter{b: bytes.Buffer{}}
	w.raw(prefix.bytes())
	w.opaqueAuth(0, []byte{4, 5})
	w.raw([]byte{6, 7, 8})

	call, err := parseRPCCall(w.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if call.xid != 0x11223344 || call.proc != getPrincipal || call.flavor != rpcsecGSS {
		t.Fatalf("call header = %+v", call)
	}
	if !bytes.Equal(call.credential, []byte{1, 2, 3}) ||
		!bytes.Equal(call.verifier, []byte{4, 5}) ||
		!bytes.Equal(call.body, []byte{6, 7, 8}) {
		t.Fatalf("call payload = %+v", call)
	}
	if !bytes.Equal(call.prefix, prefix.bytes()) {
		t.Fatalf("prefix unexpectedly includes verifier or body: %x", call.prefix)
	}
}

func TestParseRPCCallRejectsBadHeader(t *testing.T) {
	w := xdrWriter{}
	w.u32(1)
	w.u32(msgCall)
	w.u32(rpcVersion)
	w.u32(Program + 1)
	w.u32(Version)
	w.u32(getPrincipal)
	w.opaqueAuth(0, nil)
	w.opaqueAuth(0, nil)
	if _, err := parseRPCCall(w.bytes()); err == nil {
		t.Fatal("parseRPCCall accepted an unexpected program")
	}
}

func TestReadRPCRecordFragments(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], 3)
		if _, err := client.Write(header[:]); err != nil {
			done <- err
			return
		}
		if _, err := client.Write([]byte("abc")); err != nil {
			done <- err
			return
		}
		binary.BigEndian.PutUint32(header[:], 0x80000002)
		if _, err := client.Write(header[:]); err != nil {
			done <- err
			return
		}
		_, err := client.Write([]byte("de"))
		done <- err
	}()
	got, err := readRPCRecord(server)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcde" {
		t.Fatalf("record = %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadRPCRecordRejectsOversizedFragment(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(ServerMaxRecord+1)|0x80000000)
		_, _ = client.Write(header[:])
	}()
	if _, err := readRPCRecord(server); err == nil {
		t.Fatal("readRPCRecord accepted an oversized fragment")
	}
}

func TestGlobMatchWholePrincipal(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*/*@TEST.REALM", "nfs/host@TEST.REALM", true},
		{"*/?ost@TEST.REALM", "nfs/host@TEST.REALM", true},
		{"nfs?host@TEST.REALM", "nfs/host@TEST.REALM", true},
		{"*/*@TEST.REALM", "alice@TEST.REALM", false},
		{"nfs/[a-z]*@TEST.REALM", "nfs/host@TEST.REALM", true},
		{"nfs/[!a-z]*@TEST.REALM", "nfs/host@TEST.REALM", false},
		{"nfs/[a-z", "nfs/host@TEST.REALM", false},
	}
	for _, test := range tests {
		if got := globMatch(test.pattern, test.name); got != test.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", test.pattern, test.name, got, test.want)
		}
	}
}

func TestServerGoClientRoundTrip(t *testing.T) {
	const realm = "TEST.REALM"
	kt, creds := serverTestCredentials(t, realm)
	db := kdb.NewDatabase(realm)
	admin := creds.Client
	if err := db.AddPrincipal("admin/admin@"+realm, "unused", 1); err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, kt)
	s.AdminPrincipal = admin
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go s.Serve(listener)
	c, err := Dial(t.Context(), nil, admin, creds, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := principal.Parse("alice@" + realm)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CreatePrincipal(t.Context(), *p, "alice-password"); err != nil {
		t.Fatal(err)
	}
	defer c.DeletePrincipal(t.Context(), *p)
	entry, err := c.GetPrincipal(t.Context(), *p)
	if err != nil {
		t.Fatal(err)
	}
	entry.Attributes = 1
	entry.MaxLife = 3600
	entry.MaxRenewableLife = 7200
	if err := c.ModifyPrincipal(t.Context(), entry, KADM5Attributes|KADM5MaxLife|KADM5MaxRenewableLife); err != nil {
		t.Fatal(err)
	}
	renamed, err := principal.Parse("alice-renamed@" + realm)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RenamePrincipal(t.Context(), *p, *renamed); err != nil {
		t.Fatal(err)
	}
	p = renamed
	keys, err := c.RandKey(t.Context(), *p)
	if err != nil || len(keys) == 0 {
		t.Fatalf("RandKey = %d keys, %v", len(keys), err)
	}
	if err := c.SetString(t.Context(), *p, "x-test", stringPtr("value")); err != nil {
		t.Fatal(err)
	}
	attrs, err := c.GetStrings(t.Context(), *p)
	if err != nil || len(attrs) != 1 || attrs[0].Value != "value" {
		t.Fatalf("GetStrings = %#v, %v", attrs, err)
	}
	if err := c.ChangePassword(t.Context(), *p, "new-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPrincipalKeys(t.Context(), *p, 0); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Name: "test-policy", MinLength: 8, MaxFailure: 3}
	if err := c.CreatePolicy(t.Context(), policy, KADM5PWMinLength|KADM5PWMaxFailure); err != nil {
		t.Fatal(err)
	}
	defer c.DeletePolicy(t.Context(), policy.Name)
	if got, err := c.GetPolicy(t.Context(), policy.Name); err != nil || got.MinLength != 8 {
		t.Fatalf("GetPolicy = %+v, %v", got, err)
	}
	policy.MinLength = 10
	if err := c.ModifyPolicy(t.Context(), policy, KADM5PWMinLength); err != nil {
		t.Fatal(err)
	}
	if names, err := c.ListPolicies(t.Context(), policy.Name); err != nil || len(names) != 1 || names[0] != policy.Name {
		t.Fatalf("ListPolicies = %v, %v", names, err)
	}
	entry, err = c.GetPrincipal(t.Context(), *p)
	if err != nil {
		t.Fatal(err)
	}
	entry.Policy = policy.Name
	if err := c.ModifyPrincipal(t.Context(), entry, KADM5Policy); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPrivs(t.Context()); err != nil {
		t.Fatal(err)
	}
	if names, err := c.ListPrincipals(t.Context(), "alice-*"); err != nil || len(names) != 1 {
		t.Fatalf("ListPrincipals = %v, %v", names, err)
	}
	entry.Policy = ""
	if err := c.ModifyPrincipal(t.Context(), entry, KADM5Policy|KADM5PolicyClear); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePolicy(t.Context(), policy.Name); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePrincipal(t.Context(), *p); err != nil {
		t.Fatal(err)
	}
}

func stringPtr(s string) *string { return &s }

func serverTestCredentials(t *testing.T, realm string) (*keytab.Keytab, *client.Credentials) {
	t.Helper()
	etypeID := crypto.EnctypeAES128SHA1
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: realm, NameType: principal.NTSrvInstance, Components: []string{"kadmin", "admin"}}
	cli := principal.Principal{Realm: realm, NameType: principal.NTPrincipal, Components: []string{"admin", "admin"}}
	serviceKey := make([]byte, etype.KeySize())
	sessionKey := make([]byte, etype.KeySize())
	if _, err := rand.Read(serviceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(time.Hour)
	part, err := asn1.Marshal(protocol.EncTicketPart{
		Key:    protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionKey},
		CRealm: realm, CName: protocol.PrincipalName{NameType: int32(cli.NameType), NameString: cli.Components},
		AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: types.KerberosTime{Time: end, Present: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := etype.Encrypt(serviceKey, 2, part)
	if err != nil {
		t.Fatal(err)
	}
	kvno := uint32(1)
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: realm,
		SName:   protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		EncPart: protocol.EncryptedData{EType: etypeID, KVNO: &kvno, Cipher: cipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &keytab.Keytab{Entries: []keytab.Entry{{Principal: service, KVNO: kvno, Enctype: etypeID, Key: serviceKey}}},
		&client.Credentials{Client: cli, Server: service, Key: protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionKey},
			AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: types.KerberosTime{Time: end, Present: true}, Ticket: ticket}
}

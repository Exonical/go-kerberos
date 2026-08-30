package gssapi

import (
	"bytes"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestGSSContextPRFAndLucidBoundaries(t *testing.T) {
	key := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{1}, 32)}
	partial := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{2}, 32)}
	full := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{3}, 32)}
	c := &Context{
		key: key, prfPartial: partial, prfFull: full, initiator: true,
		flags: GSSMutualFlag, source: principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}},
		target:  principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "server"}},
		endtime: time.Unix(100, 0).UTC(), sendSeq: 4, recvSeq: 5,
		acceptorSubkeyKey: &full,
	}
	for _, selector := range []int{GSSPRFKeyPartial, GSSPRFKeyFull} {
		value, err := c.PseudoRandom(selector, []byte("input"), 40)
		if err != nil || len(value) != 40 {
			t.Fatalf("PRF selector %d = %x/%v", selector, value, err)
		}
	}
	if value, err := c.PseudoRandom(GSSPRFKeyFull, nil, 0); err != nil || len(value) != 0 {
		t.Fatalf("zero PRF = %x/%v", value, err)
	}
	if _, err := c.PseudoRandom(99, nil, 1); err == nil {
		t.Fatal("invalid PRF selector accepted")
	}
	if _, err := c.PseudoRandom(GSSPRFKeyFull, nil, -1); err == nil {
		t.Fatal("negative PRF length accepted")
	}
	lucid, err := c.ExportLucidContext(1)
	if err != nil || lucid.Version != 1 || !lucid.Initiate || lucid.SendSeq != 4 ||
		lucid.RecvSeq != 5 || lucid.Key.Type != key.KeyType ||
		!bytes.Equal(lucid.Key.Value, partial.KeyValue) ||
		lucid.AcceptorSubkey == nil || !bytes.Equal(lucid.AcceptorSubkey.Value, full.KeyValue) {
		t.Fatalf("lucid context = %#v/%v", lucid, err)
	}
	if _, err := c.ExportLucidContext(2); err == nil {
		t.Fatal("unsupported lucid version accepted")
	}
	if _, err := ExportLucidSecContext(nil, 1); err == nil {
		t.Fatal("nil lucid context accepted")
	}
	if _, err := (&Context{}).ExportLucidContext(1); err == nil {
		t.Fatal("unestablished lucid context accepted")
	}
}

func TestGSSCredentialAndContextWrapperValidation(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	if _, err := AcquireInitiatorCredentialWithPassword(nil, nil, name, "password"); err == nil {
		t.Fatal("nil client credential acquisition accepted")
	}
	if _, err := AcquireInitiatorCredentialWithPassword(nil, &client.Client{}, principal.Principal{}, "password"); err == nil {
		t.Fatal("invalid principal credential acquisition accepted")
	}
	if _, err := AcquireAcceptorCredential(nil, nil); err == nil {
		t.Fatal("nil keytab acceptor acquisition accepted")
	}
	if _, err := AcquireAcceptorCredentialFromFile("", nil); err == nil {
		t.Fatal("empty keytab path accepted")
	}
	var credential *Credential
	if _, err := credential.NewInitiatorForCredential(0); err == nil {
		t.Fatal("nil initiator credential accepted")
	}
	if _, err := credential.NewAcceptorForCredential(); err == nil {
		t.Fatal("nil acceptor credential accepted")
	}
	if _, err := AcquireImpersonatedCredential(nil, nil, name); err == nil {
		t.Fatal("nil impersonator accepted")
	}
}

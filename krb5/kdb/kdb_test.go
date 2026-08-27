package kdb

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var _ Store = (*Database)(nil)

func TestAddPrincipalDerivesSupportedKeys(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "alice-password", 3, 7); err != nil {
		t.Fatalf("AddPrincipal: %v", err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("principal was not stored")
	}
	if record.KVNO != 7 {
		t.Fatalf("KVNO = %d, want 7", record.KVNO)
	}
	for _, enctype := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
	} {
		key, ok := record.Keys[enctype]
		if !ok {
			t.Fatalf("missing enctype %d", enctype)
		}
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			t.Fatal(err)
		}
		if len(key.Key) != etype.KeySize() {
			t.Fatalf("enctype %d key length = %d, want %d", enctype, len(key.Key), etype.KeySize())
		}
		if key.Salt != "TEST.REALMalice" {
			t.Fatalf("enctype %d salt = %q, want MIT default", enctype, key.Salt)
		}
		if key.KVNO != 7 {
			t.Fatalf("enctype %d KVNO = %d, want 7", enctype, key.KVNO)
		}
	}
}

func TestAddPrincipalRequiresRealmConsistentWithDatabase(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice@OTHER.REALM", "password", 1); err == nil {
		t.Fatal("cross-realm principal unexpectedly accepted")
	}
}

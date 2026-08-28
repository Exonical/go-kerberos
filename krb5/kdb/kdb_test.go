package kdb

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var _ Store = (*Database)(nil)
var _ AliasResolver = (*Database)(nil)

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

func TestAddPrincipalAllowsForeignRealmTGT(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("krbtgt/TEST.REALM@OTHER.REALM", "shared-password", 1); err != nil {
		t.Fatalf("cross-realm TGT: %v", err)
	}
	name, err := principal.Parse("krbtgt/TEST.REALM@OTHER.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("cross-realm TGT was not stored")
	}
	if record.Name.Realm != "OTHER.REALM" {
		t.Fatalf("stored realm = %q", record.Name.Realm)
	}
}

func TestAliasResolver(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "alice-password", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAlias("alice-alias", "alice"); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}
	alias, err := principal.Parse("alice-alias@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	canonical, ok, err := db.ResolveAlias(*alias)
	if err != nil {
		t.Fatalf("ResolveAlias: %v", err)
	}
	if !ok || canonical.String() != "alice@TEST.REALM" {
		t.Fatalf("resolved alias = %v, %v; want alice@TEST.REALM, true", canonical, ok)
	}
	if _, ok, err := db.Lookup(*alias); err != nil || ok {
		t.Fatalf("Lookup(alias) = %v, %v; want missing", ok, err)
	}
	canonicalRecord, ok, err := db.Lookup(canonical)
	if err != nil || !ok || canonicalRecord.Name.String() != "alice@TEST.REALM" {
		t.Fatalf("Lookup(canonical) = %#v, %v, %v", canonicalRecord, ok, err)
	}
	missing, err := principal.Parse("missing@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.ResolveAlias(*missing); err != nil || ok {
		t.Fatalf("missing alias = %v, %v", ok, err)
	}
}

func TestAddAliasRequiresCanonicalTarget(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddAlias("alice-alias", "alice"); err == nil {
		t.Fatal("AddAlias accepted missing target")
	}
}

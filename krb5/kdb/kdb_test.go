package kdb

import (
	"bytes"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var _ Store = (*Database)(nil)
var _ AliasResolver = (*Database)(nil)

func TestChangePasswordPreservesAdministrativeFields(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "old-password"); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	expiration := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	passwordExpiration := expiration.Add(24 * time.Hour)
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %#v, %v, %v", record, ok, err)
	}
	record.Flags = 0x1234
	record.Policy = "strong"
	record.MaxLife = 6 * time.Hour
	record.MaxRenew = 24 * time.Hour
	record.Expiration = expiration
	record.PasswordExpiration = passwordExpiration
	oldKey := append([]byte(nil), record.Keys[crypto.EnctypeAES256SHA1].Key...)
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	attribute := "engineering"
	if err := db.SetString(*name, "department", &attribute); err != nil {
		t.Fatal(err)
	}
	if err := db.ChangePassword(*name, "new-password"); err != nil {
		t.Fatal(err)
	}
	updated, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup after change = %#v, %v, %v", updated, ok, err)
	}
	if updated.Flags != record.Flags || updated.Policy != record.Policy ||
		updated.MaxLife != record.MaxLife || updated.MaxRenew != record.MaxRenew ||
		!updated.Expiration.Equal(expiration) ||
		!updated.PasswordExpiration.Equal(passwordExpiration) ||
		updated.Name.String() != record.Name.String() ||
		updated.Strings["department"] != "engineering" {
		t.Fatalf("administrative fields changed: before=%+v after=%+v", record, updated)
	}
	if updated.KVNO != record.KVNO+1 {
		t.Fatalf("KVNO = %d, want %d", updated.KVNO, record.KVNO+1)
	}
	if bytes.Equal(updated.Keys[crypto.EnctypeAES256SHA1].Key, oldKey) {
		t.Fatal("password change did not replace key material")
	}
}

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

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

func TestKeySaltTuplesAndPurgeKeys(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.CreatePrincipalWithKeySalts("alice", "password",
		[]KeySaltTuple{{Enctype: crypto.EnctypeAES128SHA1, SaltType: SaltTypeNoRealm}}); err != nil {
		t.Fatal(err)
	}
	name, _ := principal.Parse("alice@TEST.REALM")
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	if len(record.Keys) != 1 || record.Keys[crypto.EnctypeAES128SHA1].Salt != "alice" {
		t.Fatalf("tuple-derived keys = %#v", record.Keys)
	}
	if _, err := db.RandomizeKeysWithKeySalts(*name, true,
		[]KeySaltTuple{{Enctype: crypto.EnctypeAES128SHA1, SaltType: SaltTypeOnlyRealm}}); err != nil {
		t.Fatal(err)
	}
	if err := db.PurgeKeys(*name, 0); err != nil {
		t.Fatal(err)
	}
}

func TestPrincipalUpdatesIncludeMITModifierTLData(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	status, updates := db.UpdateLog.Entries(0, time.Time{})
	if status != 0 || len(updates) != 1 {
		t.Fatalf("updates = %d/%#v, want one update", status, updates)
	}
	var modifier TLData
	for _, value := range updates[0].Record.TLData {
		if value.Type == 2 {
			modifier = value
			break
		}
	}
	if modifier.Type != 2 || len(modifier.Data) < 5 ||
		!bytes.Equal(modifier.Data[4:], []byte(name.String()+"\x00")) {
		t.Fatalf("modifier TL-data = %#v, want principal %q", modifier,
			name.String())
	}
}

func TestChangePasswordPolicy(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "Old-password1!"); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0).UTC()
	policy := PolicyRecord{
		Name: "strong", MinLength: 12, MinClasses: 3, HistoryNum: 3,
		MinLife: 60, MaxLife: 3600,
	}
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	record.LastPasswordChange = now
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	if err := db.ChangePasswordWithPolicy(*name, "short", now, &policy, false); err != ErrPasswordTooShort {
		t.Fatalf("short password error = %v", err)
	}
	if err := db.ChangePasswordWithPolicy(*name, "all-lowercase", now, &policy, false); err != ErrPasswordClasses {
		t.Fatalf("class password error = %v", err)
	}
	if err := db.ChangePasswordWithPolicy(*name, "New-password1!", now.Add(time.Second), &policy, false); err != ErrPasswordTooSoon {
		t.Fatalf("minimum-life error = %v", err)
	}
	if err := db.ChangePasswordWithPolicy(*name, "New-password1!", now, &policy, true); err != nil {
		t.Fatalf("administrative change: %v", err)
	}
	record, ok, err = db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	if !record.PasswordExpiration.Equal(now.Add(time.Hour)) {
		t.Fatalf("password expiration = %v, want %v", record.PasswordExpiration, now.Add(time.Hour))
	}
	if len(record.PasswordHistory) != 1 {
		t.Fatalf("password history length = %d, want 1", len(record.PasswordHistory))
	}
	if err := db.ChangePasswordWithPolicy(*name, "Old-password1!", now.Add(2*time.Minute), &policy, true); err != ErrPasswordReuse {
		t.Fatalf("history reuse error = %v", err)
	}
}

func TestCreatePrincipalWithOptionsAppliesPolicyAtomically(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	db.ConfigureUpdateLog(10)
	policy := PolicyRecord{Name: "strong", MaxLife: 3600, MaxRenewableLife: 7200}
	if err := db.CreatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	if err := db.CreatePrincipalWithOptions("alice", "alice-password", &policy); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	if record.Policy != policy.Name || record.MaxLife != time.Hour ||
		record.MaxRenew != 2*time.Hour {
		t.Fatalf("policy fields = %#v", record)
	}
	if record.PasswordExpiration.Before(before.Add(time.Hour)) {
		t.Fatalf("password expiration = %v, want at least %v", record.PasswordExpiration, before.Add(time.Hour))
	}
	if status, updates := db.UpdateLog.Entries(0, time.Time{}); status != 0 || len(updates) != 1 {
		t.Fatalf("updates = status %d, entries %d; want one entry", status, len(updates))
	}
}

func TestCreatePrincipalWithOptionsRejectsDeletedPolicyWithoutPrincipal(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	policy := PolicyRecord{Name: "ephemeral"}
	if err := db.CreatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePolicy(policy.Name); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePrincipalWithOptions("alice", "alice-password", &policy); err != ErrPolicyNotFound {
		t.Fatalf("create error = %v, want %v", err, ErrPolicyNotFound)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.Lookup(*name); ok {
		t.Fatal("principal created after policy disappeared")
	}
}

func TestCreatePrincipalWithKeySaltsAndOptionsAppliesPolicyAtomically(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	db.ConfigureUpdateLog(10)
	policy := PolicyRecord{Name: "tuple-policy", MaxLife: 3600, MaxRenewableLife: 7200}
	if err := db.CreatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	if err := db.CreatePrincipalWithKeySaltsAndOptions("alice", "alice-password",
		[]KeySaltTuple{{Enctype: crypto.EnctypeAES128SHA1, SaltType: SaltTypeNoRealm}},
		&policy); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %#v, %v, %v", record, ok, err)
	}
	if record.Policy != policy.Name || record.MaxLife != time.Hour ||
		record.MaxRenew != 2*time.Hour || len(record.Keys) != 1 ||
		record.Keys[crypto.EnctypeAES128SHA1].Salt != "alice" {
		t.Fatalf("created record = %#v", record)
	}
	if record.PasswordExpiration.Before(before.Add(time.Hour)) {
		t.Fatalf("password expiration = %v, want at least %v",
			record.PasswordExpiration, before.Add(time.Hour))
	}
	if status, updates := db.UpdateLog.Entries(0, time.Time{}); status != 0 || len(updates) != 1 {
		t.Fatalf("updates = status %d, entries %d; want one entry", status, len(updates))
	}
}

func TestChangePasswordKeepOldRetainsPreviousKVNO(t *testing.T) {
	db := NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "old-password"); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@TEST.REALM")
	if err != nil {
		t.Fatal(err)
	}
	before, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", err, ok)
	}
	old := before.Keys[crypto.EnctypeAES256SHA1]
	if err := db.ChangePasswordWithPolicyAndKeepOld(*name, "new-password", time.Now().UTC(), nil, false, true); err != nil {
		t.Fatal(err)
	}
	after, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("Lookup after change = %v, %v", err, ok)
	}
	if len(after.PasswordHistory) != 1 || after.PasswordHistory[0][old.Enctype].KVNO != old.KVNO {
		t.Fatalf("password history = %#v", after.PasswordHistory)
	}
	if got, ok := after.PasswordHistory[0][old.Enctype]; !ok || string(got.Key) != string(old.Key) {
		t.Fatalf("old key = %#v, want %#v", got, old)
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

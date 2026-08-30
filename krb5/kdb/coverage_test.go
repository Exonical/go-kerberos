package kdb

import (
	"bytes"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestDatabasePrincipalLifecycleAndLockout(t *testing.T) {
	db := NewDatabase("EXAMPLE.COM")
	if err := db.CreatePrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePrincipal("alice", "password"); err != ErrPrincipalExists {
		t.Fatalf("duplicate create = %v", err)
	}
	name, _ := principal.Parse("alice@EXAMPLE.COM")
	now := time.Unix(1000, 0).UTC()
	count, err := db.RecordAuthFailure(*name, now, time.Hour)
	if err != nil || count != 1 {
		t.Fatalf("first auth failure = %d/%v", count, err)
	}
	count, err = db.RecordAuthFailure(*name, now.Add(time.Minute), time.Hour)
	if err != nil || count != 2 {
		t.Fatalf("second auth failure = %d/%v", count, err)
	}
	count, err = db.RecordAuthFailure(*name, now.Add(2*time.Hour), time.Hour)
	if err != nil || count != 1 {
		t.Fatalf("expired failure window = %d/%v", count, err)
	}
	if err := db.ResetAuthFailures(*name, now); err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok || record.FailAuthCount != 1 {
		t.Fatalf("stale reset changed record = %#v", record)
	}
	if err := db.ResetAuthFailures(*name, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordAuthSuccess(*name, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	record, _, _ = db.Lookup(*name)
	if record.FailAuthCount != 0 || !record.LastSuccess.Equal(now.Add(3*time.Hour)) {
		t.Fatalf("success state = %#v", record)
	}
	if err := db.UpdateLockout(*name, 4, now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	record, _, _ = db.Lookup(*name)
	if record.FailAuthCount != 4 {
		t.Fatalf("UpdateLockout count = %d", record.FailAuthCount)
	}
	if err := db.DeletePrincipal(*name); err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePrincipal(*name); err != ErrPrincipalNotFound {
		t.Fatalf("duplicate delete = %v", err)
	}
}

func TestDatabaseKeysRenameStringsAndApply(t *testing.T) {
	db := NewDatabase("EXAMPLE.COM")
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	alice, _ := principal.Parse("alice@EXAMPLE.COM")
	bob, _ := principal.Parse("bob@EXAMPLE.COM")
	if err := db.RenamePrincipal(*alice, *bob); err != nil {
		t.Fatal(err)
	}
	record, ok, _ := db.Lookup(*bob)
	if !ok {
		t.Fatal("renamed principal missing")
	}
	oldKey := append([]byte(nil), record.Keys[crypto.EnctypeAES256SHA1].Key...)
	keys, err := db.RandomizeKeys(*bob)
	if err != nil || len(keys) == 0 {
		t.Fatalf("RandomizeKeys = %d/%v", len(keys), err)
	}
	if bytes.Equal(oldKey, keys[0].Key) {
		t.Fatal("randomized key reused old key")
	}
	if err := db.SetKeys(*bob, []Key{{Enctype: crypto.EnctypeAES256SHA1,
		Key: []byte{1, 2, 3}}}, false); err != nil {
		t.Fatal(err)
	}
	value := "department"
	if err := db.SetString(*bob, "unit", &value); err != nil {
		t.Fatal(err)
	}
	strings, err := db.GetStrings(*bob)
	if err != nil || strings["unit"] != value {
		t.Fatalf("strings = %#v/%v", strings, err)
	}
	if err := db.SetString(*bob, "unit", nil); err != nil {
		t.Fatal(err)
	}
	record.Strings = map[string]string{"applied": "yes"}
	if err := db.ApplyPrincipal(record, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetStrings(*bob); got["applied"] != "yes" {
		t.Fatalf("ApplyPrincipal strings = %#v", got)
	}
	if err := db.ApplyPrincipal(record, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.Lookup(*bob); ok {
		t.Fatal("deleted applied principal remains")
	}
}

func TestDatabasePolicyCRUDAndUsage(t *testing.T) {
	db := NewDatabase("EXAMPLE.COM")
	policy := PolicyRecord{Name: "strong", MinLength: 12, MaxLife: 3600}
	if err := db.CreatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePolicy(policy); err != ErrPolicyExists {
		t.Fatalf("duplicate policy = %v", err)
	}
	policy.MinLength = 14
	if err := db.UpdatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetPolicy("strong")
	if err != nil || got.MinLength != 14 {
		t.Fatalf("GetPolicy = %#v/%v", got, err)
	}
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	name, _ := principal.Parse("alice@EXAMPLE.COM")
	record, _, _ := db.Lookup(*name)
	record.Policy = "strong"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePolicy("strong"); err != ErrPolicyInUse {
		t.Fatalf("in-use policy delete = %v", err)
	}
	record.Policy = ""
	_ = db.UpdatePrincipal(record)
	if err := db.DeletePolicy("strong"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeletePolicy("strong"); err != ErrPolicyNotFound {
		t.Fatalf("missing policy delete = %v", err)
	}
	if got := db.ListPrincipals(); len(got) != 1 || got[0] != "alice@EXAMPLE.COM" {
		t.Fatalf("ListPrincipals = %#v", got)
	}
}

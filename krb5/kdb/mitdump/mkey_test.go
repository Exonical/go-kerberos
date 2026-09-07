package mitdump

import (
	"bytes"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMultiMasterKeyDumpLoad(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.CreatePrincipal("user@EXAMPLE.COM", "password"); err != nil {
		t.Fatal(err)
	}
	oldEType, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	old, err := oldEType.StringToKey([]byte("old"), []byte("EXAMPLE.COMKM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	newEType, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := newEType.StringToKey([]byte("new"), []byte("EXAMPLE.COMKM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	db.MasterKeys = []kdb.Key{
		{Enctype: crypto.EnctypeAES256SHA1, KVNO: 2, Key: newKey},
		{Enctype: crypto.EnctypeAES128SHA1, KVNO: 1, Key: old},
	}
	db.ActiveMKeys = []kdb.ActKVNO{{KVNO: 1, ActTime: 0}, {KVNO: 2, ActTime: 2}}
	name, _ := principalForTest("user@EXAMPLE.COM")
	record, _, _ := db.Lookup(name)
	mkvno, _ := kdb.EncodeMKVNO(1)
	record.TLData = []kdb.TLData{{Type: kdb.MKVNOType, Data: mkvno}}
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	dump, err := DumpWithMasterKey(db, crypto.EnctypeAES256SHA1, newKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ParseWithMasterKey(dump, crypto.EnctypeAES256SHA1, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.MasterKeys) != 2 {
		t.Fatalf("master key count %d", len(store.MasterKeys))
	}
	got, ok, err := store.Lookup(name)
	if err != nil || !ok {
		t.Fatalf("lookup: %v %v", ok, err)
	}
	if !bytes.Equal(got.Keys[crypto.EnctypeAES256SHA1].Key,
		record.Keys[crypto.EnctypeAES256SHA1].Key) {
		t.Fatal("principal key did not round-trip")
	}
	oldStore, err := ParseWithMasterKey(dump, crypto.EnctypeAES128SHA1, old)
	if err != nil {
		t.Fatalf("load with old master key: %v", err)
	}
	if len(oldStore.MasterKeys) != 2 {
		t.Fatalf("old-key master key count %d", len(oldStore.MasterKeys))
	}
	if oldStore.SuppliedMKVNO != 1 {
		t.Fatalf("supplied master key version %d", oldStore.SuppliedMKVNO)
	}
	passwordStore, err := ParseWithMasterPassword(dump, "old")
	if err != nil {
		t.Fatalf("load with old password: %v", err)
	}
	if passwordStore.SuppliedMKVNO != 1 ||
		passwordStore.MasterEnctype != crypto.EnctypeAES128SHA1 {
		t.Fatalf("password load supplied key = kvno %d enctype %d",
			passwordStore.SuppliedMKVNO, passwordStore.MasterEnctype)
	}
}

func TestOrdinaryDuplicateKeyDataRoundTrip(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.CreatePrincipal("user@EXAMPLE.COM", "password"); err != nil {
		t.Fatal(err)
	}
	name, err := principalForTest("user@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(name)
	if err != nil || !ok {
		t.Fatalf("lookup: %v %v", ok, err)
	}
	original := record.Keys[crypto.EnctypeAES256SHA1]
	older := original
	older.KVNO = 1
	latest := original
	latest.KVNO = 2
	record.Keys[crypto.EnctypeAES256SHA1] = latest
	record.KeyData = []kdb.Key{latest, older}
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	masterType, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	master, err := masterType.StringToKey([]byte("master"), []byte("EXAMPLE.COMKM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	dump, err := DumpWithMasterKey(db, crypto.EnctypeAES256SHA1, master)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ParseWithMasterKey(dump, crypto.EnctypeAES256SHA1, master)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := store.Lookup(name)
	if err != nil || !ok {
		t.Fatalf("loaded lookup: %v %v", ok, err)
	}
	if len(loaded.KeyData) != 2 || loaded.KeyData[0].KVNO != 2 ||
		loaded.KeyData[1].KVNO != 1 {
		t.Fatalf("duplicate key data lost or reordered: %#v", loaded.KeyData)
	}
}

func principalForTest(name string) (principal.Principal, error) {
	parsed, err := principal.Parse(name)
	if err != nil {
		return principal.Principal{}, err
	}
	return *parsed, nil
}

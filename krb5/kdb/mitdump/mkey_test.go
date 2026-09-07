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
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	old, err := etype.StringToKey([]byte("old"), []byte("EXAMPLE.COMKM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := etype.StringToKey([]byte("new"), []byte("EXAMPLE.COMKM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	db.MasterKeys = []kdb.Key{
		{Enctype: crypto.EnctypeAES256SHA1, KVNO: 2, Key: newKey},
		{Enctype: crypto.EnctypeAES256SHA1, KVNO: 1, Key: old},
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
	oldStore, err := ParseWithMasterKey(dump, crypto.EnctypeAES256SHA1, old)
	if err != nil {
		t.Fatalf("load with old master key: %v", err)
	}
	if len(oldStore.MasterKeys) != 2 {
		t.Fatalf("old-key master key count %d", len(oldStore.MasterKeys))
	}
}

func principalForTest(name string) (principal.Principal, error) {
	parsed, err := principal.Parse(name)
	if err != nil {
		return principal.Principal{}, err
	}
	return *parsed, nil
}

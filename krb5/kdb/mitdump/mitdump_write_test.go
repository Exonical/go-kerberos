package mitdump

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestDumpRoundTrip(t *testing.T) {
	const (
		realm    = "DUMP.TEST"
		password = "dump-master-password"
	)
	db := kdb.NewDatabase(realm)
	if err := db.AddPrincipal("alice@"+realm, "alice-password", 3); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("host/service."+strings.ToLower(realm), "service-password"); err != nil {
		t.Fatal(err)
	}
	aliceName, err := principal.Parse("alice@" + realm)
	if err != nil {
		t.Fatal(err)
	}
	alice, ok, err := db.Lookup(*aliceName)
	if err != nil || !ok {
		t.Fatalf("Lookup alice: %v, %v", err, ok)
	}
	alice.Flags = 0x80
	alice.MaxLife = 12 * time.Hour
	alice.MaxRenew = 48 * time.Hour
	alice.Expiration = time.Unix(1700000000, 0).UTC()
	alice.PasswordExpiration = time.Unix(1701000000, 0).UTC()
	alice.LastSuccess = time.Unix(1702000000, 0).UTC()
	alice.LastFailed = time.Unix(1703000000, 0).UTC()
	alice.FailAuthCount = 4
	alice.Policy = "test-policy"
	alice.TLData = []kdb.TLData{{Type: 42, Data: []byte{0xde, 0xad}}}
	// Use a special salt for one key to ensure the secondary key-data
	// component is preserved through the MIT representation.
	alice.Keys[crypto.EnctypeAES128SHA1] = kdb.Key{
		Enctype: crypto.EnctypeAES128SHA1,
		KVNO:    3,
		Key:     alice.Keys[crypto.EnctypeAES128SHA1].Key,
		Salt:    "custom-dump-salt",
	}
	if err := db.UpdatePrincipal(alice); err != nil {
		t.Fatal(err)
	}

	data, err := Dump(db, password)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if !bytes.HasPrefix(data, []byte(headerVersion7+"\n")) {
		t.Fatalf("dump header = %q", data[:min(len(data), 64)])
	}
	store, err := ParseWithMasterPassword(data, password)
	if err != nil {
		t.Fatalf("ParseWithMasterPassword: %v", err)
	}
	got, ok, err := store.Lookup(*aliceName)
	if err != nil || !ok {
		t.Fatalf("Lookup dumped alice: %v, %v", err, ok)
	}
	if got.Flags != alice.Flags || got.MaxLife != alice.MaxLife ||
		got.MaxRenew != alice.MaxRenew ||
		!got.Expiration.Equal(alice.Expiration) ||
		!got.PasswordExpiration.Equal(alice.PasswordExpiration) ||
		!got.LastSuccess.Equal(alice.LastSuccess) ||
		!got.LastFailed.Equal(alice.LastFailed) ||
		got.FailAuthCount != alice.FailAuthCount || got.Policy != alice.Policy {
		t.Fatalf("administrative fields changed: got %#v want %#v", got, alice)
	}
	if len(got.TLData) != len(alice.TLData)+1 ||
		got.TLData[0].Type != alice.TLData[0].Type ||
		!bytes.Equal(got.TLData[0].Data, alice.TLData[0].Data) {
		t.Fatalf("tagged data changed: got %#v want %#v", got.TLData, alice.TLData)
	}
	if got.KVNO != alice.KVNO || len(got.Keys) != len(alice.Keys) {
		t.Fatalf("key metadata changed: got kvno=%d keys=%d want kvno=%d keys=%d",
			got.KVNO, len(got.Keys), alice.KVNO, len(alice.Keys))
	}
	for enctype, want := range alice.Keys {
		gotKey, ok := got.Keys[enctype]
		if !ok || gotKey.KVNO != want.KVNO ||
			!bytes.Equal(gotKey.Key, want.Key) || gotKey.Salt != want.Salt {
			t.Fatalf("key %d changed: got %#v want %#v", enctype, gotKey, want)
		}
	}
}

func TestDumpWithMasterKeySupportsAllAESMasterEnctypes(t *testing.T) {
	db := kdb.NewDatabase("DUMP.TEST")
	if err := db.AddPrincipal("alice", "alice-password"); err != nil {
		t.Fatal(err)
	}
	for _, enctype := range []int32{
		crypto.EnctypeAES128SHA1,
		crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256,
		crypto.EnctypeAES256SHA384,
	} {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			t.Fatal(err)
		}
		masterKey, err := etype.StringToKey([]byte("master-password"),
			[]byte(db.Realm+"KM"), nil)
		if err != nil {
			t.Fatal(err)
		}
		data, err := DumpWithMasterKey(db, enctype, masterKey)
		if err != nil {
			t.Fatalf("DumpWithMasterKey(%d): %v", enctype, err)
		}
		if _, err := ParseWithMasterPassword(data, "master-password"); err != nil {
			t.Fatalf("ParseWithMasterPassword(%d): %v", enctype, err)
		}
	}
}

func TestDumpRejectsInvalidInputs(t *testing.T) {
	db := kdb.NewDatabase("DUMP.TEST")
	if err := db.AddPrincipal("alice", "alice-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := Dump(db, ""); err == nil {
		t.Fatal("Dump accepted empty master password")
	}
	if _, err := DumpWithMasterKey(db, 23, []byte("invalid")); err == nil {
		t.Fatal("DumpWithMasterKey accepted unsupported master enctype")
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DumpWithMasterKey(db, crypto.EnctypeAES256SHA1,
		make([]byte, etype.KeySize()-1)); err == nil {
		t.Fatal("DumpWithMasterKey accepted invalid master key length")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

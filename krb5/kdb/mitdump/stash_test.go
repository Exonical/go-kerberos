package mitdump

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestParseStashKeytabSelectsHighestKVNO(t *testing.T) {
	realm := "STASH.TEST"
	name := principal.Principal{Realm: realm, NameType: principal.NTPrincipal, Components: []string{"K", "M"}}
	entries := &keytab.Keytab{Entries: []keytab.Entry{
		{Principal: name, KVNO: 3, Enctype: crypto.EnctypeAES256SHA1, Key: bytes.Repeat([]byte{3}, 32)},
		{Principal: name, KVNO: 5, Enctype: crypto.EnctypeAES256SHA1, Key: bytes.Repeat([]byte{5}, 32)},
	}}
	var data bytes.Buffer
	if err := keytab.Write(&data, entries); err != nil {
		t.Fatal(err)
	}
	got, err := ParseStash(data.Bytes(), realm)
	if err != nil {
		t.Fatalf("ParseStash: %v", err)
	}
	if got.Enctype != crypto.EnctypeAES256SHA1 || got.KVNO != 5 ||
		!bytes.Equal(got.Key, bytes.Repeat([]byte{5}, 32)) {
		t.Fatalf("stash key = %#v", got)
	}
	selected, err := ParseStash(data.Bytes(), realm, 3)
	if err != nil {
		t.Fatalf("ParseStash requested KVNO: %v", err)
	}
	if selected.KVNO != 3 || !bytes.Equal(selected.Key, bytes.Repeat([]byte{3}, 32)) {
		t.Fatalf("requested stash key = %#v", selected)
	}
	if _, err := ParseStash(data.Bytes(), realm, 9); err == nil {
		t.Fatal("ParseStash accepted a missing requested KVNO")
	}
}

func TestParseStashLegacyBothByteOrders(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		t.Run(orderName(order), func(t *testing.T) {
			key := bytes.Repeat([]byte{0x42}, 32)
			data := make([]byte, 6+len(key))
			order.PutUint16(data[:2], uint16(crypto.EnctypeAES256SHA1))
			order.PutUint32(data[2:6], uint32(len(key)))
			copy(data[6:], key)
			got, err := ParseStash(data, "STASH.TEST")
			if err != nil {
				t.Fatalf("ParseStash: %v", err)
			}
			if got.Enctype != crypto.EnctypeAES256SHA1 || got.KVNO != 1 ||
				!bytes.Equal(got.Key, key) {
				t.Fatalf("stash key = %#v", got)
			}
		})
	}
}

func TestWriteAndLoadWithStash(t *testing.T) {
	const (
		realm    = "STASH.TEST"
		password = "master-password"
	)
	db := kdb.NewDatabase(realm)
	if err := db.AddPrincipal("alice@"+realm, "alice-password"); err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := etype.StringToKey([]byte(password), []byte(realm+"KM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	dump, err := DumpWithMasterKey(db, etype.ID(), masterKey)
	if err != nil {
		t.Fatalf("DumpWithMasterKey: %v", err)
	}
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "principal.dump")
	stashPath := filepath.Join(dir, ".k5."+realm)
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteStashFile(stashPath, realm, etype.ID(), 7, masterKey); err != nil {
		t.Fatalf("WriteStashFile: %v", err)
	}
	store, err := LoadWithStash(dumpPath, stashPath)
	if err != nil {
		t.Fatalf("LoadWithStash: %v", err)
	}
	name := principal.Principal{Realm: realm, Components: []string{"alice"}}
	record, ok, err := store.Lookup(name)
	if err != nil || !ok {
		t.Fatalf("Lookup alice: %v, %v", err, ok)
	}
	expected, err := etype.StringToKey([]byte("alice-password"), []byte(realm+"alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := record.Keys[etype.ID()]; !bytes.Equal(got.Key, expected) {
		t.Fatalf("alice key does not match: %x != %x", got.Key, expected)
	}
	if loaded, err := LoadWithMasterKey(dumpPath, etype.ID(), masterKey); err != nil {
		t.Fatalf("LoadWithMasterKey: %v", err)
	} else if _, ok, _ := loaded.Lookup(name); !ok {
		t.Fatal("LoadWithMasterKey omitted alice")
	}
}

func TestParseStashRejectsInvalidLegacyKeyLength(t *testing.T) {
	data := make([]byte, 6+16)
	binary.BigEndian.PutUint16(data[:2], uint16(crypto.EnctypeAES256SHA1))
	binary.BigEndian.PutUint32(data[2:6], 16)
	if _, err := ParseStash(data, "STASH.TEST"); err == nil {
		t.Fatal("ParseStash accepted an invalid AES master-key length")
	}
}

func TestParseStashRejectsMalformedLegacyData(t *testing.T) {
	tests := map[string][]byte{
		"truncated header": {0, 18, 0},
		"truncated key":    {0, 18, 0, 0, 0, 32, 1},
		"zero length":      {0, 18, 0, 0, 0, 0},
		"oversized length": {0, 18, 0, 0, 4, 1},
		"unsupported type": {0x7f, 0x7f, 0, 0, 0, 16,
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStash(data, "STASH.TEST"); err == nil {
				t.Fatal("ParseStash accepted malformed stash")
			}
		})
	}
}

func TestParseStashRejectsMissingKeytabPrincipal(t *testing.T) {
	kt := &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: principal.Principal{
			Realm: "STASH.TEST", NameType: principal.NTPrincipal,
			Components: []string{"not", "K/M"},
		},
		KVNO: 1, Enctype: crypto.EnctypeAES256SHA1, Key: bytes.Repeat([]byte{1}, 32),
	}}}
	var data bytes.Buffer
	if err := keytab.Write(&data, kt); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStash(data.Bytes(), "STASH.TEST"); err == nil {
		t.Fatal("ParseStash accepted keytab without K/M")
	}
}

func orderName(order binary.ByteOrder) string {
	if order == binary.LittleEndian {
		return "little-endian"
	}
	return "big-endian"
}

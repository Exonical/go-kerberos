package iprop

import (
	"bytes"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMasterKeyEntryRoundTripAndSaltForms(t *testing.T) {
	name, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{0x11}, etype.KeySize())
	record := kdb.PrincipalRecord{
		Name: *name,
		Keys: map[int32]kdb.Key{
			crypto.EnctypeAES256SHA1: {
				Enctype: crypto.EnctypeAES256SHA1, KVNO: 7,
				Key:  bytes.Repeat([]byte{0x22}, etype.KeySize()),
				Salt: "custom-salt",
			},
		},
	}
	entry, err := EntryFromRecordWithMasterKey(record, etype.ID(), master)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry) < 10 || len(entry[9].Keys) != 1 ||
		bytes.Equal(entry[9].Keys[0].Contents[0], record.Keys[etype.ID()].Key) {
		t.Fatalf("key was not encrypted in entry: %#v", entry)
	}
	decoded, err := RecordFromEntryWithMasterKey(*name, entry, etype.ID(), master)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Keys[etype.ID()].Key, record.Keys[etype.ID()].Key) ||
		decoded.Keys[etype.ID()].Salt != "custom-salt" {
		t.Fatalf("master-key round trip = %#v", decoded.Keys)
	}
	for _, salt := range []string{name.Realm + "alice", "alice", name.Realm, "other"} {
		kind, data := saltData(*name, salt)
		if salt == "other" && (kind != 4 || string(data) != salt) {
			t.Fatalf("custom salt = %d/%q", kind, data)
		}
	}
}

func TestMasterKeyConversionRejectsInvalidInputs(t *testing.T) {
	name, _ := principal.Parse("alice@EXAMPLE.COM")
	if _, err := EntryFromRecordWithMasterKey(kdb.PrincipalRecord{Name: *name},
		999, []byte{1}); err == nil {
		t.Fatal("unknown master enctype accepted")
	}
	if _, err := EntryFromRecordWithMasterKey(kdb.PrincipalRecord{Name: *name},
		crypto.EnctypeAES256SHA1, []byte{1}); err == nil {
		t.Fatal("short master key accepted")
	}
	if _, err := RecordFromEntryWithMasterKey(*name, Entry{{Type: ATKeyData,
		Keys: []Key{{Version: 1, KVNO: 1, Enctypes: []int32{crypto.EnctypeAES256SHA1},
			Contents: [][]byte{{1}}}}}}, crypto.EnctypeAES256SHA1,
		bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("truncated encrypted key accepted")
	}
	if _, err := RecordFromEntry(*name, Entry{{Type: ATPrinc,
		Principal: Principal{Realm: nil}}}); err == nil {
		t.Fatal("invalid principal accepted")
	}
}

func TestKeyMapPlaintextAndSaltDecoding(t *testing.T) {
	name, _ := principal.Parse("alice@EXAMPLE.COM")
	values := []Key{
		{Version: 1, KVNO: 2, Enctypes: []int32{18}, Contents: [][]byte{{1, 2, 3}}},
		{Version: 2, KVNO: 3, Enctypes: []int32{17, 2}, Contents: [][]byte{{4}, nil}},
		{Version: 2, KVNO: 4, Enctypes: []int32{23, 3}, Contents: [][]byte{{5}, nil}},
		{Version: 2, KVNO: 5, Enctypes: []int32{16, 4}, Contents: [][]byte{{6}, []byte("custom")}},
	}
	got := keyMap(values, *name)
	if len(got) != 4 || got[18].KVNO != 2 || got[17].Salt != "alice" ||
		got[23].Salt != "EXAMPLE.COM" || got[16].Salt != "custom" {
		t.Fatalf("plaintext key map = %#v", got)
	}
	if len(keyMap([]Key{{}}, *name)) != 0 {
		t.Fatal("empty key record was not ignored")
	}
}

func TestIPROPMalformedWireIsRejected(t *testing.T) {
	for _, data := range [][]byte{{0}, {0, 0, 0, 1}, bytes.Repeat([]byte{0xff}, 32)} {
		if _, err := UnmarshalLast(data); err == nil {
			t.Errorf("UnmarshalLast accepted %x", data)
		}
		if _, err := UnmarshalIncrementalResult(data); err == nil {
			t.Errorf("UnmarshalIncrementalResult accepted %x", data)
		}
		if _, err := UnmarshalFullResyncResult(data); err == nil {
			t.Errorf("UnmarshalFullResyncResult accepted %x", data)
		}
	}
}

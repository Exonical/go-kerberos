package iprop

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

type failingEType struct{}

func (failingEType) ID() int32                                  { return 18 }
func (failingEType) KeySize() int                               { return 32 }
func (failingEType) StringToKey(_, _, _ []byte) ([]byte, error) { return nil, nil }
func (failingEType) Encrypt([]byte, uint32, []byte) ([]byte, error) {
	return nil, fmt.Errorf("encryption failed")
}
func (failingEType) Decrypt([]byte, uint32, []byte) ([]byte, error)      { return nil, nil }
func (failingEType) Checksum([]byte, uint32, []byte) ([]byte, error)     { return nil, nil }
func (failingEType) ChecksumSize() int                                   { return 0 }
func (failingEType) VerifyChecksum([]byte, uint32, []byte, []byte) error { return nil }

func TestKeyValuesPropagatesEncryptionFailure(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	_, err := keyValues(name, map[int32]kdb.Key{
		18: {Enctype: 18, Key: []byte{1, 2, 3}},
	}, failingEType{}, []byte("master"))
	if err == nil {
		t.Fatal("key encryption failure was discarded")
	}
}

func TestLastGoldenEncoding(t *testing.T) {
	got := Last{LastSno: 0x01020304, LastTime: Time{Seconds: 5, Useconds: 6}}.MarshalXDR()
	want := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x06,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Last encoding = %x, want %x", got, want)
	}
	decoded, err := UnmarshalLast(got)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != (Last{LastSno: 0x01020304, LastTime: Time{Seconds: 5, Useconds: 6}}) {
		t.Fatalf("decoded Last = %#v", decoded)
	}
}

func TestIncrementalRoundTrip(t *testing.T) {
	name, err := principal.Parse("host/replica@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	value := IncrementalResult{
		LastEntry: Last{LastSno: 4, LastTime: Time{Seconds: 20, Useconds: 7}},
		Ret:       UpdateOK,
		Updates: []Update{{
			PrincipalName: name.String(),
			EntrySno:      4,
			Time:          Time{Seconds: 20, Useconds: 7},
			Entry: Entry{
				{Type: ATAttrFlags, Uint32: 0x1234},
				{Type: ATPrinc, Principal: principalValue(*name)},
				{Type: ATKeyData, Keys: []Key{{
					Version:  1,
					KVNO:     3,
					Enctypes: []int32{18},
					Contents: [][]byte{{1, 2, 3}},
				}}},
				{Type: ATTlData, TLData: []TL{{Type: 3, Data: []byte{4, 5, 6}}}},
				{Type: ATPWHist, PasswordHistory: [][]Key{{{
					Version: 1, KVNO: 2, Enctypes: []int32{18},
					Contents: [][]byte{{7, 8}},
				}}}},
				{Type: ATPWPolicySwitch, Bool: true},
				{Type: ATModWhere, String: []byte("master")},
				{Type: AttrType(99), Extension: []byte{8, 9}},
			},
			Commit:     true,
			KDCSSeenBy: []string{"host/replica@EXAMPLE.COM"},
			Futures:    []byte{10, 11},
		}},
	}
	encoded := value.MarshalXDR()
	decoded, err := UnmarshalIncrementalResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.MarshalXDR(), encoded) {
		t.Fatalf("round-trip changed bytes: %x != %x", decoded.MarshalXDR(), encoded)
	}
	if len(decoded.Updates) != 1 || decoded.Updates[0].PrincipalName != name.String() {
		t.Fatalf("decoded update = %#v", decoded.Updates)
	}
}

func TestFullResyncRoundTrip(t *testing.T) {
	value := FullResyncResult{
		LastEntry: Last{LastSno: 9, LastTime: Time{Seconds: 10}},
		Ret:       UpdateFullResyncNeeded,
	}
	decoded, err := UnmarshalFullResyncResult(value.MarshalXDR())
	if err != nil {
		t.Fatal(err)
	}
	if decoded != value {
		t.Fatalf("decoded full result = %#v, want %#v", decoded, value)
	}
}

func TestPrincipalRecordAttributeRoundTrip(t *testing.T) {
	name, err := principal.Parse("user/admin@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	record := kdb.PrincipalRecord{
		Name:               *name,
		Keys:               map[int32]kdb.Key{18: {Enctype: 18, KVNO: 4, Key: []byte{1, 2, 3}}},
		Flags:              0x40,
		MaxLife:            8 * time.Hour,
		MaxRenew:           24 * time.Hour,
		Expiration:         time.Unix(100, 0).UTC(),
		PasswordExpiration: time.Unix(200, 0).UTC(),
		LastSuccess:        time.Unix(300, 0).UTC(),
		LastFailed:         time.Unix(400, 0).UTC(),
		FailAuthCount:      2,
		LastPasswordChange: time.Unix(500, 0).UTC(),
		Policy:             "default",
		TLData:             []kdb.TLData{{Type: 42, Data: []byte{9, 8, 7}}},
	}
	encoded, err := EntryFromRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := RecordFromEntry(*name, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if converted.Name.String() != record.Name.String() ||
		converted.Flags != record.Flags ||
		converted.MaxLife != record.MaxLife ||
		converted.MaxRenew != record.MaxRenew ||
		!converted.Expiration.Equal(record.Expiration) ||
		!converted.PasswordExpiration.Equal(record.PasswordExpiration) ||
		!converted.LastSuccess.Equal(record.LastSuccess) ||
		!converted.LastFailed.Equal(record.LastFailed) ||
		converted.FailAuthCount != record.FailAuthCount ||
		!converted.LastPasswordChange.Equal(record.LastPasswordChange) ||
		converted.Policy != record.Policy {
		t.Fatalf("record metadata changed: %#v", converted)
	}
	if len(converted.Keys) != 1 || converted.Keys[18].KVNO != 4 ||
		!bytes.Equal(converted.Keys[18].Key, []byte{1, 2, 3}) {
		t.Fatalf("record keys changed: %#v", converted.Keys)
	}
	if len(converted.TLData) != 1 || !bytes.Equal(converted.TLData[0].Data, []byte{9, 8, 7}) {
		t.Fatalf("record TL data changed: %#v", converted.TLData)
	}
}

func TestReplicaAppliesCommittedAndDeletedUpdates(t *testing.T) {
	master, err := principal.Parse("host/master@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	db := kdb.NewDatabase("EXAMPLE.COM")
	replica := &Replica{Database: db}
	record := kdb.PrincipalRecord{
		Name:  *master,
		Keys:  map[int32]kdb.Key{18: {Enctype: 18, KVNO: 2, Key: []byte{1, 2}}},
		Flags: 7,
	}
	encoded, err := EntryFromRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.apply([]Update{{
		PrincipalName: master.String(),
		Entry:         encoded,
		Commit:        true,
	}}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.Lookup(*master)
	if err != nil || !ok {
		t.Fatalf("replica lookup = %#v, %v, %v", got, ok, err)
	}
	if got.Flags != 7 || got.Keys[18].KVNO != 2 {
		t.Fatalf("replica record = %#v", got)
	}
	if err := replica.apply([]Update{{
		PrincipalName: master.String(),
		Entry:         encoded,
		Commit:        false,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := replica.apply([]Update{{
		PrincipalName: master.String(),
		Deleted:       true,
		Commit:        true,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.Lookup(*master); ok {
		t.Fatal("deleted principal still present")
	}
}

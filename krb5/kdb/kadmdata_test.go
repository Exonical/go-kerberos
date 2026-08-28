package kdb

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestKADMDataHistoryRoundTrip(t *testing.T) {
	db := NewDatabase("KADM.TEST")
	if err := db.AddPrincipal("alice", "alice-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("kadmin/history", "history-password", 2); err != nil {
		t.Fatal(err)
	}
	aliceName, err := principal.Parse("alice@KADM.TEST")
	if err != nil {
		t.Fatal(err)
	}
	historyName, err := principal.Parse("kadmin/history@KADM.TEST")
	if err != nil {
		t.Fatal(err)
	}
	alice, ok, err := db.Lookup(*aliceName)
	if err != nil || !ok {
		t.Fatalf("alice lookup: %v, %v", err, ok)
	}
	history, ok, err := db.Lookup(*historyName)
	if err != nil || !ok {
		t.Fatalf("history lookup: %v, %v", err, ok)
	}
	historyKey := history.Keys[18]
	data, err := EncodeKADMData(KADMData{
		Policy: "strong", AuxAttributes: kadmPolicy, AdminHistoryKVNO: 2,
		OldKeyNext: 1, OldKeys: []map[int32]Key{alice.Keys},
	}, &historyKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeKADMData(data, keyList(history.Keys), "KADM.TESTalice")
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Policy != "strong" || decoded.AuxAttributes != kadmPolicy ||
		decoded.OldKeyNext != 1 ||
		decoded.AdminHistoryKVNO != 2 || len(decoded.OldKeys) != 1 {
		t.Fatalf("decoded KADM data = %#v", decoded)
	}
	for enctype, want := range alice.Keys {
		got, ok := decoded.OldKeys[0][enctype]
		if !ok || got.KVNO != want.KVNO || got.Salt != want.Salt ||
			!bytes.Equal(got.Key, want.Key) {
			t.Fatalf("decoded history key %d = %#v, want %#v", enctype, got, want)
		}
	}
}

func TestKADMDataNormalizesWrappedHistoryCursor(t *testing.T) {
	db := NewDatabase("KADM.TEST")
	if err := db.AddPrincipal("alice", "alice-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("kadmin/history", "history-password", 2); err != nil {
		t.Fatal(err)
	}
	aliceName, err := principal.Parse("alice@KADM.TEST")
	if err != nil {
		t.Fatal(err)
	}
	historyName, err := principal.Parse("kadmin/history@KADM.TEST")
	if err != nil {
		t.Fatal(err)
	}
	alice, ok, err := db.Lookup(*aliceName)
	if err != nil || !ok {
		t.Fatalf("alice lookup: %v, %v", err, ok)
	}
	history, ok, err := db.Lookup(*historyName)
	if err != nil || !ok {
		t.Fatalf("history lookup: %v, %v", err, ok)
	}
	historyKey := history.Keys[18]
	base := alice.Keys[18]
	makeEntry := func(marker byte) map[int32]Key {
		key := base
		key.Key = append([]byte(nil), base.Key...)
		key.Key[0] = marker
		return map[int32]Key{18: key}
	}
	encoded, err := EncodeKADMData(KADMData{
		Policy: "wrapped", AdminHistoryKVNO: 2,
		OldKeys: []map[int32]Key{makeEntry(3), makeEntry(2), makeEntry(1)},
	}, &historyKey)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the normalized cursor with a wrapped MIT cursor.
	binary.BigEndian.PutUint32(encoded[20:24], 1)
	wrapped, err := DecodeKADMData(encoded, keyList(history.Keys), "KADM.TESTalice")
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.OldKeyNext != 1 {
		t.Fatalf("wrapped cursor = %d, want 1", wrapped.OldKeyNext)
	}
	reencoded, err := EncodeKADMData(wrapped, &historyKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(reencoded[20:24]); got != 3 {
		t.Fatalf("re-encoded cursor = %d, want 3", got)
	}
	roundTrip, err := DecodeKADMData(reencoded, keyList(history.Keys), "KADM.TESTalice")
	if err != nil {
		t.Fatal(err)
	}
	if len(roundTrip.OldKeys) != len(wrapped.OldKeys) {
		t.Fatalf("round-trip history length = %d, want %d",
			len(roundTrip.OldKeys), len(wrapped.OldKeys))
	}
	for i := range wrapped.OldKeys {
		if wrapped.OldKeys[i][18].Key[0] != roundTrip.OldKeys[i][18].Key[0] {
			t.Fatalf("round-trip history order = %v, want %v",
				roundTrip.OldKeys, wrapped.OldKeys)
		}
	}
}

func TestChangePasswordWritesKADMDataHistory(t *testing.T) {
	db := NewDatabase("KADM.TEST")
	if err := db.AddPrincipal("alice", "alice-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("kadmin/history", "history-password", 2); err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse("alice@KADM.TEST")
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("alice lookup: %v, %v", err, ok)
	}
	record.Policy = "strong"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	if err := db.ChangePasswordWithPolicy(*name, "new-password", record.LastPasswordChange.Add(1),
		&PolicyRecord{Name: "strong", HistoryNum: 3}, false); err != nil {
		t.Fatal(err)
	}
	record, ok, err = db.Lookup(*name)
	if err != nil || !ok {
		t.Fatalf("updated alice lookup: %v, %v", err, ok)
	}
	if len(record.PasswordHistory) != 1 || record.AdminHistoryKVNO != 2 {
		t.Fatalf("history metadata = %#v", record)
	}
	var raw []byte
	for _, item := range record.TLData {
		if item.Type == KADMDataType {
			raw = item.Data
		}
	}
	if len(raw) == 0 {
		t.Fatal("password change did not write KADM data")
	}
	historyName, _ := principal.Parse("kadmin/history@KADM.TEST")
	history, _, _ := db.Lookup(*historyName)
	decoded, err := DecodeKADMData(raw, keyList(history.Keys), "KADM.TESTalice")
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.OldKeys) != 1 {
		t.Fatalf("decoded history entries = %d, want 1", len(decoded.OldKeys))
	}
}

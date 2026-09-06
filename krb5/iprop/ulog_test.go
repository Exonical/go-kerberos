package iprop

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestUlogRoundTripAndReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "principal.ulog")
	log, err := Create(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	update := Update{
		PrincipalName: "alice@EXAMPLE.COM",
		EntrySno:      1,
		Time:          Time{Seconds: 10, Useconds: 20},
		Commit:        true,
	}
	if err := log.AddUpdate(update); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	last, err := log.Last()
	if err != nil || last.LastSno != 1 || last.LastTime != update.Time {
		t.Fatalf("last = %#v, %v", last, err)
	}
	entries, err := log.GetEntries(0)
	if err != nil || len(entries) != 1 || entries[0].Update.PrincipalName != update.PrincipalName {
		t.Fatalf("entries = %#v, %v", entries, err)
	}
	if err := log.Reset(); err != nil {
		t.Fatal(err)
	}
	last, err = log.Last()
	if err != nil || last.LastSno != 1 {
		t.Fatalf("reset last = %#v, %v", last, err)
	}
}

func TestUlogHeaderBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "principal.ulog")
	log, err := Create(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "12126606010000000100000000000000000000000000000000000000010000000100000001000008"
	if got := hex.EncodeToString(data[:40]); got != want {
		t.Fatalf("header = %s, want %s", got, want)
	}
}

func TestUlogEntryCountAndReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "principal.ulog")
	log, err := Create(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	for serial := uint32(1); serial <= 5; serial++ {
		if err := log.AddUpdate(Update{
			PrincipalName: "user",
			EntrySno:      serial,
			Time:          Time{Seconds: serial},
			Commit:        true,
		}); err != nil {
			t.Fatal(err)
		}
		want := serial
		if want > 3 {
			want = 3
		}
		if got := log.Header().NumEntries; got != want {
			t.Fatalf("serial %d: NumEntries = %d, want %d", serial, got, want)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := readOnly.AddUpdate(Update{PrincipalName: "blocked"}); err == nil {
		t.Fatal("read-only AddUpdate unexpectedly succeeded")
	}
	if err := readOnly.Reset(); err == nil {
		t.Fatal("read-only Reset unexpectedly succeeded")
	}
	entries, err := readOnly.GetEntries(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3 after wraparound", len(entries))
	}
}

package mitdump

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "testdata", "mitdump", "test-gokrb5.dump"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseMITDumpFixture(t *testing.T) {
	store, err := ParseWithMasterPassword(fixtureBytes(t), "synthetic-master-password")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	alice, ok, err := store.Lookup(principal.Principal{
		Realm: "TEST.GOKRB5.LOCAL", Components: []string{"alice"},
	})
	if err != nil {
		t.Fatalf("Lookup alice: %v", err)
	}
	if !ok {
		t.Fatal("alice missing")
	}
	if alice.MaxLife != 24*time.Hour {
		t.Fatalf("alice max life = %v", alice.MaxLife)
	}
	if len(alice.Keys) != 2 {
		t.Fatalf("alice key count = %d, want 2", len(alice.Keys))
	}
	for _, enctype := range []int32{crypto.EnctypeAES256SHA1, crypto.EnctypeAES128SHA1} {
		key, ok := alice.Keys[enctype]
		if !ok {
			t.Fatalf("alice missing enctype %d", enctype)
		}
		if key.KVNO != 1 {
			t.Fatalf("alice enctype %d kvno = %d, want 1", enctype, key.KVNO)
		}
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := etype.StringToKey([]byte("alice-password"),
			[]byte("TEST.GOKRB5.LOCALalice"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key.Key, expected) {
			t.Fatalf("alice enctype %d key does not match MIT string-to-key", enctype)
		}
	}
	host, ok, err := store.Lookup(principal.Principal{
		Realm: "TEST.GOKRB5.LOCAL", Components: []string{"host", "service.test"},
	})
	if err != nil {
		t.Fatalf("Lookup host: %v", err)
	}
	if !ok || host.Keys[crypto.EnctypeAES256SHA1].KVNO != 1 {
		t.Fatalf("host record = %#v", host)
	}
	tgt, ok, err := store.Lookup(principal.Principal{
		Realm: "TEST.GOKRB5.LOCAL", Components: []string{"krbtgt", "TEST.GOKRB5.LOCAL"},
	})
	if err != nil {
		t.Fatalf("Lookup krbtgt: %v", err)
	}
	if !ok || tgt.Flags != 8388608 {
		t.Fatalf("krbtgt record = %#v", tgt)
	}
}

func TestParseMITDumpRejectsWrongMasterPassword(t *testing.T) {
	if _, err := ParseWithMasterPassword(fixtureBytes(t), "wrong-password"); err == nil {
		t.Fatal("ParseWithMasterPassword unexpectedly succeeded")
	}
}

func TestParseMITDumpRejectsUnsupportedMasterEnctype(t *testing.T) {
	realm := "TEST.GOKRB5.LOCAL"
	name := "K/M@" + realm
	record := fmt.Sprintf("princ\t%d\t%d\t0\t1\t0\t%s\t0\t0\t0\t0\t0\t0\t0\t0\t1\t1\t23\t0\t-1\t-1;\n",
		len(name), len(name), name)
	data := append(append([]byte(nil), fixtureBytes(t)...), []byte(record)...)
	_, err := ParseWithMasterPassword(data, "synthetic-master-password")
	if err == nil || !strings.Contains(err.Error(), "unsupported MIT dump master enctype 23") {
		t.Fatalf("error = %v, want unsupported master enctype", err)
	}
}

func TestParseMITDumpAcceptsVersion7(t *testing.T) {
	data := bytes.Replace(fixtureBytes(t),
		[]byte("kdb5_util load_dump version 6"),
		[]byte("kdb5_util load_dump version 7"), 1)
	if _, err := ParseWithMasterPassword(data, "synthetic-master-password"); err != nil {
		t.Fatalf("ParseWithMasterPassword version 7: %v", err)
	}
}

func TestParseMITDumpRejectsMalformedInput(t *testing.T) {
	fixture := fixtureBytes(t)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "unsupported version", data: bytes.Replace(fixture,
			[]byte("kdb5_util load_dump version 6"), []byte("kdb5_util load_dump version 8"), 1)},
		{name: "truncated record", data: fixture[:len(fixture)-10]},
		{name: "bad hex", data: bytes.Replace(fixture, []byte("20001f"), []byte("20001z"), 1)},
		{name: "unknown record", data: []byte("kdb5_util load_dump version 6\nunknown\t;\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.data); err == nil {
				t.Fatal("Parse unexpectedly succeeded")
			}
		})
	}
}

func FuzzParseMITDump(f *testing.F) {
	root := filepath.Join("..", "..", "..")
	fixture, err := os.ReadFile(filepath.Join(root, "testdata", "mitdump", "test-gokrb5.dump"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fixture)
	f.Add([]byte("kdb5_util load_dump version 7\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Parse(input)
	})
}

package keytab

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// These bytes follow the MIT FILE keytab v2 format:
// https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html
func counted16(w io.Writer, value []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(value))); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}

func TestResolveWithConfigExpandsDefaultKeytab(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keytab")
	if err := os.WriteFile(path, []byte{0x05, 0x02}, 0600); err != nil {
		t.Fatal(err)
	}
	kt, err := ResolveWithConfig("", &config.Config{DefaultKeytabName: "FILE:" + path})
	if err != nil {
		t.Fatal(err)
	}
	if kt == nil {
		t.Fatal("ResolveWithConfig returned nil keytab")
	}
	if _, err := ResolveClientWithConfig("", &config.Config{DefaultClientKeytabName: "FILE:" + path}); err != nil {
		t.Fatalf("ResolveClientWithConfig: %v", err)
	}
}

func TestResolveClientWithConfigUsesMITNameChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.keytab")
	if err := os.WriteFile(path, []byte{0x05, 0x02}, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_CLIENT_KTNAME", "FILE:"+path)
	t.Setenv("KRB5_KTNAME", "FILE:"+filepath.Join(t.TempDir(), "server-must-not-win"))
	if _, err := ResolveClientWithConfig("", &config.Config{
		DefaultKeytabName:       "FILE:" + filepath.Join(t.TempDir(), "default-must-not-win"),
		DefaultClientKeytabName: "FILE:" + filepath.Join(t.TempDir(), "client-must-not-win"),
	}); err != nil {
		t.Fatalf("client environment keytab: %v", err)
	}

	t.Setenv("KRB5_CLIENT_KTNAME", "")
	clientDefault := filepath.Join(t.TempDir(), "client-default")
	if _, err := ResolveClientWithConfig("", &config.Config{
		DefaultKeytabName:       "FILE:" + path,
		DefaultClientKeytabName: "FILE:" + clientDefault,
	}); err == nil {
		t.Fatal("client resolver unexpectedly used server default")
	}
	t.Setenv("KRB5_KTNAME", "")
	errTarget := "/var/kerberos/krb5/user/"
	if _, err := ResolveClientWithConfig("", &config.Config{DefaultKeytabName: "FILE:" + path}); err == nil {
		t.Fatal("client resolver unexpectedly used default_keytab_name")
	} else if !strings.Contains(err.Error(), errTarget) {
		t.Fatalf("client default error = %v, want compile-time client path", err)
	}
}

func keytabRecord(p principal.Principal, timestamp uint32, kvno uint32, enctype uint16, key []byte) ([]byte, error) {
	var record bytes.Buffer
	if err := binary.Write(&record, binary.BigEndian, uint16(len(p.Components))); err != nil {
		return nil, err
	}
	if err := counted16(&record, []byte(p.Realm)); err != nil {
		return nil, err
	}
	for _, component := range p.Components {
		if err := counted16(&record, []byte(component)); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(&record, binary.BigEndian, uint32(p.NameType)); err != nil {
		return nil, err
	}
	if err := binary.Write(&record, binary.BigEndian, timestamp); err != nil {
		return nil, err
	}
	if err := binary.Write(&record, binary.BigEndian, uint8(kvno)); err != nil {
		return nil, err
	}
	if err := binary.Write(&record, binary.BigEndian, enctype); err != nil {
		return nil, err
	}
	if err := counted16(&record, key); err != nil {
		return nil, err
	}
	if err := binary.Write(&record, binary.BigEndian, kvno); err != nil {
		return nil, err
	}
	return record.Bytes(), nil
}

func syntheticKeytab() ([]byte, error) {
	p := principal.Principal{
		Realm:      "REALM",
		NameType:   principal.NTPrincipal,
		Components: []string{"alice"},
	}
	record, err := keytabRecord(p, 100, 0x107, 17, []byte{1, 2, 3, 4})
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, int32(len(record))); err != nil {
		return nil, err
	}
	if _, err := b.Write(record); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func TestReadKeytabV2(t *testing.T) {
	data, err := syntheticKeytab()
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	kt, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(kt.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(kt.Entries))
	}
	entry := kt.Entries[0]
	if entry.Principal.Realm != "REALM" ||
		entry.Principal.NameType != principal.NTPrincipal ||
		len(entry.Principal.Components) != 1 ||
		entry.Principal.Components[0] != "alice" ||
		entry.KVNO != 0x107 || entry.Enctype != 17 || entry.Timestamp != 100 {
		t.Fatalf("entry metadata = %#v", entry)
	}
}

func TestReadKeytabMultiComponentAndUnknownEnctype(t *testing.T) {
	p := principal.Principal{
		Realm:      "EXAMPLE.COM",
		NameType:   principal.NTSrvHst,
		Components: []string{"host", "server.example.com"},
	}
	record, err := keytabRecord(p, 200, 3, 999, []byte{9, 8, 7})
	if err != nil {
		t.Fatalf("build record: %v", err)
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.BigEndian, Version); err != nil {
		t.Fatalf("write version: %v", err)
	}
	if err := binary.Write(&data, binary.BigEndian, int32(len(record))); err != nil {
		t.Fatalf("write record length: %v", err)
	}
	if _, err := data.Write(record); err != nil {
		t.Fatalf("write record: %v", err)
	}
	kt, err := Read(bytes.NewReader(data.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(kt.Entries) != 1 || kt.Entries[0].Enctype != 999 ||
		len(kt.Entries[0].Principal.Components) != 2 {
		t.Fatalf("parsed entry = %#v", kt.Entries)
	}
}

func TestKeytabNegativeLengthHoleIsSkipped(t *testing.T) {
	record, err := syntheticKeytab()
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.BigEndian, Version); err != nil {
		t.Fatalf("write version: %v", err)
	}
	if err := binary.Write(&data, binary.BigEndian, int32(-4)); err != nil {
		t.Fatalf("write hole length: %v", err)
	}
	if _, err := data.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("write hole: %v", err)
	}
	if _, err := data.Write(record[2:]); err != nil {
		t.Fatalf("write record: %v", err)
	}
	kt, err := Read(bytes.NewReader(data.Bytes()))
	if err != nil {
		t.Fatalf("Read with hole: %v", err)
	}
	if len(kt.Entries) != 1 {
		t.Fatalf("entries after hole = %d, want 1", len(kt.Entries))
	}
}

func TestWriteKeytabAndLookups(t *testing.T) {
	p := principal.Principal{Realm: "REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	kt := &Keytab{Entries: []Entry{
		{Principal: p, Timestamp: 100, KVNO: 7, Enctype: 17, Key: []byte{1, 2, 3, 4}},
		{Principal: p, Timestamp: 101, KVNO: 8, Enctype: 18, Key: []byte{5, 6, 7, 8}},
	}}
	var out bytes.Buffer
	if err := Write(&out, kt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, lookup := range []func() ([]Entry, error){
		func() ([]Entry, error) { return kt.LookupPrincipal(p) },
		func() ([]Entry, error) { return kt.LookupEnctype(18) },
		func() ([]Entry, error) { return kt.LookupKVNO(8) },
	} {
		entries, err := lookup()
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if len(entries) == 0 {
			t.Fatal("lookup returned no entries")
		}
	}
}

func TestKeytabMalformedRecords(t *testing.T) {
	tests := [][]byte{
		{0x05, 0x02, 0, 0, 0, 4, 0, 0},
		{0x05, 0x02, 0, 0, 0, 20, 0, 1},
		{0x05, 0x02, 0xff, 0xff, 0xff, 0xf8, 0, 0},
	}
	for _, input := range tests {
		if _, err := Read(bytes.NewReader(input)); err == nil {
			t.Fatalf("malformed keytab %x unexpectedly accepted", input)
		}
	}
}

func TestReadMITGeneratedKeytabFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/keytabs/mit-multi-enctype.keytab")
	if os.IsNotExist(err) {
		t.Skipf("fixture not yet generated: %s", "../../testdata/keytabs/mit-multi-enctype.keytab")
	}
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if _, err := Read(bytes.NewReader(data)); err != nil {
		t.Fatalf("Read MIT-generated keytab: %v", err)
	}
}

func TestMemoryKeytabResolveSharesEntries(t *testing.T) {
	name := "MEMORY:go-keytab-test"
	first, err := Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	first.Entries = nil
	if len(first.Entries) != 0 {
		t.Fatal("new MEMORY keytab was not empty")
	}
	entry := Entry{
		Principal: principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "service"}},
		Timestamp: 1, KVNO: 2, Enctype: 17, Key: []byte{1, 2, 3},
	}
	if err := first.AddEntry(entry); err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(second.Entries) != 1 ||
		!entriesEqual(second.Entries[0], entry) {
		t.Fatalf("shared MEMORY keytab = %#v", second.Entries)
	}
	if err := second.RemoveEntry(entry); err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 0 {
		t.Fatal("MEMORY keytab removal was not shared")
	}
}

func TestMemoryKeytabConcurrentResolve(t *testing.T) {
	const workers = 32
	results := make(chan *Keytab, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kt, err := Resolve("MEMORY:go-keytab-concurrent-test")
			if err != nil {
				t.Errorf("Resolve: %v", err)
				return
			}
			results <- kt
		}()
	}
	wg.Wait()
	close(results)
	var first *Keytab
	for kt := range results {
		if first == nil {
			first = kt
		} else if first != kt {
			t.Fatal("concurrent MEMORY resolves returned different keytabs")
		}
	}
}

func TestMemoryKeytabConcurrentReadersAndWriters(t *testing.T) {
	kt, err := Resolve("MEMORY:go-keytab-reader-writer-test")
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{
		Principal: principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "service"}},
		Timestamp: 1, KVNO: 2, Enctype: 17, Key: []byte{1, 2, 3},
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if i%2 == 0 {
					_ = kt.AddEntry(entry)
				} else {
					_, _ = kt.LookupPrincipal(entry.Principal)
					_, _ = kt.LookupEnctype(entry.Enctype)
					_, _ = kt.LookupKVNO(entry.KVNO)
				}
			}
		}(i)
	}
	wg.Wait()
	entries, err := kt.LookupPrincipal(entry.Principal)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("concurrent readers observed no entries")
	}
	entries[0].Key[0] = 99
	again, err := kt.LookupPrincipal(entry.Principal)
	if err != nil || len(again) == 0 || again[0].Key[0] != 1 {
		t.Fatalf("lookup did not return an isolated snapshot: %#v, %v", again, err)
	}
}

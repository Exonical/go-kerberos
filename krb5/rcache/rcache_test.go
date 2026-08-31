package rcache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

func TestSipHashMITVectors(t *testing.T) {
	seed := make([]byte, 16)
	for i := range seed {
		seed[i] = byte(i)
	}
	want := []uint64{
		0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a,
		0x85676696d7fb7e2d, 0xcf2794e0277187b7, 0x18765564cd99a68d,
		0xcbc9466e58fee3ce, 0xab0200f58b01d137, 0x93f5f5799a932462,
		0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
		0x751e8fbc860ee5fb,
	}
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	for i, expected := range want {
		if got := sipHash24(data[:i], seed); got != expected {
			t.Fatalf("length %d: got %#x, want %#x", i, got, expected)
		}
	}
}

func TestTagFromCiphertextUsesChecksumTrailer(t *testing.T) {
	ciphertext := make([]byte, 40)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	tests := []struct {
		name       string
		trailerLen int
		want       []byte
	}{
		{name: "aes-sha1", trailerLen: 12, want: ciphertext[28:40]},
		{name: "aes128-sha256", trailerLen: 16, want: ciphertext[24:36]},
		{name: "aes256-sha384", trailerLen: 24, want: ciphertext[16:28]},
		{name: "camellia", trailerLen: 16, want: ciphertext[24:36]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := TagFromCiphertext(ciphertext, test.trailerLen); !bytes.Equal(got, test.want) {
				t.Fatalf("tag = %x, want %x", got, test.want)
			}
		})
	}
}

func TestFile2SeedAndExactRecordLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.rcache2")
	seed := make([]byte, hashSeedLen)
	for i := range seed {
		seed[i] = byte(0xa0 + i)
	}
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	tag := []byte("fixed-tag")
	now := time.Unix(0x01020304, 0).UTC()
	if err := (&File2{Path: path}).Store(tag, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	index := int(sipHash24(append(tag, make([]byte, tagLen-len(tag))...), seed) % firstTableRecords)
	offset := hashSeedLen + index*recordLen
	if len(data) != offset+recordLen {
		t.Fatalf("file length %d, want %d", len(data), offset+recordLen)
	}
	if !bytes.Equal(data[:hashSeedLen], seed) {
		t.Fatal("file seed changed")
	}
	if !bytes.Equal(data[offset:offset+tagLen], append(tag, make([]byte, tagLen-len(tag))...)) {
		t.Fatalf("record tag = %x", data[offset:offset+tagLen])
	}
	if got := binary.BigEndian.Uint32(data[offset+tagLen : offset+recordLen]); got != 0x01020304 {
		t.Fatalf("record timestamp = %#x", got)
	}
	if err := (&File2{Path: path}).Store(tag, now, time.Minute); !errors.Is(err, krberrors.ErrReplay) {
		t.Fatalf("second store error = %v, want replay", err)
	}
}

func TestFile2ReusesExpiredAndWrapsTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.rcache2")
	seed := bytes.Repeat([]byte{7}, hashSeedLen)
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	tag := bytes.Repeat([]byte{1}, tagLen)
	index := int(sipHash24(tag, seed) % firstTableRecords)
	offset := int64(hashSeedLen + index*recordLen)
	record := make([]byte, recordLen)
	copy(record, bytes.Repeat([]byte{2}, tagLen))
	binary.BigEndian.PutUint32(record[tagLen:], 100)
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(record, offset); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (&File2{Path: path}).Store(tag, time.Unix(1000, 0), time.Second); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if got := binary.BigEndian.Uint32(data[offset+tagLen : offset+recordLen]); got != 1000 {
		t.Fatalf("expired slot timestamp = %d", got)
	}

	wrapPath := filepath.Join(t.TempDir(), "wrap.rcache2")
	if err := os.WriteFile(wrapPath, seed, 0600); err != nil {
		t.Fatal(err)
	}
	wrapTag := bytes.Repeat([]byte{3}, tagLen)
	wrapIndex := int(sipHash24(wrapTag, seed) % firstTableRecords)
	wrapOffset := int64(hashSeedLen + wrapIndex*recordLen)
	wrapRecord := make([]byte, recordLen)
	copy(wrapRecord, bytes.Repeat([]byte{4}, tagLen))
	binary.BigEndian.PutUint32(wrapRecord[tagLen:], ^uint32(0)-2)
	file, _ = os.OpenFile(wrapPath, os.O_RDWR, 0600)
	_, _ = file.WriteAt(wrapRecord, wrapOffset)
	_ = file.Close()
	if err := (&File2{Path: wrapPath}).Store(wrapTag, time.Unix(1, 0), 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestFile2CollisionGrowsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.rcache2")
	seed := bytes.Repeat([]byte{9}, hashSeedLen)
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	var tags [][]byte
	target := -1
	for i := 0; i < 200000 && len(tags) < 3; i++ {
		tag := make([]byte, tagLen)
		binary.BigEndian.PutUint32(tag[8:], uint32(i))
		index := int(sipHash24(tag, seed) % firstTableRecords)
		if index == firstTableRecords-1 {
			continue
		}
		if target == -1 {
			target = index
		}
		if index == target {
			tags = append(tags, tag)
		}
	}
	if len(tags) != 3 {
		t.Fatal("could not find three colliding tags")
	}
	cache := &File2{Path: path}
	for _, tag := range tags {
		if err := cache.Store(tag, time.Unix(200, 0), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secondTableOffset := hashSeedLen + firstTableRecords*recordLen
	if len(data) <= secondTableOffset {
		t.Fatalf("collision did not grow file: %d bytes", len(data))
	}
	seed2 := append([]byte(nil), seed...)
	seed2[0]++
	secondIndex := int(sipHash24(tags[2], seed2) % ((firstTableRecords + 1) * 2))
	offset := secondTableOffset + secondIndex*recordLen
	if !bytes.Equal(data[offset:offset+tagLen], tags[2]) {
		t.Fatalf("grown-table tag at offset %d = %x, want %x", offset,
			data[offset:offset+tagLen], tags[2])
	}
}

func TestFile2TruncatedRecordIsAvailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.rcache2")
	seed := bytes.Repeat([]byte{4}, hashSeedLen)
	tag := bytes.Repeat([]byte{8}, tagLen)
	index := int(sipHash24(tag, seed) % firstTableRecords)
	offset := hashSeedLen + index*recordLen
	data := append(append([]byte(nil), seed...), make([]byte, offset+5-hashSeedLen)...)
	copy(data[offset:], []byte{1, 2, 3, 4, 5})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&File2{Path: path}).Store(tag, time.Unix(300, 0), time.Minute); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(data[offset+tagLen : offset+recordLen]); got != 300 {
		t.Fatalf("truncated slot timestamp = %d", got)
	}
}

func TestFile2ConcurrentSameTagHasOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.rcache2")
	cache := &File2{Path: path}
	tag := []byte("same-authenticator")
	const workers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cache.Store(tag, time.Unix(100, 0), time.Minute); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			} else if !errors.Is(err, krberrors.ErrReplay) {
				t.Errorf("store: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("successful stores = %d, want 1", winners)
	}
}

func TestResolveReplayCacheNames(t *testing.T) {
	cache, err := Resolve("none:")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Store([]byte("tag"), time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve("unknown:path"); err == nil {
		t.Fatal("unknown replay-cache type accepted")
	}
	t.Setenv("KRB5RCACHEDIR", t.TempDir())
	cache, err = Resolve("dfl:")
	if err != nil {
		t.Fatal(err)
	}
	file2, ok := cache.(*File2)
	if !ok || filepath.Dir(file2.Path) != os.Getenv("KRB5RCACHEDIR") {
		t.Fatalf("default cache = %#v", cache)
	}
}

func TestDefaultReplayCacheUsesTMPDIR(t *testing.T) {
	t.Setenv("KRB5RCACHEDIR", "")
	t.Setenv("TMPDIR", t.TempDir())
	cache, err := Resolve("dfl:")
	if err != nil {
		t.Fatal(err)
	}
	file2, ok := cache.(*File2)
	if !ok || filepath.Dir(file2.Path) != os.Getenv("TMPDIR") {
		t.Fatalf("default cache = %#v", cache)
	}
}

func TestDefaultReplayCacheExpandsMITPathTokens(t *testing.T) {
	previous, present := os.LookupEnv("KRB5RCACHENAME")
	_ = os.Unsetenv("KRB5RCACHENAME")
	t.Cleanup(func() {
		if present {
			_ = os.Setenv("KRB5RCACHENAME", previous)
		} else {
			_ = os.Unsetenv("KRB5RCACHENAME")
		}
	})
	cfg := &config.Config{DefaultRCacheName: "file2:%{TEMP}/krb5_%{euid}_%{uid}_%{USERID}_%{username}%{null}"}
	cache, err := Default(cfg)
	if err != nil {
		t.Fatal(err)
	}
	file2, ok := cache.(*File2)
	if !ok {
		t.Fatalf("default cache = %#v", cache)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(os.TempDir(), "krb5_"+strconv.Itoa(os.Geteuid())+"_"+strconv.Itoa(os.Getuid())+
		"_"+strconv.Itoa(os.Getuid())+"_"+current.Username)
	if file2.Path != want {
		t.Fatalf("expanded cache path = %q, want %q", file2.Path, want)
	}
	cfg.DefaultRCacheName = "file2:%{unknown}"
	if _, err := Default(cfg); err == nil {
		t.Fatal("unknown path token accepted")
	}
}

package ccache

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func testCache() *Cache {
	p := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	return &Cache{DefaultPrincipal: p, Credentials: []Credential{{
		Client: p, Server: p, Key: []byte{1, 2, 3}, Ticket: []byte("ticket"),
	}}}
}

func TestResolveCacheNames(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		typ  Type
	}{
		{filepath.Join(dir, "file.ccache"), TypeFile},
		{"FILE:" + filepath.Join(dir, "file.ccache"), TypeFile},
		{"DIR:" + dir, TypeDir},
		{"MEMORY:unit-test", TypeMemory},
	}
	for _, test := range tests {
		cache, err := Resolve(test.name)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", test.name, err)
		}
		if cache.Type() != test.typ {
			t.Errorf("Resolve(%q) type = %q, want %q", test.name, cache.Type(), test.typ)
		}
	}
	if _, err := Resolve("UNKNOWN:value"); err == nil {
		t.Fatal("unknown cache type unexpectedly resolved")
	}
	if _, err := Resolve("DIR::" + filepath.Join(dir, "not-a-cache")); err == nil {
		t.Fatal("invalid DIR subsidiary unexpectedly resolved")
	}
}

func TestDIRPrimaryAndCollection(t *testing.T) {
	dir := t.TempDir()
	collection, err := Resolve("DIR:" + dir)
	if err != nil {
		t.Fatalf("Resolve DIR: %v", err)
	}
	primary, err := collection.Primary()
	if err != nil {
		t.Fatalf("Primary: %v", err)
	}
	primaryData, err := os.ReadFile(filepath.Join(dir, "primary"))
	if err != nil {
		t.Fatalf("read primary: %v", err)
	}
	if string(primaryData) != "tkt\n" {
		t.Fatalf("primary = %q, want %q", primaryData, "tkt\n")
	}

	if err := primary.Write(testCache()); err != nil {
		t.Fatalf("write primary: %v", err)
	}
	other, err := collection.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if filepath.Base(other.path)[:3] != "tkt" {
		t.Fatalf("new cache path = %q", other.path)
	}
	if err := other.Write(testCache()); err != nil {
		t.Fatalf("write other: %v", err)
	}
	if err := other.SetPrimary(); err != nil {
		t.Fatalf("SetPrimary: %v", err)
	}
	selected, err := collection.Primary()
	if err != nil {
		t.Fatalf("Primary after switch: %v", err)
	}
	if selected.path != other.path {
		t.Fatalf("selected primary = %q, want %q", selected.path, other.path)
	}
	caches, err := collection.Collection()
	if err != nil {
		t.Fatalf("Collection: %v", err)
	}
	if len(caches) != 2 || caches[0].path != other.path {
		t.Fatalf("collection = %#v, want switched primary first and two caches", caches)
	}
	got, err := caches[0].Read()
	if err != nil {
		t.Fatalf("read selected primary: %v", err)
	}
	if got.DefaultPrincipal.Components[0] != "alice" {
		t.Fatalf("selected cache principal = %#v", got.DefaultPrincipal)
	}
}

func TestDIRPrimaryRejectsInvalidContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "primary"), []byte("../outside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve("DIR:" + dir); err == nil {
		t.Fatal("invalid primary unexpectedly accepted")
	}
}

func TestMemoryCacheSharingAndAnonymousNames(t *testing.T) {
	first, err := Resolve("MEMORY:shared")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve("MEMORY:shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Write(testCache()); err != nil {
		t.Fatal(err)
	}
	got, err := second.Read()
	if err != nil || got.DefaultPrincipal.Components[0] != "alice" {
		t.Fatalf("shared cache read = %#v, %v", got, err)
	}
	anonymousA, err := Resolve("MEMORY:")
	if err != nil {
		t.Fatal(err)
	}
	anonymousB, err := Resolve("MEMORY:")
	if err != nil {
		t.Fatal(err)
	}
	if anonymousA.Name() == anonymousB.Name() {
		t.Fatalf("anonymous MEMORY names collide: %q", anonymousA.Name())
	}
}

func TestCacheDestroyFileAndMemory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cache")
	handle, err := Resolve("FILE:" + file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := handle.Destroy(); err != nil {
		t.Fatalf("destroy file cache: %v", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file remains after destroy: %v", err)
	}
	memory, err := Resolve("MEMORY:destroy-test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve("MEMORY:destroy-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Write(testCache()); err != nil {
		t.Fatalf("write memory cache: %v", err)
	}
	if err := memory.Destroy(); err != nil {
		t.Fatalf("destroy memory cache: %v", err)
	}
	if _, err := second.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale memory handle read = %v", err)
	}
	again, err := Resolve("MEMORY:destroy-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destroyed memory cache read = %v", err)
	}
	if err := second.Write(testCache()); err != nil {
		t.Fatalf("recreate memory cache through old handle: %v", err)
	}
	fresh, err := Resolve("MEMORY:destroy-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Read(); err != nil {
		t.Fatalf("fresh memory handle read after recreate = %v", err)
	}
}

func TestMemoryCacheConcurrentSnapshots(t *testing.T) {
	cache, err := Resolve("MEMORY:concurrent")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := testCache()
			value.Credentials[0].Key[0] = byte(i)
			if err := cache.Write(value); err != nil {
				t.Errorf("Write: %v", err)
			}
			if _, err := cache.Read(); err != nil {
				t.Errorf("Read: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if _, err := cache.Read(); err != nil {
		t.Fatalf("final Read: %v", err)
	}
}

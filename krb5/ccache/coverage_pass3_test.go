package ccache

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestCCacheNamedAPIsAndCollectionBoundaries(t *testing.T) {
	name, _ := principal.Parse("alice@EXAMPLE.COM")
	cache := &Cache{DefaultPrincipal: *name}
	cacheName := "MEMORY:coverage-pass3"
	if err := WriteName(cacheName, cache); err != nil {
		t.Fatal(err)
	}
	got, err := ReadName(cacheName)
	if err != nil || got.DefaultPrincipal.String() != name.String() {
		t.Fatalf("named cache = %#v/%v", got, err)
	}
	collection, err := Collection(cacheName)
	if err != nil || len(collection) == 0 {
		t.Fatalf("memory collection = %#v/%v", collection, err)
	}
	for _, handle := range collection {
		if err := handle.Close(); err != nil {
			t.Fatalf("close collection handle: %v", err)
		}
	}
	if _, err := Resolve(""); err == nil {
		t.Fatal("empty cache name accepted")
	}
	if _, err := Resolve("UNKNOWN:cache"); err == nil {
		t.Fatal("unknown cache type accepted")
	}
	if _, err := Resolve("FILE:"); err == nil {
		t.Fatal("empty file cache accepted")
	}
	if _, err := (&Handle{}).Read(); err == nil {
		t.Fatal("zero handle read succeeded")
	}
	if err := (*Handle)(nil).Write(cache); err == nil {
		t.Fatal("nil handle write succeeded")
	}
}

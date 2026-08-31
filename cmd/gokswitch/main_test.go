package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestParseSwitchArgs(t *testing.T) {
	if _, err := parseSwitchArgs(nil); err == nil {
		t.Fatal("empty options accepted")
	}
	if _, err := parseSwitchArgs([]string{"-c", "FILE:x", "-p", "alice@TEST"}); err == nil {
		t.Fatal("multiple selectors accepted")
	}
	options, err := parseSwitchArgs([]string{"-p", "alice@TEST"})
	if err != nil || options.Principal != "alice@TEST" {
		t.Fatalf("options = %#v, err = %v", options, err)
	}
}

func TestSwitchSelectsPrincipalAndMakesPrimary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "collection")
	collection, err := ccache.Resolve("DIR:" + dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		cache, err := collection.New()
		if err != nil {
			t.Fatal(err)
		}
		p := principal.Principal{Realm: "TEST", Components: []string{name}}
		if err := cache.Write(&ccache.Cache{DefaultPrincipal: p}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KRB5CCNAME", "DIR:"+dir)
	if err := runSwitch([]string{"-p", "bob@TEST"}, os.Stderr); err != nil {
		t.Fatal(err)
	}
	primary, err := collection.Primary()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := primary.Read()
	if err != nil {
		t.Fatal(err)
	}
	if cache.DefaultPrincipal.String() != "bob@TEST" {
		t.Fatalf("primary = %s, want bob@TEST", cache.DefaultPrincipal)
	}
}

func TestSwitchRejectsUnsupportedCacheType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache")
	if err := os.WriteFile(path, []byte("not a cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runSwitch([]string{"-c", path}, os.Stderr); err == nil {
		t.Fatal("FILE cache switching unexpectedly succeeded")
	}
}

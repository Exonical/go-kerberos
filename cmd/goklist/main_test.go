package main

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestKlistFormatting(t *testing.T) {
	value := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := formatKlistTime(value); got != "01/02/25 03:04:05" {
		t.Fatalf("formatted time = %q", got)
	}
	for _, test := range []struct {
		id   int32
		name string
	}{
		{17, "aes128-cts-hmac-sha1-96"},
		{18, "aes256-cts-hmac-sha1-96"},
		{19, "aes128-cts-hmac-sha256-128"},
		{20, "aes256-cts-hmac-sha384-192"},
	} {
		if got := enctypeName(test.id); got != test.name {
			t.Fatalf("enctype %d name = %q", test.id, got)
		}
	}
}

func TestParseListArgs(t *testing.T) {
	options, err := parseListArgs([]string{"-e", "-c", "cache", "-k", "keytab"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.ShowEtypes || options.CachePath != "cache" || options.KeytabPath != "keytab" {
		t.Fatalf("options = %#v", options)
	}
	if _, err := parseListArgs([]string{"-c"}); err == nil {
		t.Fatal("missing cache path accepted")
	}
	if _, err := parseListArgs([]string{"unexpected"}); err == nil {
		t.Fatal("unexpected argument accepted")
	}
	if got := resolveListCachePath("FILE:/tmp/cache", 42); got != "/tmp/cache" {
		t.Fatalf("cache path = %q", got)
	}
}

func TestListCacheSkipsConfigurationCredentials(t *testing.T) {
	client, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse("host/server@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	configEntry, err := principal.Parse("X-CACHECONF:/krb5_ccache_conf_data/fast_avail@X-CACHECONF:")
	if err != nil {
		t.Fatal(err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: *client,
		Credentials: []ccache.Credential{
			{Client: *client, Server: *service, Enctype: 18, StartTime: 1, EndTime: 2},
			{Client: *client, Server: *configEntry, Enctype: 18},
		},
	}
	file, err := os.CreateTemp(t.TempDir(), "cache")
	if err != nil {
		t.Fatal(err)
	}
	if err := ccache.Write(file, cache); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := listCache(file.Name(), false, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("host/server@EXAMPLE.COM")) {
		t.Fatalf("ticket missing:\n%s", output.String())
	}
	if bytes.Contains(output.Bytes(), []byte("X-CACHECONF:")) {
		t.Fatalf("configuration credential listed:\n%s", output.String())
	}
}

package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoklistRunAndFormattingErrors(t *testing.T) {
	if err := runList([]string{"-c", t.TempDir() + "/missing"}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing cache accepted")
	}
	client, _ := principal.Parse("alice@EXAMPLE.COM")
	service, _ := principal.Parse("host/server@EXAMPLE.COM")
	cache := &ccache.Cache{DefaultPrincipal: *client, Credentials: []ccache.Credential{
		{Client: *client, Server: *service, Enctype: 18, StartTime: 1, EndTime: 2},
	}}
	path := t.TempDir() + "/cache"
	file, err := os.Create(path)
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
	if err := runList([]string{"-e", "-c", "FILE:" + path}, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("Etype (skey): aes256")) {
		t.Fatalf("list output = %s", output.String())
	}
}

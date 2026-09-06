package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/iprop"
)

func TestSummaryAndVerboseOutput(t *testing.T) {
	dir := t.TempDir()
	ulogPath := filepath.Join(dir, "principal.ulog")
	log, err := iprop.Create(ulogPath, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.AddUpdate(iprop.Update{PrincipalName: "alice@EXAMPLE.COM", EntrySno: 1, Time: iprop.Time{Seconds: 10}, Commit: true}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "kdc.conf")
	if err := os.WriteFile(conf, []byte("[realms]\n EXAMPLE.COM = {\n  iprop_logfile = "+ulogPath+"\n }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5_KDC_PROFILE", conf)
	t.Setenv("KRB5_REALM", "EXAMPLE.COM")
	var out bytes.Buffer
	if err := run([]string{"-v", "-e", "1"}, &out, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Kerberos update log (" + ulogPath + ")", "Log version # : 1", "Update Entry", "Update principal : alice@EXAMPLE.COM"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

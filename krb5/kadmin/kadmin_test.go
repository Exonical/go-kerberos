package kadmin

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestParseCommandAndDates(t *testing.T) {
	args, err := splitCommand(`addprinc -pw "secret value" +requires_preauth user`)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 5 || args[2] != "secret value" {
		t.Fatalf("split command = %#v", args)
	}
	loc := time.FixedZone("TEST", -5*60*60)
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, loc)
	date, err := ParseDate("2025-02-03 04:05:06", now, loc)
	if err != nil || date.Location() != loc {
		t.Fatalf("date = %v, err = %v", date, err)
	}
	if got, err := ParseInterval("2d 03:04:05", now, loc); err != nil || got != 51*time.Hour+4*time.Minute+5*time.Second {
		t.Fatalf("interval = %v, err = %v", got, err)
	}
	if got, err := ParseDate("never", now, loc); err != nil || !got.IsZero() {
		t.Fatalf("never = %v, err = %v", got, err)
	}
}

func TestFlagspecAndDefaultPolicy(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "default"}); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	engine := New(Config{
		Ops:    NewLocal(db),
		Local:  true,
		Realm:  "EXAMPLE.COM",
		Now:    func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) },
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &stderr,
	})
	if _, err := engine.Execute(`addprinc -pw secret +requires_preauth user`); err != nil {
		t.Fatal(err)
	}
	p, err := principal.Parse("user@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	entry, ok, err := db.Lookup(*p)
	if err != nil || !ok {
		t.Fatalf("lookup: %v %v", ok, err)
	}
	if entry.Flags&kdb.RequiresPreAuth == 0 || entry.Policy != "default" {
		t.Fatalf("entry flags/policy = %#x/%q", entry.Flags, entry.Policy)
	}
	if !strings.Contains(stderr.String(), `assigning "default"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPrincipalOutputGolden(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	p, _ := principal.Parse("user@EXAMPLE.COM")
	record := kdb.PrincipalRecord{
		Name: *p, KVNO: 2, MaxLife: time.Hour,
		MaxRenew: 2 * time.Hour, Flags: kdb.RequiresPreAuth,
	}
	if err := db.ImportPrincipal(record); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	engine := New(Config{
		Ops: NewLocal(db), Realm: "EXAMPLE.COM", Stdout: &out,
		Stderr: &bytes.Buffer{}, Now: func() time.Time { return time.Unix(0, 0) },
		Location: time.UTC,
	})
	if _, err := engine.Execute("getprinc user"); err != nil {
		t.Fatal(err)
	}
	want := "Principal: user@EXAMPLE.COM\n" +
		"Expiration date: [never]\n" +
		"Last password change: [never]\n" +
		"Password expiration date: [never]\n" +
		"Maximum ticket life: 0 days 01:00:00\n" +
		"Maximum renewable life: 0 days 02:00:00\n" +
		"Last modified: [never] ()\n" +
		"Last successful authentication: [never]\n" +
		"Last failed authentication: [never]\n" +
		"Failed password attempts: 0\n" +
		"Number of keys: 0\n" +
		"MKey: vno 0\n" +
		"Attributes: REQUIRES_PRE_AUTH\n" +
		"Policy: [none]\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestConfirmationAndScriptMode(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.CreatePrincipal("user", "secret"); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	engine := New(Config{Ops: NewLocal(db), Realm: "EXAMPLE.COM", Stdin: strings.NewReader("no\n"), Stdout: &out, Stderr: &errOut})
	if _, err := engine.Execute("delprinc user"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "not deleted") {
		t.Fatalf("confirmation output = %q", errOut.String())
	}
	engine = New(Config{Ops: NewLocal(db), Realm: "EXAMPLE.COM", Script: true, Stdout: &out, Stderr: &errOut})
	if _, err := engine.Execute("unknown"); err == nil {
		t.Fatal("unknown command succeeded")
	}
}

func TestKTAddWritesReadableKeytab(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.CreatePrincipal("user", "secret"); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/test.keytab"
	var out bytes.Buffer
	engine := New(Config{Ops: NewLocal(db), Local: true, Realm: "EXAMPLE.COM", Stdout: &out, Stderr: &bytes.Buffer{}})
	if _, err := engine.Execute("ktadd -k " + path + " -norandkey user"); err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := kt.EntriesSnapshot()
	if len(entries) == 0 || entries[0].Principal.String() != "user@EXAMPLE.COM" {
		t.Fatalf("keytab entries = %#v", entries)
	}
}

func TestParseStartupModes(t *testing.T) {
	opts, err := ParseStartup([]string{"-r", "EXAMPLE.COM", "-q", "getprinc user"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Realm != "EXAMPLE.COM" || opts.Query != "getprinc user" {
		t.Fatalf("startup = %#v", opts)
	}
	if _, err := ParseStartup([]string{"-c", "FILE:/tmp/a", "-k"}, false); err == nil {
		t.Fatal("expected mutually exclusive startup options")
	}
	if _, err := ParseStartup([]string{"-t", "/tmp/a"}, false); err == nil {
		t.Fatal("expected -t validation")
	}
	if _, err := ParseStartup([]string{"-n"}, false); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unsupported option error = %v", err)
	}
}

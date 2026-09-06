package klog

import (
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
)

func TestParseSpecs(t *testing.T) {
	specs, err := ParseSpecs([]string{"FILE=/tmp/one FILE:/tmp/two", "SYSLOG:INFO:LOCAL3 STDERR"})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 4 || specs[0].Kind != File || specs[1].Kind != File ||
		specs[2].Facility != syslog.LOG_LOCAL3 || specs[3].Kind != Stderr {
		t.Fatalf("specs = %#v", specs)
	}
}

func TestLoggerLineFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "klog")
	logger, err := New([]string{"FILE=" + path}, "krb5kdc")
	if err != nil {
		t.Fatal(err)
	}
	logger.Hostname = "host.example"
	logger.PID = 42
	logger.Now = func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) }
	logger.Info("message %s", "value")
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "Jan 02 03:04:05 host.example krb5kdc[42](info): message value\n"
	if string(data) != want {
		t.Fatalf("line = %q, want %q", data, want)
	}
}

func TestFileAppendDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "klog")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger, err := New([]string{"FILE:" + path}, "krb5kdc")
	if err != nil {
		t.Fatal(err)
	}
	logger.Hostname = "host"
	logger.PID = 1
	logger.Now = func() time.Time { return time.Unix(0, 0).UTC() }
	logger.Info("new")
	_ = logger.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "old\n") || !strings.HasSuffix(string(data), "new\n") {
		t.Fatalf("append output = %q", data)
	}
}

func TestNewFromConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`[logging]
 default = STDERR
 kdc = FILE=/tmp/kdc
`))
	if err != nil {
		t.Fatal(err)
	}
	logger, err := NewFromConfig(cfg, "kdc", "kdc")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	if len(logger.destinations) != 1 || logger.destinations[0].spec.Kind != File ||
		!strings.HasSuffix(logger.destinations[0].spec.Path, "/kdc") {
		t.Fatalf("destinations = %#v", logger.destinations)
	}
}

package trace

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestFileCallbackFormat(t *testing.T) {
	previous := now
	now = func() time.Time { return time.Unix(1700000000, 123456000).UTC() }
	defer func() { now = previous }()

	var output bytes.Buffer
	FileCallback(&output)("message")
	want := "["
	if !strings.HasPrefix(output.String(), want) ||
		!strings.HasSuffix(output.String(), "] 1700000000.123456: message\n") {
		t.Fatalf("trace output = %q", output.String())
	}
}

func TestFromEnv(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		t.Setenv("KRB5_TRACE", "")
		callback, err := FromEnv()
		if err != nil || callback != nil {
			t.Fatalf("FromEnv = %v, %v", callback, err)
		}
	})
	t.Run("shared path", func(t *testing.T) {
		file, err := os.CreateTemp("", "go-kerberos-trace-shared-*")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			defer os.Remove(path)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		fileCallbacks.Lock()
		before := len(fileCallbacks.values)
		fileCallbacks.Unlock()
		t.Setenv("KRB5_TRACE", path)
		first, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		fileCallbacks.Lock()
		afterFirst := len(fileCallbacks.values)
		fileCallbacks.Unlock()
		second, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		fileCallbacks.Lock()
		afterSecond := len(fileCallbacks.values)
		fileCallbacks.Unlock()
		if afterFirst != before+1 || afterSecond != afterFirst {
			t.Fatalf("cached callbacks = %d, want one new callback", afterSecond)
		}
		first("first")
		second("second")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), "\n") != 2 ||
			!strings.Contains(string(data), ": first\n") ||
			!strings.Contains(string(data), ": second\n") {
			t.Fatalf("shared trace file = %q", data)
		}
	})
	t.Run("file", func(t *testing.T) {
		file, err := os.CreateTemp("", "go-kerberos-trace-*")
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			defer os.Remove(path)
		}
		t.Setenv("KRB5_TRACE", path)
		callback, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		callback("hello")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(data), ": hello\n") {
			t.Fatalf("trace file = %q", data)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("trace mode = %o", info.Mode().Perm())
		}
	})
	t.Run("error", func(t *testing.T) {
		path := t.TempDir()
		t.Setenv("KRB5_TRACE", path)
		if callback, err := FromEnv(); err == nil || callback != nil {
			t.Fatalf("FromEnv = %v, %v", callback, err)
		}
	})
}

func TestFormatHelpers(t *testing.T) {
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "kdc"}}
	if got := Principal(name); got != "host/kdc@EXAMPLE.COM" {
		t.Fatalf("principal = %q", got)
	}
	if got := PadataType(2); got != "PA-ENC-TIMESTAMP" {
		t.Fatalf("padata = %q", got)
	}
	if got := PadataType(999); got != "PA-999" {
		t.Fatalf("unknown padata = %q", got)
	}
	if got := RemoteAddress("tcp", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 88}); got != "stream 192.0.2.1:88" {
		t.Fatalf("remote address = %q", got)
	}
}

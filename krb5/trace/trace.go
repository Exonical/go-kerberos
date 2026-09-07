// Package trace provides MIT-compatible Kerberos protocol tracing.
package trace

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// Callback receives one formatted trace message without the file prefix.
type Callback func(message string)

var (
	now           = time.Now
	fileCallbacks = struct {
		sync.Mutex
		values map[string]Callback
	}{values: make(map[string]Callback)}
	padataNames = map[int32]string{
		1:   "PA-TGS-REQ",
		2:   "PA-ENC-TIMESTAMP",
		3:   "PA-PW-SALT",
		5:   "PA-ENC-UNIX-TIME",
		6:   "PA-SANDIA-SECUREID",
		7:   "PA-SESAME",
		8:   "PA-OSF-DCE",
		9:   "PA-CYBERSAFE-SECUREID",
		10:  "PA-AFS3-SALT",
		11:  "PA-ETYPE-INFO",
		12:  "PA-SAM-CHALLENGE",
		13:  "PA-SAM-RESPONSE",
		14:  "PA-PK-AS-REQ_OLD",
		15:  "PA-PK-AS-REP_OLD",
		16:  "PA-PK-AS-REQ",
		17:  "PA-PK-AS-REP",
		19:  "PA-ETYPE-INFO2",
		20:  "PA-SVR-REFERRAL-INFO",
		21:  "PA-SAM-REDIRECT",
		22:  "PA-GET-FROM-TYPED-DATA",
		30:  "PA-SAM-CHALLENGE2",
		31:  "PA-SAM-RESPONSE2",
		128: "PA-PAC-REQUEST",
		129: "PA-FOR_USER",
		130: "PA-FOR-X509-USER",
		132: "PA-AS-CHECKSUM",
		133: "PA-FX-COOKIE",
		136: "PA-FX-FAST",
		137: "PA-FX-ERROR",
		138: "PA-ENCRYPTED-CHALLENGE",
		141: "PA-OTP-CHALLENGE",
		142: "PA-OTP-REQUEST",
		144: "PA-OTP-PIN-CHANGE",
		147: "PA-PKINIT-KX",
		149: "PA-REQ-ENC-PA-REP",
		150: "PA-AS-FRESHNESS",
		151: "PA-SPAKE",
	}
)

// FileCallback returns a callback using MIT's KRB5_TRACE file format.
func FileCallback(w io.Writer) Callback {
	var mu sync.Mutex
	pid := os.Getpid()
	return func(message string) {
		t := now()
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintf(w, "[%d] %d.%06d: %s\n", pid,
			t.Unix(), t.Nanosecond()/int(time.Microsecond), message)
	}
}

// FromEnv opens the file named by KRB5_TRACE and returns a file callback.
// The file is opened once per path and shared process-wide; it remains open
// for the process lifetime.
func FromEnv() (Callback, error) {
	path := os.Getenv("KRB5_TRACE")
	if path == "" {
		return nil, nil
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fileCallbacks.Lock()
	defer fileCallbacks.Unlock()
	if callback, ok := fileCallbacks.values[path]; ok {
		return callback, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	callback := FileCallback(file)
	fileCallbacks.values[path] = callback
	return callback, nil
}

// Principal renders a principal in MIT's unparsed form.
func Principal(value principal.Principal) string {
	return value.String()
}

// Enctype renders an encryption type using its MIT name.
func Enctype(id int32) string {
	return crypto.EnctypeName(id)
}

// PadataType renders a preauthentication type using MIT's trace name.
func PadataType(id int32) string {
	if name, ok := padataNames[id]; ok {
		return name
	}
	return fmt.Sprintf("PA-%d", id)
}

// RemoteAddress renders a network address in MIT's trace form.
func RemoteAddress(network string, address net.Addr) string {
	prefix := "transport"
	switch {
	case strings.HasPrefix(strings.ToLower(network), "udp"):
		prefix = "dgram"
	case strings.HasPrefix(strings.ToLower(network), "tcp"):
		prefix = "stream"
	case strings.HasPrefix(strings.ToLower(network), "unix"):
		prefix = "UNIX domain socket"
	case strings.HasPrefix(strings.ToLower(network), "http"):
		prefix = "https"
	}
	if address == nil {
		return prefix
	}
	return prefix + " " + address.String()
}

package otp

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/krad"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestDecodeTokenTypesDefaultsAndSecret(t *testing.T) {
	dir := t.TempDir()
	previous := SecretDir
	SecretDir = dir
	t.Cleanup(func() { SecretDir = previous })
	if err := os.WriteFile(filepath.Join(dir, "radius.secret"), []byte(" shared-secret \nignored"), 0600); err != nil {
		t.Fatal(err)
	}
	profile, err := config.Parse([]byte(`[otp]
DEFAULT = {
 server = /tmp/radius.sock
 timeout = 7
 retries = 2
 strip_realm = false
 indicator = radius
}

remote = {
 server = /tmp/radius.sock
 secret = radius.secret
}`))
	if err != nil {
		t.Fatal(err)
	}
	types, err := DecodeTokenTypes(profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[0].Name != "DEFAULT" {
		t.Fatalf("types = %#v", types)
	}
	if types[0].Timeout != 7*time.Second || types[0].StripRealm ||
		len(types[0].Indicators) != 1 {
		t.Fatalf("default type = %#v", types[0])
	}
	if types[1].Secret != "shared-secret" {
		t.Fatalf("secret = %q", types[1].Secret)
	}
}

func TestRADIUSVerifierUnixAccept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-domain RADIUS sockets are unavailable on Windows")
	}
	path := filepath.Join(t.TempDir(), "radius.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		wire, readErr := krad.ReadPacket(conn)
		if readErr != nil {
			return
		}
		request, decodeErr := krad.DecodeRequest(wire)
		if decodeErr != nil {
			return
		}
		code := krad.AccessReject
		if string(request.Attributes.Get(krad.UserName, 0)) == "alice" &&
			string(request.Attributes.Get(krad.UserPassword, 0)) == "accept" {
			code = krad.AccessAccept
		}
		response, responseErr := krad.NewResponse(code, request, krad.NewAttributes())
		if responseErr == nil {
			responseWire, responseErr := response.Bytes()
			if responseErr == nil {
				_, _ = conn.Write(responseWire)
			}
		}
	}()
	verifier := &RADIUSVerifier{
		Types: []TokenType{{Name: "DEFAULT", Server: path, Timeout: time.Second, Retries: 0, StripRealm: true}},
	}
	client := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	indicators, err := verifier.Verify(client, "", []byte("accept"))
	if err != nil {
		t.Fatal(err)
	}
	if len(indicators) != 0 {
		t.Fatalf("indicators = %#v", indicators)
	}
}

func TestDecodeTokens(t *testing.T) {
	user := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	types := []TokenType{{Name: "DEFAULT", StripRealm: true, Indicators: []string{"otp"}}}
	tokens, err := decodeTokens(user, `[{"username":"remote","indicators":["radius"]}]`, types)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Username != "remote" || tokens[0].Indicators == nil ||
		len(*tokens[0].Indicators) != 1 {
		t.Fatalf("tokens = %#v", tokens)
	}
	tokens, err = decodeTokens(user, `[{}]`, types)
	if err != nil || tokens[0].Username != "alice" {
		t.Fatalf("default token = %#v, %v", tokens, err)
	}
}

func TestDecodeTokensIndicatorsPresence(t *testing.T) {
	user := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	types := []TokenType{{Name: "DEFAULT", StripRealm: true, Indicators: []string{"otp"}}}
	tokens, err := decodeTokens(user, `[{}]`, types)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Indicators != nil {
		t.Fatal("absent indicators unexpectedly became present")
	}
	tokens, err = decodeTokens(user, `[{"indicators":[]}]`, types)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Indicators == nil || len(*tokens[0].Indicators) != 0 {
		t.Fatalf("empty indicators = %#v", tokens[0].Indicators)
	}
}

func TestDecodeTokenTypesCaseSensitiveDefault(t *testing.T) {
	profile, err := config.Parse([]byte(`[otp]
default = {
 server = /tmp/lower.sock
}`))
	if err != nil {
		t.Fatal(err)
	}
	types, err := DecodeTokenTypes(profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 2 || types[0].Name != "DEFAULT" || types[1].Name != "default" {
		t.Fatalf("types = %#v", types)
	}
}

func TestRADIUSVerifierAbortsOnTransportError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-domain RADIUS sockets are unavailable on Windows")
	}
	dir := os.TempDir()
	first := filepath.Join(dir, fmt.Sprintf("gk-radius-%d-a", os.Getpid()))
	second := filepath.Join(dir, fmt.Sprintf("gk-radius-%d-b", os.Getpid()))
	t.Cleanup(func() {
		_ = os.Remove(first)
		_ = os.Remove(second)
	})
	listener, err := net.Listen("unix", second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reached := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		reached <- struct{}{}
		_ = conn.Close()
	}()

	verifier := &RADIUSVerifier{Types: []TokenType{
		{Name: "first", Server: first, Timeout: time.Millisecond, Retries: 0},
		{Name: "second", Server: second, Timeout: time.Second, Retries: 0},
	}}
	client := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	if _, err := verifier.Verify(client, `[{"type":"first"},{"type":"second"}]`, []byte("accept")); err == nil {
		t.Fatal("transport error unexpectedly fell through to the next token")
	}
	select {
	case <-reached:
		t.Fatal("second token was attempted after transport failure")
	default:
	}
}

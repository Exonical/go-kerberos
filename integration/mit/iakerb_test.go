//go:build integration

package mit_test

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var errPythonIAKERBSkipped = errors.New("Python MIT IAKERB unavailable")

func TestMITIAKERBInitiatorAgainstGo(t *testing.T) {
	python := requirePythonGSSAPI(t)
	k := startGoKDC(t)
	configData, err := os.ReadFile(k.config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{
		Realm: goKDCRealm, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	record, ok, err := k.db.Lookup(service)
	if err != nil || !ok {
		t.Fatalf("lookup service key: %v, %v", err, ok)
	}
	entries := make([]keytab.Entry, 0, len(record.Keys))
	for _, value := range record.Keys {
		entries = append(entries, keytab.Entry{
			Principal: service, KVNO: value.KVNO, Enctype: value.Enctype,
			Key: append([]byte(nil), value.Key...),
		})
	}
	acceptor, err := gssapi.NewIAKERBAcceptor(
		&keytab.Keytab{Entries: entries},
		&client.Client{Config: cfg},
		goKDCRealm,
	)
	if err != nil {
		t.Fatal(err)
	}
	peer := startPythonIAKERBPeer(t, python, k.config, goKDCRealm)
	defer peer.close()
	now := time.Now().UTC()
	token, more, err := peer.initial()
	if err != nil {
		if errors.Is(err, errPythonIAKERBSkipped) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if !more || len(token) == 0 {
		t.Fatalf("MIT IAKERB initiator produced no initial token")
	}
	var ctx *gssapi.Context
	for step := 0; step < 16 && len(token) != 0; step++ {
		nextContext, reply, err := acceptor.Accept(token, now)
		if err != nil {
			t.Fatalf("Go IAKERB acceptor step %d: %v", step, err)
		}
		if nextContext != nil {
			ctx = nextContext
		}
		token, more, err = peer.step(reply)
		if err != nil {
			if errors.Is(err, errPythonIAKERBSkipped) {
				t.Skip(err)
			}
			t.Fatal(err)
		}
		if !more && len(token) == 0 {
			break
		}
	}
	if ctx == nil {
		t.Fatal("Go IAKERB acceptor did not establish a context")
	}
	if more || len(token) != 0 {
		t.Fatal("MIT IAKERB initiator did not finish")
	}
	wrapped, err := peer.wrap([]byte("MIT IAKERB initiator"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ctx.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Go IAKERB unwrap: %v", err)
	}
	if string(plain) != "MIT IAKERB initiator" {
		t.Fatalf("Go IAKERB unwrap = %q", plain)
	}
}

type pythonIAKERBPeer struct {
	cmd    *exec.Cmd
	in     *bufio.Writer
	out    *bufio.Scanner
	closed bool
}

func startPythonIAKERBPeer(t *testing.T, python, config, realm string) *pythonIAKERBPeer {
	t.Helper()
	script := filepath.Join(t.TempDir(), "iakerb_peer.py")
	writeIntegrationFile(t, script, pythonIAKERBScript)
	cmd := exec.Command(python, script, config, realm)
	cmd.Env = append(os.Environ(), "KRB5_CONFIG="+config, "KRB5_TRACE=/dev/stderr")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return &pythonIAKERBPeer{cmd: cmd, in: bufio.NewWriter(stdin), out: bufio.NewScanner(stdout)}
}

func (p *pythonIAKERBPeer) initial() ([]byte, bool, error) {
	return p.read("initial\n")
}

func (p *pythonIAKERBPeer) step(token []byte) ([]byte, bool, error) {
	return p.read("step " + base64.StdEncoding.EncodeToString(token) + "\n")
}

func (p *pythonIAKERBPeer) read(command string) ([]byte, bool, error) {
	if _, err := p.in.WriteString(command); err != nil {
		return nil, false, err
	}
	if err := p.in.Flush(); err != nil {
		return nil, false, err
	}
	if !p.out.Scan() {
		return nil, false, fmt.Errorf("Python IAKERB peer exited: %v", p.cmd.Wait())
	}
	if strings.HasPrefix(p.out.Text(), "skip ") {
		return nil, false, fmt.Errorf("%w: %s", errPythonIAKERBSkipped, strings.TrimPrefix(p.out.Text(), "skip "))
	}
	token, err := decodePeerLine(p.out.Text(), "token ")
	if err != nil {
		return nil, false, err
	}
	if !p.out.Scan() {
		return nil, false, fmt.Errorf("Python IAKERB peer exited before state: %v", p.cmd.Wait())
	}
	state := strings.TrimSpace(p.out.Text())
	if state != "more" && state != "done" {
		return nil, false, fmt.Errorf("unexpected Python IAKERB state %q", state)
	}
	return token, state == "more", nil
}

func (p *pythonIAKERBPeer) wrap(value []byte) ([]byte, error) {
	if _, err := p.in.WriteString("wrap " + base64.StdEncoding.EncodeToString(value) + "\n"); err != nil {
		return nil, err
	}
	if err := p.in.Flush(); err != nil {
		return nil, err
	}
	if !p.out.Scan() {
		return nil, fmt.Errorf("Python IAKERB peer exited: %v", p.cmd.Wait())
	}
	return decodePeerLine(p.out.Text(), "wrapped ")
}

func (p *pythonIAKERBPeer) close() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

const pythonIAKERBScript = `import base64, sys
import gssapi
from gssapi import raw
from gssapi.raw.oids import OID

config, realm = sys.argv[1:]
iakerb = OID.from_int_seq((1, 3, 6, 1, 5, 2, 5))
name = gssapi.Name("alice@" + realm, name_type=gssapi.NameType.kerberos_principal)
target = gssapi.Name("host/service.test@" + realm,
                     name_type=gssapi.NameType.kerberos_principal)
try:
    acquired = raw.acquire_cred_with_password(name, b"alice-password", mechs=[iakerb])
    creds = gssapi.Credentials(base=acquired.creds)
    ctx = gssapi.SecurityContext(name=target, creds=creds, mech=iakerb,
                                 usage="initiate",
                                 flags=[gssapi.RequirementFlag.mutual_authentication,
                                        gssapi.RequirementFlag.integrity,
                                        gssapi.RequirementFlag.confidentiality])
except Exception as err:
    if "Message size is incompatible with encryption type" in str(err):
        print("skip MIT runtime lacks current IAKERB implementation", flush=True)
        sys.exit(0)
    raise

def emit(token, more):
    print("token " + base64.b64encode(token or b"").decode("ascii"), flush=True)
    print("more" if more else "done", flush=True)

for line in sys.stdin:
    parts = line.rstrip("\n").split(" ", 1)
    try:
        if parts[0] == "initial":
            token = ctx.step(None)
            print("token " + base64.b64encode(token or b"").decode("ascii"), flush=True)
            print("more" if not ctx.complete else "done", flush=True)
        elif parts[0] == "step":
            value = base64.b64decode(parts[1])
            token = ctx.step(value)
            print("token " + base64.b64encode(token or b"").decode("ascii"), flush=True)
            print("more" if not ctx.complete else "done", flush=True)
        elif parts[0] == "wrap":
            value = base64.b64decode(parts[1])
            print("wrapped " + base64.b64encode(ctx.wrap(value, encrypt=True).message).decode("ascii"), flush=True)
        else:
            raise RuntimeError("unknown command")
    except Exception as err:
        if "Message size is incompatible with encryption type" in str(err):
            print("skip MIT runtime lacks current IAKERB implementation", flush=True)
            sys.exit(0)
        raise
`

//go:build integration

package mit_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/spnego"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestGoSPNEGOInitiatorAgainstMIT(t *testing.T) {
	python := requirePythonGSSAPI(t)
	realm := testenv.Start(t)
	cfgData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(cfgData)
	if err != nil {
		t.Fatal(err)
	}
	kclient := &client.Client{Config: cfg}
	tgt, err := kclient.ASExchange(t.Context(), principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service, err := kclient.TGSExchange(t.Context(), tgt, principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := spnego.NewInitiator(service, gssapi.GSSMutualFlag|gssapi.GSSIntegrityFlag|gssapi.GSSConfidentialityFlag)
	if err != nil {
		t.Fatal(err)
	}
	peer := startPythonSPNEGOPeer(t, python, realm, "accept")
	defer peer.close()
	first, err := initiator.InitialToken(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reply, err := peer.step(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Continue(reply); err != nil {
		t.Fatal(err)
	}
	ctx, err := initiator.Context()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ctx.Wrap([]byte("Go SPNEGO initiator"), true)
	if err != nil {
		t.Fatal(err)
	}
	plain, peerReply, err := peer.wrap(wire)
	if err != nil || string(plain) != "Go SPNEGO initiator" {
		t.Fatalf("MIT SPNEGO peer unwrap = %q, err %v", plain, err)
	}
	got, err := ctx.Unwrap(peerReply)
	if err != nil || string(got) != "MIT SPNEGO acceptor" {
		t.Fatalf("Go SPNEGO unwrap = %q, err %v", got, err)
	}
}

func TestMITSPNEGOInitiatorAgainstGo(t *testing.T) {
	python := requirePythonGSSAPI(t)
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	file, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Read(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	acceptor := spnego.NewAcceptor(kt)
	peer := startPythonSPNEGOPeer(t, python, realm, "initiate")
	defer peer.close()
	first, err := peer.initial()
	if err != nil {
		t.Fatal(err)
	}
	ctx, reply, err := acceptor.Accept(first, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.step(reply); err != nil {
		t.Fatal(err)
	}
	wire, err := peer.wrapMessage([]byte("MIT SPNEGO initiator"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ctx.Unwrap(wire)
	if err != nil || string(got) != "MIT SPNEGO initiator" {
		t.Fatalf("Go SPNEGO acceptor unwrap = %q, err %v", got, err)
	}
	replyWire, err := ctx.Wrap([]byte("Go SPNEGO acceptor"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.unwrap(replyWire); err != nil {
		t.Fatal(err)
	}
}

func TestMITGSSDelegationAgainstGo(t *testing.T) {
	python := requirePythonGSSAPI(t)
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	file, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Read(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	peer := startPythonSPNEGOPeer(t, python, realm, "delegate")
	defer peer.close()
	first, err := peer.initial()
	if err != nil {
		t.Fatal(err)
	}
	ctx, reply, err := gssapi.NewAcceptor(kt).Accept(first, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 0 {
		t.Fatal("unexpected AP-REP for non-mutual delegation exchange")
	}
	if ctx.Flags()&gssapi.GSS_C_DELEG_FLAG == 0 || len(ctx.DelegatedCredentials) != 1 {
		t.Fatalf("delegation result flags=%#x credentials=%d", ctx.Flags(), len(ctx.DelegatedCredentials))
	}
	delegated := ctx.DelegatedCredentials[0]
	if delegated.Flags&types.TicketForwarded == 0 ||
		len(delegated.Server.Components) != 2 ||
		delegated.Server.Components[0] != "krbtgt" {
		t.Fatalf("delegated credential = %#v", delegated)
	}
	cfgData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(cfgData)
	if err != nil {
		t.Fatal(err)
	}
	kclient := &client.Client{Config: cfg}
	_, err = kclient.TGSExchange(t.Context(), delegated, principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	})
	if err != nil {
		t.Fatalf("delegated TGT unusable: %v", err)
	}
}

type pythonPeer struct {
	cmd    *exec.Cmd
	in     *bufio.Writer
	out    *bufio.Scanner
	closed bool
}

func startPythonSPNEGOPeer(t *testing.T, python string, realm *testenv.Realm, mode string) *pythonPeer {
	t.Helper()
	script := filepath.Join(realm.Dir, "spnego_peer.py")
	writeIntegrationFile(t, script, pythonSPNEGOScript)
	cmd := exec.Command(python, script, mode, realm.Config, realm.Cache, realm.Keytab, testenv.RealmName)
	env := append(os.Environ(),
		"KRB5_CONFIG="+realm.Config,
		"KRB5CCNAME=FILE:"+realm.Cache,
		"KRB5_KTNAME=FILE:"+realm.Keytab,
	)
	cmd.Env = env
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
	return &pythonPeer{cmd: cmd, in: bufio.NewWriter(stdin), out: bufio.NewScanner(stdout)}
}

func (p *pythonPeer) initial() ([]byte, error) {
	return p.read("")
}

func (p *pythonPeer) step(token []byte) ([]byte, error) {
	return p.read("step " + base64.StdEncoding.EncodeToString(token))
}

func (p *pythonPeer) wrap(token []byte) ([]byte, []byte, error) {
	if err := p.write("wrap " + base64.StdEncoding.EncodeToString(token)); err != nil {
		return nil, nil, err
	}
	first, err := p.readLine()
	if err != nil {
		return nil, nil, err
	}
	second, err := p.readLine()
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(first, "plain ") || !strings.HasPrefix(second, "wrap ") {
		return nil, nil, fmt.Errorf("unexpected Python peer output %q / %q", first, second)
	}
	plain, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(first, "plain "))
	if err != nil {
		return nil, nil, err
	}
	reply, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(second, "wrap "))
	return plain, reply, err
}

func (p *pythonPeer) wrapMessage(message []byte) ([]byte, error) {
	if err := p.write("makewrap " + base64.StdEncoding.EncodeToString(message)); err != nil {
		return nil, err
	}
	line, err := p.readLine()
	if err != nil {
		return nil, err
	}
	return decodePeerLine(line, "wrap ")
}

func (p *pythonPeer) unwrap(token []byte) error {
	if err := p.write("unwrap " + base64.StdEncoding.EncodeToString(token)); err != nil {
		return err
	}
	line, err := p.readLine()
	if err != nil {
		return err
	}
	plain, err := decodePeerLine(line, "plain ")
	if err != nil {
		return err
	}
	if string(plain) != "Go SPNEGO acceptor" {
		return fmt.Errorf("unexpected Python unwrap %q", plain)
	}
	return nil
}

func (p *pythonPeer) read(token string) ([]byte, error) {
	if token != "" {
		if err := p.write(token); err != nil {
			return nil, err
		}
	}
	line, err := p.readLine()
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(line, "done") {
		return nil, nil
	}
	return decodePeerLine(line, "step ")
}

func (p *pythonPeer) write(line string) error {
	if _, err := p.in.WriteString(line + "\n"); err != nil {
		return err
	}
	return p.in.Flush()
}

func (p *pythonPeer) readLine() (string, error) {
	if !p.out.Scan() {
		return "", fmt.Errorf("Python SPNEGO peer exited: %v", p.cmd.Wait())
	}
	return p.out.Text(), nil
}

func (p *pythonPeer) close() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

func decodePeerLine(line, prefix string) ([]byte, error) {
	if !strings.HasPrefix(line, prefix) {
		return nil, fmt.Errorf("unexpected Python peer output %q", line)
	}
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(line, prefix))
}

func requirePythonGSSAPI(t *testing.T) string {
	t.Helper()
	python := "/usr/bin/python3"
	if _, err := os.Stat(python); err != nil {
		t.Skipf("SPNEGO integration skipped: missing %s", python)
	}
	cmd := exec.Command(python, "-c", "import gssapi")
	if err := cmd.Run(); err == nil {
		return python
	}
	path := "/home/ubuntu/.cache/go-kerberos-spnego/root/usr/lib/python3/dist-packages"
	if _, err := os.Stat(filepath.Join(path, "gssapi")); err != nil {
		t.Skipf("SPNEGO integration skipped: python3-gssapi unavailable")
	}
	t.Setenv("PYTHONPATH", path)
	return python
}

func writeIntegrationFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

const pythonSPNEGOScript = `import base64, sys
import gssapi
from gssapi.raw.oids import OID

spnego = OID.from_int_seq((1, 3, 6, 1, 5, 5, 2))
kerberos = OID.from_int_seq((1, 2, 840, 113554, 1, 2, 2))
mode, config, cache, keytab, realm = sys.argv[1:]
if mode in ("accept", "kerberos-accept"):
    acceptor_name = gssapi.Name("host/service.test@" + realm, name_type=gssapi.NameType.kerberos_principal)
    acceptor_mechs = [kerberos] if mode == "kerberos-accept" else [spnego]
    acceptor_creds = gssapi.Credentials(name=acceptor_name, usage="accept", mechs=acceptor_mechs)
    ctx = gssapi.SecurityContext(creds=acceptor_creds, usage="accept")
elif mode == "delegate":
    name = gssapi.Name("host/service.test@" + realm, name_type=gssapi.NameType.kerberos_principal)
    flags = [gssapi.RequirementFlag.delegate_to_peer]
    ctx = gssapi.SecurityContext(name=name, usage="initiate", mech=kerberos, flags=flags)
else:
    name = gssapi.Name("host/service.test@" + realm, name_type=gssapi.NameType.kerberos_principal)
    flags = [gssapi.RequirementFlag.mutual_authentication,
             gssapi.RequirementFlag.integrity,
             gssapi.RequirementFlag.confidentiality]
    ctx = gssapi.SecurityContext(name=name, usage="initiate", mech=spnego, flags=flags)

def emit(kind, value):
    print(kind + " " + base64.b64encode(value or b"").decode("ascii"), flush=True)

if mode in ("initiate", "delegate"):
    emit("step", ctx.step(None))

for line in sys.stdin:
    kind, encoded = line.rstrip("\n").split(" ", 1)
    value = base64.b64decode(encoded)
    if kind == "step":
        emit("step", ctx.step(value))
    elif kind == "wrap":
        result = ctx.unwrap(value)
        emit("plain", result.message)
        emit("wrap", ctx.wrap(b"MIT SPNEGO acceptor", encrypt=False).message)
    elif kind == "makewrap":
        emit("wrap", ctx.wrap(value, encrypt=True).message)
    elif kind == "unwrap":
        emit("plain", ctx.unwrap(value).message)
`

//go:build integration

package testenv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	RealmName = "TEST.GOKRB5.LOCAL"
	MasterKey = "synthetic-master-password"
)

var requiredBinaries = []string{
	"/usr/sbin/kdb5_util",
	"/usr/sbin/kadmin.local",
	"/usr/sbin/krb5kdc",
	"/usr/sbin/kadmind",
	"/usr/bin/kinit",
	"/usr/bin/klist",
	"/usr/bin/kvno",
	"/usr/bin/ktutil",
}

// Realm is a disposable MIT KDC and its isolated configuration.
type Realm struct {
	Dir         string
	Config      string
	KDCConfig   string
	Keytab      string
	Cache       string
	Port        int
	AdminPort   int
	KPasswdPort int
	IPropPort   int

	cmds   []*exec.Cmd
	output bytes.Buffer
}

// Start creates and starts an MIT realm entirely below t.TempDir.
func Start(t *testing.T) *Realm {
	return start(t, "", false)
}

// StartWithMasterEType creates and starts an MIT realm with the requested
// database master-key enctype.
func StartWithMasterEType(t *testing.T, enctype string) *Realm {
	return start(t, enctype, false)
}

// StartWithIPROP creates and starts an MIT realm with incremental propagation
// enabled on kadmind.
func StartWithIPROP(t *testing.T) *Realm {
	return start(t, "", true)
}

func start(t *testing.T, masterEType string, iprop bool) *Realm {
	t.Helper()
	if testing.Short() {
		t.Skip("MIT interoperability harness skipped in short mode")
	}
	for _, path := range requiredBinaries {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("MIT interoperability harness skipped: missing binary %s", path)
		}
	}
	dir := t.TempDir()
	port := freePort(t)
	adminPort := freePort(t)
	kpasswdPort := freePort(t)
	ipropPort := 0
	if iprop {
		ipropPort = freePort(t)
	}
	r := &Realm{
		Dir:         dir,
		Config:      filepath.Join(dir, "krb5.conf"),
		KDCConfig:   filepath.Join(dir, "kdc.conf"),
		Keytab:      filepath.Join(dir, "services.keytab"),
		Cache:       filepath.Join(dir, "alice.ccache"),
		Port:        port,
		AdminPort:   adminPort,
		KPasswdPort: kpasswdPort,
		IPropPort:   ipropPort,
	}
	ipropKDCConfig := ""
	if iprop {
		ipropKDCConfig = fmt.Sprintf(`
  iprop_enable = true
  iprop_ulog_size = 1000
  iprop_port = %d
  iprop_logfile = %s/iprop.ulog
`, ipropPort, dir)
	}
	writeFile(t, r.Config, fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 ticket_lifetime = 24h
 forwardable = true

[realms]
 %s = {
  kdc = 127.0.0.1:%d
  admin_server = 127.0.0.1:%d
  kpasswd_port = %d
 }
`, RealmName, RealmName, port, adminPort, kpasswdPort))
	writeFile(t, r.KDCConfig, fmt.Sprintf(`[kdcdefaults]
 kdc_ports = %d
 kdc_tcp_ports = %d

[realms]
 %s = {
  database_name = %s/principal
  admin_database_name = %s/principal.kadm5
  admin_database_lockfile = %s/principal.kadm5.lock
  admin_keytab = %s/kadm5.keytab
  acl_file = %s/kadm5.acl
  key_stash_file = %s/.k5.%s
%s
 }
`, port, port, RealmName, dir, dir, dir, dir, dir, dir, RealmName, ipropKDCConfig))
	acl := "admin/admin@" + RealmName + " sxe\n"
	if iprop {
		acl += "kiprop/replica@" + RealmName + " p\n"
	}
	writeFile(t, filepath.Join(dir, "kadm5.acl"), acl)
	createArgs := []string{"create", "-s"}
	if masterEType != "" {
		createArgs = append(createArgs, "-k", masterEType)
	}
	createArgs = append(createArgs, "-P", MasterKey)
	run(t, r.env(), "", "/usr/sbin/kdb5_util", createArgs...)
	for _, command := range []string{
		"ktadd -k " + filepath.Join(dir, "kadm5.keytab") + " kadmin/admin kadmin/changepw",
		"addprinc -pw admin-password admin/admin",
		"addprinc -pw alice-password alice",
		"addprinc -pw bob-password bob",
		"addprinc -pw host-password host/server.test",
		"addprinc -pw http-password HTTP/server.test",
		"addprinc -randkey host/service.test",
		"ktadd -k " + r.Keytab + " -e aes128-cts-hmac-sha1-96,aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha256-128,aes256-cts-hmac-sha384-192 host/service.test",
	} {
		run(t, r.env(), "", "/usr/sbin/kadmin.local", "-q", command)
	}
	if iprop {
		commands := []string{
			"addprinc -pw kiprop-replica-password kiprop/replica",
			"addprinc -randkey kiprop/127.0.0.1",
			"ktadd -k " + r.Keytab + " kiprop/127.0.0.1",
		}
		for _, hostname := range localHostnames(t) {
			commands = append(commands,
				"addprinc -randkey kiprop/"+hostname,
				"ktadd -k "+r.Keytab+" kiprop/"+hostname)
		}
		for _, command := range commands {
			run(t, r.env(), "", "/usr/sbin/kadmin.local", "-q", command)
		}
	}
	r.startKDC(t)
	r.startKadmind(t)
	t.Cleanup(func() {
		r.stop()
	})
	return r
}

func (r *Realm) env() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") ||
			strings.HasPrefix(value, "KRB5_KDC_PROFILE=") {
			continue
		}
		env = append(env, value)
	}
	return append(env,
		"KRB5_CONFIG="+r.Config,
		"KRB5_KDC_PROFILE="+r.KDCConfig,
	)
}

func (r *Realm) startKDC(t *testing.T) {
	t.Helper()
	cmd := exec.Command("/usr/sbin/krb5kdc", "-n")
	cmd.Env = r.env()
	cmd.Stdout = &r.output
	cmd.Stderr = &r.output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start krb5kdc: %v", err)
	}
	r.cmds = append(r.cmds, cmd)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	r.stop()
	t.Fatalf("krb5kdc did not become ready: %s", r.output.String())
}

func (r *Realm) startKadmind(t *testing.T) {
	t.Helper()
	cmd := exec.Command("/usr/sbin/kadmind", "-nofork", "-port", strconv.Itoa(r.AdminPort))
	cmd.Env = r.env()
	cmd.Stdout = &r.output
	cmd.Stderr = &r.output
	if err := cmd.Start(); err != nil {
		r.stop()
		t.Fatalf("start kadmind: %v", err)
	}
	r.cmds = append(r.cmds, cmd)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.KPasswdPort)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	r.stop()
	t.Fatalf("kadmind did not become ready: %s", r.output.String())
}

func (r *Realm) stop() {
	for _, cmd := range r.cmds {
		if cmd == nil || cmd.Process == nil {
			continue
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	r.cmds = nil
}

// Run executes a command with the realm's isolated environment.
func (r *Realm) Run(t *testing.T, input string, name string, args ...string) string {
	t.Helper()
	return run(t, r.env(), input, name, args...)
}

func run(t *testing.T, env []string, input string, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Env = env
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output.String())
	}
	return output.String()
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate ephemeral port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func localHostname(t *testing.T) string {
	t.Helper()
	name, err := os.Hostname()
	if err != nil {
		t.Fatalf("get local hostname: %v", err)
	}
	return name
}

func localHostnames(t *testing.T) []string {
	t.Helper()
	names := []string{localHostname(t)}
	if output, err := exec.Command("hostname", "-f").Output(); err == nil {
		name := strings.TrimSpace(string(output))
		if name != "" && name != names[0] {
			names = append(names, name)
		}
	}
	return names
}

// CopyFile copies a generated artifact while preserving test-controlled errors.
func CopyFile(t *testing.T, source, destination string) {
	t.Helper()
	in, err := os.Open(source)
	if err != nil {
		t.Fatalf("open %s: %v", source, err)
	}
	defer in.Close()
	out, err := os.Create(destination)
	if err != nil {
		t.Fatalf("create %s: %v", destination, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatalf("copy %s: %v", destination, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", destination, err)
	}
}

//go:build integration

package mit_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMITKpropToGoServer(t *testing.T) {
	realm := testenv.Start(t)
	hostOutput, err := exec.Command("hostname", "-f").Output()
	if err != nil {
		t.Fatal(err)
	}
	localHost := strings.TrimSpace(string(hostOutput))
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -randkey host/"+localHost)
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"ktadd -k "+realm.Keytab+" host/"+localHost)
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -randkey host/127.0.0.1")
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"ktadd -k "+realm.Keytab+" host/127.0.0.1")
	keytabFile, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatal(err)
	}
	serviceKeytab, err := keytab.Read(keytabFile)
	_ = keytabFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var loaded []byte
	server := &kprop.Server{
		Keytab: serviceKeytab,
		Realm:  testenv.RealmName,
		Authorize: func(p principal.Principal) error {
			if p.String() != "host/"+localHost+"@"+testenv.RealmName {
				t.Fatalf("unexpected kprop client %s", p)
			}
			return nil
		},
		Load: func(r io.Reader, size uint64) error {
			if size == 0 {
				return io.ErrUnexpectedEOF
			}
			loaded, err = io.ReadAll(r)
			return err
		},
		ErrorLog: func(err error) { t.Logf("Go kprop server: %v", err) },
	}
	go func() { _ = server.Serve(listener) }()
	dump := filepath.Join(realm.Dir, "mit-kprop.dump")
	realm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dump)
	realm.Run(t, "", "/usr/sbin/kprop", "-d", "-f", dump,
		"-P", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
		"-s", realm.Keytab, "127.0.0.1")
	if len(loaded) == 0 {
		t.Fatal("Go server did not receive MIT dump")
	}
	path := filepath.Join(realm.Dir, "received.dump")
	if err := os.WriteFile(path, loaded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := mitdump.LoadWithMasterPassword(path, testenv.MasterKey)
	if err != nil {
		t.Fatalf("parse received MIT dump: %v", err)
	}
	alice, _ := principal.Parse("alice@" + testenv.RealmName)
	if _, ok, err := store.Lookup(*alice); err != nil || !ok {
		t.Fatalf("received dump missing alice: %v found=%t", err, ok)
	}
}

func TestGoKpropToMITKpropd(t *testing.T) {
	realm := testenv.Start(t)
	hostOutput, err := exec.Command("hostname", "-f").Output()
	if err != nil {
		t.Fatal(err)
	}
	localHost := strings.TrimSpace(string(hostOutput))
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -randkey host/"+localHost)
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"ktadd -k "+realm.Keytab+" host/"+localHost)
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -randkey host/127.0.0.1")
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"ktadd -k "+realm.Keytab+" host/127.0.0.1")
	dumpDB := seedKpropDatabase(t, realm)
	dump, err := mitdump.DumpWithMasterPassword(dumpDB, testenv.MasterKey,
		crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(realm.Dir, "go-kprop.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	replicaDB := filepath.Join(realm.Dir, "kprop-replica")
	aclPath := filepath.Join(realm.Dir, "kpropd.acl")
	replicaFile := filepath.Join(realm.Dir, "kpropd.repl")
	if err := os.WriteFile(aclPath, []byte("alice@"+testenv.RealmName+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freeIPROPTestPort(t)
	cmd := testenvCommand(realm, "/usr/sbin/kpropd", "-d", "-D",
		"-r", testenv.RealmName, "-s", realm.Keytab, "-f", replicaFile, "-F", replicaDB,
		"-P", strconv.Itoa(port), "-a", aclPath)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	time.Sleep(300 * time.Millisecond)
	cfgData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(cfgData)
	if err != nil {
		t.Fatal(err)
	}
	goClient := &client.Client{Config: cfg}
	tgt, err := goClient.ASExchange(context.Background(),
		mustPrincipal(t, "alice@"+testenv.RealmName), "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := goClient.TGSExchange(context.Background(), tgt,
		mustPrincipal(t, "host/"+localHost+"@"+testenv.RealmName))
	if err != nil {
		t.Fatal(err)
	}
	if err := kprop.DialAndSend(context.Background(),
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), creds,
		bytes.NewReader(dump), uint64(len(dump))); err != nil {
		t.Fatalf("Go kprop to MIT kpropd: %v\n%s", err, output.String())
	}
	result := exec.Command("/usr/sbin/kadmin.local", "-r", testenv.RealmName,
		"-d", replicaDB, "-q", "getprinc kprop-live")
	result.Env = testenvEnv(realm)
	var resultOutput bytes.Buffer
	result.Stdout, result.Stderr = &resultOutput, &resultOutput
	if err := result.Run(); err != nil {
		t.Fatalf("query MIT replica database: %v\n%s\nkpropd:\n%s",
			err, resultOutput.String(), output.String())
	}
	if !strings.Contains(resultOutput.String(), "Principal: kprop-live@"+testenv.RealmName) {
		t.Fatalf("replica missing kprop-live:\n%s\nkpropd:\n%s",
			resultOutput.String(), output.String())
	}
}

func seedKpropDatabase(t *testing.T, realm *testenv.Realm) *kdb.Database {
	t.Helper()
	dump := filepath.Join(realm.Dir, "seed.dump")
	realm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dump)
	store, err := mitdump.LoadWithMasterPassword(dump, testenv.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	db := kdb.NewDatabase(testenv.RealmName)
	for _, name := range []string{"alice", "bob"} {
		record, ok, err := store.Lookup(mustPrincipal(t, name+"@"+testenv.RealmName))
		if err != nil || !ok {
			t.Fatalf("seed %s: %v found=%t", name, err, ok)
		}
		if err := db.ApplyPrincipal(record, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddPrincipal("kprop-live", "kprop-live-password"); err != nil {
		t.Fatal(err)
	}
	live := mustPrincipal(t, "kprop-live@"+testenv.RealmName)
	record, found, err := db.Lookup(live)
	if err != nil || !found {
		t.Fatalf("lookup kprop-live: %v found=%t", err, found)
	}
	delete(record.Keys, crypto.EnctypeAES128SHA256)
	delete(record.Keys, crypto.EnctypeAES256SHA384)
	modifier := []byte("admin/admin@" + testenv.RealmName + "\x00")
	record.TLData = []kdb.TLData{{Type: 2, Data: append(
		binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix())), modifier...)}}
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	return db
}

func mustPrincipal(t *testing.T, value string) principal.Principal {
	t.Helper()
	p, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func testenvCommand(realm *testenv.Realm, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = testenvEnv(realm)
	return cmd
}

func testenvEnv(realm *testenv.Realm) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") || strings.HasPrefix(value, "KRB5_KDC_PROFILE=") {
			continue
		}
		env = append(env, value)
	}
	return append(env, "KRB5_CONFIG="+realm.Config, "KRB5_KDC_PROFILE="+realm.KDCConfig)
}

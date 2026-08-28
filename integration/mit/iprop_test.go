//go:build integration

package mit_test

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoIPROPReplicaAgainstMITMaster(t *testing.T) {
	realm := testenv.StartWithIPROP(t)
	for _, service := range []string{"kiprop/127.0.0.1", "kiprop/replica"} {
		output := realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
			"getprinc "+service)
		if !strings.Contains(output, "Principal: "+service+"@"+testenv.RealmName) {
			t.Fatalf("MIT iprop service principal %s was not available:\n%s",
				service, output)
		}
	}
	ordinaryDump := filepath.Join(realm.Dir, "iprop-seed.dump")
	ipropDump := filepath.Join(realm.Dir, "iprop-seed.ipropx")
	realm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", ordinaryDump)
	realm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-i1", ipropDump)

	marker, err := readIPROPMarker(ipropDump)
	if err != nil {
		t.Fatalf("read MIT iprop dump marker: %v", err)
	}
	store, err := mitdump.LoadWithMasterPassword(ordinaryDump, testenv.MasterKey)
	if err != nil {
		t.Fatalf("load MIT seed dump: %v", err)
	}
	replicaDB := kdb.NewDatabase(testenv.RealmName)
	for _, name := range []string{"alice", "bob"} {
		parsed, err := principal.Parse(name + "@" + testenv.RealmName)
		if err != nil {
			t.Fatal(err)
		}
		record, ok, err := store.Lookup(*parsed)
		if err != nil {
			t.Fatalf("lookup %s in MIT dump: %v", name, err)
		}
		if !ok {
			t.Fatalf("%s missing from MIT seed dump", name)
		}
		if err := replicaDB.ApplyPrincipal(record, false); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	before, ok, err := replicaDB.Lookup(principal.Principal{
		Realm: testenv.RealmName, Components: []string{"alice"},
	})
	if err != nil || !ok {
		t.Fatalf("lookup seeded alice: %v, found=%t", err, ok)
	}

	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse MIT client config: %v", err)
	}
	goClient := &client.Client{Config: cfg}
	replicaPrincipal, err := principal.Parse("kiprop/replica@" + testenv.RealmName)
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := goClient.ASExchange(context.Background(), *replicaPrincipal,
		"kiprop-replica-password")
	if err != nil {
		t.Fatalf("AS exchange for kiprop replica: %v", err)
	}
	masterService, err := principal.Parse("kiprop/127.0.0.1@" + testenv.RealmName)
	if err != nil {
		t.Fatal(err)
	}
	serviceCreds, err := goClient.TGSExchange(context.Background(), tgt, *masterService)
	if err != nil {
		t.Fatalf("TGS exchange for kiprop master: %v", err)
	}
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(realm.IPropPort)),
		5*time.Second)
	if err != nil {
		t.Fatalf("dial MIT iprop service: %v", err)
	}
	rpcClient := iprop.NewClient(conn, serviceCreds)
	t.Cleanup(func() { _ = rpcClient.Close() })
	if err := rpcClient.Authenticate(context.Background()); err != nil {
		t.Fatalf("authenticate to MIT iprop: %v", err)
	}
	replica := &iprop.Replica{
		Client:   rpcClient,
		Database: replicaDB,
		Cursor:   marker,
	}

	realm.Run(t, "", "/usr/bin/kadmin",
		"-p", "admin/admin", "-w", "admin-password",
		"-q", "addprinc -pw iprop-live-password iprop-live")
	realm.Run(t, "", "/usr/bin/kadmin",
		"-p", "admin/admin", "-w", "admin-password",
		"-q", "cpw -pw alice-iprop-password alice")

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, err := replica.Poll(context.Background())
		if err != nil {
			t.Fatalf("poll MIT iprop: %v", err)
		}
		if status != iprop.UpdateOK && status != iprop.UpdateNil {
			t.Fatalf("poll MIT iprop status = %d", status)
		}
		newPrincipal, found, err := replicaDB.Lookup(principal.Principal{
			Realm: testenv.RealmName, Components: []string{"iprop-live"},
		})
		if err != nil {
			t.Fatalf("lookup replicated principal: %v", err)
		}
		updated, updatedFound, err := replicaDB.Lookup(principal.Principal{
			Realm: testenv.RealmName, Components: []string{"alice"},
		})
		if err != nil {
			t.Fatalf("lookup replicated alice: %v", err)
		}
		if found && updatedFound && !sameKeys(before, updated) &&
			newPrincipal.Name.String() == "iprop-live@"+testenv.RealmName {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("MIT iprop updates were not applied; cursor=%+v", replica.Cursor)
}

func TestMITKpropdAgainstGoIPROPMaster(t *testing.T) {
	const (
		kpropd  = "/usr/sbin/kpropd"
		kdbutil = "/usr/sbin/kdb5_util"
	)
	if _, err := os.Stat(kpropd); err != nil {
		t.Skipf("MIT kpropd unavailable at %s: %v", kpropd, err)
	}
	realm := testenv.StartWithIPROP(t)
	masterDump := filepath.Join(realm.Dir, "go-master.dump")
	replicaDB := filepath.Join(realm.Dir, "replica")
	replicaDump := filepath.Join(realm.Dir, "replica.ipropx")
	dump, err := mitdump.DumpWithMasterPassword(
		seedGoIPROPDatabase(t, realm), testenv.MasterKey)
	if err != nil {
		t.Fatalf("write Go master dump: %v", err)
	}
	dump = append([]byte("ipropx 1 0 0 0\n"),
		dump[bytes.IndexByte(dump, '\n')+1:]...)
	if err := os.WriteFile(masterDump, dump, 0o600); err != nil {
		t.Fatalf("write Go iprop dump: %v", err)
	}
	if err := os.WriteFile(replicaDump, dump, 0o600); err != nil {
		t.Fatalf("write replica iprop dump: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen Go iprop master: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	replicaProfile := filepath.Join(realm.Dir, "replica-kdc.conf")
	replicaLog := filepath.Join(realm.Dir, "replica.ulog")
	replicaAdminDB := filepath.Join(realm.Dir, "replica.kadm5")
	writeTestFile(t, replicaProfile, fmt.Sprintf(`[kdcdefaults]
kdc_ports = 0
kdc_tcp_ports = 0

	[realms]
	%s = {
	  admin_server = 127.0.0.1
	  kadmind_port = %d
	  database_name = %s
	  key_stash_file = %s/.k5.%s
	  admin_database_name = %s
  admin_database_lockfile = %s.lock
  iprop_enable = true
  iprop_ulog_size = 1000
	  iprop_logfile = %s
	  iprop_port = %d
	  iprop_slave_poll = 1
	 }
	`, testenv.RealmName, realm.AdminPort, replicaDB, realm.Dir,
		testenv.RealmName, replicaAdminDB,
		replicaAdminDB, replicaLog, listener.Addr().(*net.TCPAddr).Port))
	replicaEnv := testEnvironment(realm.Config, replicaProfile)
	runTestCommand(t, replicaEnv, "", kdbutil, "load", "-i", replicaDump)

	keytabData, err := os.ReadFile(realm.Keytab)
	if err != nil {
		t.Fatalf("read Go iprop keytab: %v", err)
	}
	serviceKeytab, err := keytab.Read(bytes.NewReader(keytabData))
	if err != nil {
		t.Fatalf("parse Go iprop keytab: %v", err)
	}
	masterDB := seedGoIPROPDatabase(t, realm)
	if err := masterDB.AddPrincipal("iprop-live", "iprop-live-password"); err != nil {
		t.Fatalf("mutate Go iprop master: %v", err)
	}
	liveName, err := principal.Parse("iprop-live@" + testenv.RealmName)
	if err != nil {
		t.Fatalf("parse live principal: %v", err)
	}
	liveRecord, ok, err := masterDB.Lookup(*liveName)
	if err != nil || !ok {
		t.Fatalf("lookup live principal: %v found=%t", err, ok)
	}
	// MIT 1.19's default enctype set is AES-SHA1. Keep this gate focused on
	// the iprop wire/update path rather than asking that runtime to decode
	// newer AES-SHA2 key types.
	delete(liveRecord.Keys, crypto.EnctypeAES128SHA256)
	delete(liveRecord.Keys, crypto.EnctypeAES256SHA384)
	masterDB.ConfigureUpdateLog(1024)
	if err := masterDB.UpdatePrincipal(liveRecord); err != nil {
		t.Fatalf("record filtered live update: %v", err)
	}
	master := iprop.NewServer(masterDB, serviceKeytab)
	masterEType, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatalf("get MIT master enctype: %v", err)
	}
	masterKey, err := masterEType.StringToKey([]byte(testenv.MasterKey),
		[]byte(testenv.RealmName+"KM"), nil)
	if err != nil {
		t.Fatalf("derive MIT master key: %v", err)
	}
	master.MasterEnctype = crypto.EnctypeAES256SHA1
	master.MasterKey = masterKey
	localHostBytes, err := exec.Command("hostname", "-f").Output()
	if err != nil {
		t.Fatalf("get local hostname: %v", err)
	}
	localHost := strings.TrimSpace(string(localHostBytes))
	replicaName := "kiprop/" + localHost + "@" + testenv.RealmName
	master.AllowedReplicas = map[string]bool{replicaName: true}
	master.ErrorLog = func(err error) { t.Logf("Go iprop master: %v", err) }
	go func() { _ = master.Serve(listener) }()

	kpropPort := freeIPROPTestPort(t)
	cmd := exec.Command(kpropd,
		"-S", "-d", "-D", "-r", testenv.RealmName,
		"-s", realm.Keytab, "-f", filepath.Join(realm.Dir, "replica.dat"),
		"-F", replicaDB, "-P", strconv.Itoa(kpropPort))
	cmd.Env = replicaEnv
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start MIT kpropd: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()
	time.Sleep(2 * time.Second)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		t.Fatalf("MIT kpropd exited before update: %v\n%s",
			cmd.ProcessState, output.String())
	}

	if err := masterDB.ChangePassword(*liveName, "iprop-live-updated"); err != nil {
		t.Fatalf("drive Go iprop password change: %v", err)
	}
	time.Sleep(3 * time.Second)
	deadline := time.Now().Add(15 * time.Second)
	var lastResult string
	for time.Now().Before(deadline) {
		check := exec.Command(kadminLocal, "-r", testenv.RealmName,
			"-d", replicaDB, "-q", "getprinc iprop-live")
		result := runTestCommandOutput(check, replicaEnv)
		lastResult = result
		if strings.Contains(result, "Principal: iprop-live@"+testenv.RealmName) {
			t.Logf("MIT kpropd output:\n%s", output.String())
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	dumpResult := runTestCommandOutput(exec.Command(kdbutil, "dump", "-verbose",
		"-d", replicaDB), replicaEnv)
	t.Fatalf("MIT kpropd did not apply Go update; last kadmin output:\n%s\n"+
		"replica dump:\n%s\nkpropd:\n%s", lastResult, dumpResult,
		output.String())
}

const kadminLocal = "/usr/sbin/kadmin.local"

func seedGoIPROPDatabase(t *testing.T, realm *testenv.Realm) *kdb.Database {
	t.Helper()
	dump := filepath.Join(realm.Dir, "mit-seed.dump")
	realm.Run(t, "", kdbutilPath, "dump", "-r18", dump)
	store, err := mitdump.LoadWithMasterPassword(dump, testenv.MasterKey)
	if err != nil {
		t.Fatalf("load MIT seed dump: %v", err)
	}
	db := kdb.NewDatabase(testenv.RealmName)
	for _, name := range []string{"alice", "bob"} {
		parsed, err := principal.Parse(name + "@" + testenv.RealmName)
		if err != nil {
			t.Fatal(err)
		}
		record, ok, err := store.Lookup(*parsed)
		if err != nil || !ok {
			t.Fatalf("lookup %s in MIT seed dump: %v found=%t", name, err, ok)
		}
		if err := db.ApplyPrincipal(record, false); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return db
}

const kdbutilPath = "/usr/sbin/kdb5_util"

func testEnvironment(configPath, profilePath string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") ||
			strings.HasPrefix(value, "KRB5_KDC_PROFILE=") {
			continue
		}
		env = append(env, value)
	}
	return append(env, "KRB5_CONFIG="+configPath,
		"KRB5_KDC_PROFILE="+profilePath)
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runTestCommand(t *testing.T, env []string, input, name string,
	args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", cmd.String(), err, output.String())
	}
	return output.String()
}

func runTestCommandOutput(cmd *exec.Cmd, env []string) string {
	cmd.Env = env
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("command failed: %v\n%s", err, output.String())
	}
	return output.String()
}

func freeIPROPTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate test port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func readIPROPMarker(path string) (iprop.Last, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return iprop.Last{}, err
	}
	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) != 5 || fields[0] != "ipropx" {
		return iprop.Last{}, fmt.Errorf("unexpected iprop dump header %q", fields)
	}
	var values [4]uint32
	for i := range values {
		value, err := strconv.ParseUint(fields[i+1], 10, 32)
		if err != nil {
			return iprop.Last{}, fmt.Errorf("parse header field %q: %w", fields[i+1], err)
		}
		values[i] = uint32(value)
	}
	return iprop.Last{
		LastSno:  values[1],
		LastTime: iprop.Time{Seconds: values[2], Useconds: values[3]},
	}, nil
}

func sameKeys(a, b kdb.PrincipalRecord) bool {
	if len(a.Keys) != len(b.Keys) {
		return false
	}
	for enctype, first := range a.Keys {
		second, ok := b.Keys[enctype]
		if !ok || first.KVNO != second.KVNO ||
			string(first.Key) != string(second.Key) {
			return false
		}
	}
	return true
}

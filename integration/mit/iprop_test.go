//go:build integration

package mit_test

import (
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
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
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
	const kpropd = "/usr/sbin/kpropd"
	if _, err := os.Stat(kpropd); err != nil {
		cmd := exec.Command(kpropd, "-S")
		output, runErr := cmd.CombinedOutput()
		t.Logf("kpropd attempt: error=%v output=%q", runErr, output)
		t.Skipf("MIT kpropd unavailable at %s; missing binary prevents live gate: %v",
			kpropd, err)
	}
	t.Skip("MIT kpropd gate requires the separate kprop dump-push protocol")
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

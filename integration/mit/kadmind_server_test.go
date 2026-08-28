//go:build integration

package mit_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMITKadminAgainstGoKadmind(t *testing.T) {
	realm := testenv.Start(t)
	keytabFile, err := os.Open(filepath.Join(realm.Dir, "kadm5.keytab"))
	if err != nil {
		t.Fatal(err)
	}
	serviceKeytab, err := keytab.Read(keytabFile)
	keytabFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	db := kdb.NewDatabase(testenv.RealmName)
	if err := db.CreatePolicy(kdb.PolicyRecord{
		Name: "integration-policy", MinLength: 8, MinClasses: 3, HistoryNum: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("admin/admin@"+testenv.RealmName, "admin-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("nfs/host@"+testenv.RealmName, "nfs-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("limited@"+testenv.RealmName, "limited-password"); err != nil {
		t.Fatal(err)
	}
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addprinc -pw limited-password limited")
	aclPath := filepath.Join(t.TempDir(), "kadm5.acl")
	aclContents := "admin/admin@" + testenv.RealmName + " *\n" +
		"limited@" + testenv.RealmName + " i\n"
	if err := os.WriteFile(aclPath, []byte(aclContents), 0o600); err != nil {
		t.Fatal(err)
	}
	acl, err := kadm5.LoadACL(aclPath)
	if err != nil {
		t.Fatal(err)
	}
	server := kadm5.NewServer(db, serviceKeytab)
	server.ACL = acl.Func()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go server.Serve(listener)
	kadmin := func(command string) string {
		return realm.Run(t, "", "/usr/bin/kadmin", "-p", "admin/admin",
			"-w", "admin-password", "-s", listener.Addr().String(), "-q", command)
	}
	if output := kadmin("getprinc admin/admin"); !strings.Contains(output, "Principal: admin/admin@"+testenv.RealmName) {
		t.Fatalf("getprinc output = %s", output)
	}
	kadmin("addprinc -pw Scratch-password1 scratch")
	scratch, err := principal.Parse("scratch@" + testenv.RealmName)
	if err != nil {
		t.Fatal(err)
	}
	scratchRecord, ok, err := db.Lookup(*scratch)
	if err != nil || !ok {
		t.Fatalf("lookup scratch: %v, %v", err, ok)
	}
	scratchRecord.Policy = "integration-policy"
	if err := db.UpdatePrincipal(scratchRecord); err != nil {
		t.Fatal(err)
	}
	tooShortScript := fmt.Sprintf(
		`set +e; output=$(/usr/bin/kadmin -p admin/admin -w admin-password -s %s -q 'cpw -pw short scratch' 2>&1); rc=$?; printf '%%s\n' "$output"; test "$rc" -ne 0; printf '%%s\n' "$output" | grep -qi 'too short'`,
		listener.Addr().String())
	realm.Run(t, "", "/bin/sh", "-c", tooShortScript)
	kadmin("cpw -pw Strong-password1 scratch")
	reuseScript := fmt.Sprintf(
		`set +e; output=$(/usr/bin/kadmin -p admin/admin -w admin-password -s %s -q 'cpw -pw Scratch-password1 scratch' 2>&1); rc=$?; printf '%%s\n' "$output"; test "$rc" -ne 0; printf '%%s\n' "$output" | grep -qi 'reuse'`,
		listener.Addr().String())
	realm.Run(t, "", "/bin/sh", "-c", reuseScript)
	kadmin("cpw -pw Changed-password1 scratch")
	if output := kadmin("getprinc scratch"); !strings.Contains(output, "Principal: scratch@"+testenv.RealmName) {
		t.Fatalf("getprinc scratch output = %s", output)
	}
	if output := kadmin("listprincs scratch"); !strings.Contains(output, "scratch@"+testenv.RealmName) {
		t.Fatalf("listprincs output = %s", output)
	}
	if output := kadmin("listprincs */*"); !strings.Contains(output, "nfs/host@"+testenv.RealmName) {
		t.Fatalf("listprincs service glob output = %s", output)
	}
	kadmin("delprinc -force scratch")

	limitedGet := realm.Run(t, "", "/usr/bin/kadmin", "-p", "limited",
		"-w", "limited-password", "-s", listener.Addr().String(), "-q",
		"getprinc admin/admin")
	if !strings.Contains(limitedGet, "Principal: admin/admin@"+testenv.RealmName) {
		t.Fatalf("limited getprinc output = %s", limitedGet)
	}
	deniedScript := fmt.Sprintf(
		`set +e; output=$(/usr/bin/kadmin -p limited -w limited-password -s %s -q 'addprinc -pw denied-password denied' 2>&1); rc=$?; printf '%%s\n' "$output"; test "$rc" -ne 0; printf '%%s\n' "$output" | grep -qi privilege`,
		listener.Addr().String())
	realm.Run(t, "", "/bin/sh", "-c", deniedScript)
}

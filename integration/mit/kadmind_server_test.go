//go:build integration

package mit_test

import (
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
	if err := db.AddPrincipal("admin/admin@"+testenv.RealmName, "admin-password"); err != nil {
		t.Fatal(err)
	}
	server := kadm5.NewServer(db, serviceKeytab)
	admin := principal.Principal{Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"admin", "admin"}}
	server.AdminPrincipal = admin
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
	kadmin("addprinc -pw scratch-password scratch")
	kadmin("cpw -pw changed-password scratch")
	if output := kadmin("getprinc scratch"); !strings.Contains(output, "Principal: scratch@"+testenv.RealmName) {
		t.Fatalf("getprinc scratch output = %s", output)
	}
	if output := kadmin("listprincs scratch"); !strings.Contains(output, "scratch@"+testenv.RealmName) {
		t.Fatalf("listprincs output = %s", output)
	}
	kadmin("delprinc -force scratch")
}

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
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kpasswd"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoKpasswdServerAgainstMITClient(t *testing.T) {
	realm := testenv.Start(t)
	db := kdb.NewDatabase(testenv.RealmName)
	for _, value := range []struct {
		name, password string
	}{
		{"alice", "alice-password"},
		{"bob", "bob-password"},
		{"kadmin/changepw", "unused-service-password"},
	} {
		if err := db.AddPrincipal(value.name, value.password); err != nil {
			t.Fatal(err)
		}
	}
	installMITChangePasswordKeys(t, db, filepath.Join(realm.Dir, "kadm5.keytab"))
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "strong", MinLength: 12, MinClasses: 3}); err != nil {
		t.Fatal(err)
	}
	alice, _ := principal.Parse("alice@" + testenv.RealmName)
	record, ok, err := db.Lookup(*alice)
	if err != nil || !ok {
		t.Fatalf("lookup alice: %v, %t", err, ok)
	}
	record.Policy = "strong"
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admin, _ := principal.Parse("admin/admin@" + testenv.RealmName)
	bob, _ := principal.Parse("bob@" + testenv.RealmName)
	server := &kpasswd.Server{
		Realm: testenv.RealmName, DB: db,
		ErrorLog: func(err error) { t.Logf("Go kpasswd server: %v", err) },
		ACL: func(client principal.Principal, operation string, target principal.Principal) bool {
			return client.String() == admin.String() && operation == "set-password" &&
				target.String() == bob.String()
		},
	}
	go func() { _ = server.ListenAndServe(ctx, udpConn, tcpListener) }()

	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	configData = []byte(strings.Replace(string(configData),
		fmt.Sprintf("kpasswd_port = %d", realm.KPasswdPort),
		fmt.Sprintf("kpasswd_port = %d", port), 1))
	configData = []byte(strings.Replace(string(configData),
		fmt.Sprintf(" admin_server = 127.0.0.1:%d", realm.AdminPort),
		fmt.Sprintf(" admin_server = 127.0.0.1:%d\n  kpasswd_server = 127.0.0.1:%d", realm.AdminPort, port), 1))
	clientConfig := filepath.Join(realm.Dir, "gokpasswd.conf")
	if err := os.WriteFile(clientConfig, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	runMITKpasswd(t, clientConfig, "alice-password\n", "alice")
	output, err := runMITKpasswdResult(clientConfig,
		"Alice-new-password1\nshort\nshort\n", "alice")
	if err == nil || !strings.Contains(strings.ToLower(output), "password") {
		t.Fatalf("short password unexpectedly accepted or lacked error: %q", output)
	}

	// The first invocation above uses the real MIT kpasswd exchange and
	// supplies the compliant new password through its prompt sequence.
	_ = output
	updated, ok, err := db.Lookup(*alice)
	if err != nil || !ok {
		t.Fatalf("lookup changed alice: %v, %t", err, ok)
	}
	etype, _ := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	expected, err := etype.StringToKey([]byte("Alice-new-password1"), []byte(testenv.RealmName+"alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(updated.Keys[crypto.EnctypeAES256SHA1].Key) != string(expected) {
		t.Fatal("MIT kpasswd did not update the Go KDB")
	}

	goClient := &client.Client{Config: mustParseConfig(t, configData)}
	if err := (&kpasswd.Client{Kerberos: goClient}).SetPassword(
		context.Background(), *admin, "admin-password", *bob, "bob-set-password",
	); err != nil {
		t.Fatalf("Go set-password against Go server: %v", err)
	}
}

func runMITKpasswd(t *testing.T, conf, input string, principalName string) {
	t.Helper()
	// kpasswd prompts for current, new, and verification passwords.
	out, err := runMITKpasswdResult(conf, input+"Alice-new-password1\nAlice-new-password1\n", principalName)
	if err != nil {
		trace, _ := os.ReadFile(conf + ".trace")
		t.Fatalf("MIT kpasswd: %v\n%s\ntrace:\n%s", err, out, trace)
	}
}

func runMITKpasswdResult(conf, input, principalName string) (string, error) {
	cmd := exec.Command("/usr/bin/kpasswd", principalName)
	cmd.Env = append(os.Environ(), "KRB5_CONFIG="+conf, "KRB5_TRACE="+conf+".trace")
	cmd.Stdin = strings.NewReader(input)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}

func mustParseConfig(t *testing.T, data []byte) *config.Config {
	t.Helper()
	value, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func installMITChangePasswordKeys(t *testing.T, db *kdb.Database, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Read(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	service, _ := principal.Parse("kadmin/changepw@" + testenv.RealmName)
	record, ok, err := db.Lookup(*service)
	if err != nil || !ok {
		t.Fatalf("lookup changepw: %v, %t", err, ok)
	}
	for _, enctype := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
	} {
		var selected *keytab.Entry
		for i := range kt.Entries {
			entry := &kt.Entries[i]
			if entry.Enctype == enctype && entry.Principal.String() == service.String() &&
				(selected == nil || entry.KVNO > selected.KVNO) {
				selected = entry
			}
		}
		if selected != nil {
			record.Keys[enctype] = kdb.Key{
				Enctype: enctype, KVNO: selected.KVNO,
				Key:  append([]byte(nil), selected.Key...),
				Salt: testenv.RealmName + "kadminchangepw",
			}
			record.KVNO = selected.KVNO
		}
	}
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
}

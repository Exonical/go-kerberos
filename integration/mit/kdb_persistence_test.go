//go:build integration

package mit_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMITDumpToGoKDCPersistence(t *testing.T) {
	mitRealm := testenv.Start(t)
	dumpPath := filepath.Join(mitRealm.Dir, "principal.dump")
	mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dumpPath)
	store, err := mitdump.LoadWithMasterPassword(dumpPath, testenv.MasterKey)
	if err != nil {
		t.Fatalf("load MIT dump: %v", err)
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
	t.Cleanup(func() {
		udpConn.Close()
		tcpListener.Close()
	})
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	configPath := filepath.Join(mitRealm.Dir, "go-kdc.conf")
	config := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false

[realms]
 %s = {
  kdc = 127.0.0.1:%d
  kdc = tcp/127.0.0.1:%d
 }
`, testenv.RealmName, testenv.RealmName, udpPort, tcpPort)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &kdc.Server{
		Realm:            testenv.RealmName,
		DB:               store,
		Now:              time.Now,
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Go KDC did not stop")
		}
	})

	cachePath := filepath.Join(mitRealm.Dir, "go-kdc.ccache")
	run := func(input string, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = []string{"KRB5_CONFIG=" + configPath, "KRB5CCNAME=FILE:" + cachePath,
			"KRB5_TRACE=/dev/stderr"}
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v failed: %v\n%s", name, args, err, output)
		}
		return string(output)
	}
	run("alice-password\n", "/usr/bin/kinit", "alice")
	kvno := run("", "/usr/bin/kvno", "host/service.test")
	if !strings.Contains(kvno, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("unexpected kvno output: %s", kvno)
	}
	listing := run("", "/usr/bin/klist", "-e")
	if !strings.Contains(listing, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("klist does not show persisted service ticket:\n%s", listing)
	}
}

func TestMITDumpWithMITStash(t *testing.T) {
	mitRealm := testenv.Start(t)
	dumpPath := filepath.Join(mitRealm.Dir, "principal-stash.dump")
	mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dumpPath)
	stashPath := filepath.Join(mitRealm.Dir, ".k5."+testenv.RealmName)
	store, err := mitdump.LoadWithStash(dumpPath, stashPath)
	if err != nil {
		t.Fatalf("load MIT dump with stash: %v", err)
	}
	record, ok, err := store.Lookup(principal.Principal{
		Realm: testenv.RealmName, Components: []string{"alice"},
	})
	if err != nil {
		t.Fatalf("lookup alice: %v", err)
	}
	if !ok {
		t.Fatal("alice missing")
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := etype.StringToKey([]byte("alice-password"),
		[]byte(testenv.RealmName+"alice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := record.Keys[etype.ID()]
	if !ok || !bytes.Equal(key.Key, expected) {
		t.Fatalf("alice key does not match stash-decrypted key: %#v", key)
	}
}

func TestGoWrittenStashConsumedByMIT(t *testing.T) {
	mitRealm := testenv.Start(t)
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := etype.StringToKey([]byte(testenv.MasterKey),
		[]byte(testenv.RealmName+"KM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	stashPath := filepath.Join(mitRealm.Dir, ".k5."+testenv.RealmName)
	if err := mitdump.WriteStashFile(stashPath, testenv.RealmName,
		etype.ID(), 1, masterKey); err != nil {
		t.Fatalf("write Go stash: %v", err)
	}
	dumpPath := filepath.Join(mitRealm.Dir, "go-stash-consumed.dump")
	mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dumpPath)
}

func TestMITDumpMasterKeyEnctypes(t *testing.T) {
	for _, enctype := range []string{
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
	} {
		t.Run(enctype, func(t *testing.T) {
			mitRealm := testenv.StartWithMasterEType(t, enctype)
			dumpPath := filepath.Join(mitRealm.Dir, "principal.dump")
			mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dumpPath)
			store, err := mitdump.LoadWithMasterPassword(dumpPath, testenv.MasterKey)
			if err != nil {
				t.Fatalf("load %s MIT dump: %v", enctype, err)
			}
			record, ok, err := store.Lookup(principal.Principal{
				Realm: testenv.RealmName, Components: []string{"alice"},
			})
			if err != nil {
				t.Fatalf("lookup alice: %v", err)
			}
			if !ok {
				t.Fatal("alice missing")
			}
			for _, keyType := range []int32{
				crypto.EnctypeAES128SHA1,
				crypto.EnctypeAES256SHA1,
			} {
				key, ok := record.Keys[keyType]
				if !ok || (len(key.Key) != 16 && len(key.Key) != 32) {
					t.Fatalf("alice key %d = %#v", keyType, key)
				}
				etype, err := crypto.NewRegistry().Get(keyType)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := etype.StringToKey([]byte("alice-password"),
					[]byte(testenv.RealmName+"alice"), nil)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(key.Key, expected) {
					t.Fatalf("alice key %d does not match MIT string-to-key", keyType)
				}
			}
		})
	}
}

func TestGoDumpLoadsIntoMIT(t *testing.T) {
	mitRealm := testenv.Start(t)
	mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"addpol -minlength 1 dump-policy")
	db := kdb.NewDatabase(testenv.RealmName)
	if err := db.AddPrincipal("dumped-user", "dumped-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("host/dumped-service.test", "service-password"); err != nil {
		t.Fatal(err)
	}
	dumpedName, err := principal.Parse("dumped-user@" + testenv.RealmName)
	if err != nil {
		t.Fatal(err)
	}
	dumped, ok, err := db.Lookup(*dumpedName)
	if err != nil || !ok {
		t.Fatalf("lookup dumped principal: %v, %v", err, ok)
	}
	dumped.Policy = "dump-policy"
	// MIT administrative retrieval requires a valid modifier-principal TL.
	modifier := []byte("ubuntu/admin@" + testenv.RealmName + "\x00")
	modData := make([]byte, 4+len(modifier))
	binary.BigEndian.PutUint32(modData, uint32(time.Now().Unix()))
	copy(modData[4:], modifier)
	dumped.TLData = []kdb.TLData{
		{Type: 2, Data: modData},
	}
	if err := db.UpdatePrincipal(dumped); err != nil {
		t.Fatalf("set dumped principal policy: %v", err)
	}
	data, err := mitdump.Dump(db, testenv.MasterKey)
	if err != nil {
		t.Fatalf("dump Go database: %v", err)
	}
	dumpPath := filepath.Join(mitRealm.Dir, "go-principal.dump")
	if err := os.WriteFile(dumpPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "load", "-update", dumpPath)
	cachePath := filepath.Join(mitRealm.Dir, "dumped.ccache")
	mitRealm.Run(t, "dumped-password\n", "/usr/bin/kinit", "-c", cachePath,
		"dumped-user")
	principalInfo := mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		"getprinc dumped-user")
	if !strings.Contains(principalInfo, "Policy: dump-policy") {
		t.Fatalf("MIT did not retain dumped policy reference:\n%s", principalInfo)
	}
	listing := mitRealm.Run(t, "", "/usr/bin/klist", "-c", cachePath)
	if !strings.Contains(listing, "dumped-user@"+testenv.RealmName) {
		t.Fatalf("klist does not show dumped principal:\n%s", listing)
	}
}

func TestMITPasswordHistoryRoundTrip(t *testing.T) {
	t.Run("MITToGo", func(t *testing.T) {
		mitRealm := testenv.Start(t)
		mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
			"addpol -minlength 1 -history 3 history-policy")
		mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
			"modprinc -policy history-policy alice")
		mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
			"cpw -pw alice-history-2 alice")
		mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
			"cpw -pw alice-history-3 alice")

		dumpPath := filepath.Join(mitRealm.Dir, "history.dump")
		mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "dump", "-r18", dumpPath)
		store, err := mitdump.LoadWithMasterPassword(dumpPath, testenv.MasterKey)
		if err != nil {
			t.Fatalf("load MIT history dump: %v", err)
		}
		name, err := principal.Parse("alice@" + testenv.RealmName)
		if err != nil {
			t.Fatal(err)
		}
		record, ok, err := store.Lookup(*name)
		if err != nil || !ok {
			t.Fatalf("lookup dumped alice: %v, %v", err, ok)
		}
		if len(record.PasswordHistory) != 2 {
			t.Fatalf("MIT password history entries = %d, want 2", len(record.PasswordHistory))
		}
		if record.Policy != "history-policy" {
			t.Fatalf("MIT password policy = %q, want history-policy", record.Policy)
		}
		if record.AdminHistoryKVNO == 0 {
			t.Fatal("MIT history KVNO was not decoded")
		}

		db := kdb.NewDatabase(testenv.RealmName)
		if err := db.AddPrincipal("alice", "placeholder"); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdatePrincipal(record); err != nil {
			t.Fatal(err)
		}
		err = db.ChangePasswordWithPolicy(*name, "alice-password",
			time.Now().UTC(), &kdb.PolicyRecord{Name: "history-policy", HistoryNum: 3}, true)
		if err != kdb.ErrPasswordReuse {
			t.Fatalf("Go history reuse error = %v, want %v", err, kdb.ErrPasswordReuse)
		}
	})

	t.Run("GoToMIT", func(t *testing.T) {
		mitRealm := testenv.Start(t)
		mitRealm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
			"addpol -minlength 1 -history 3 history-policy")
		db := kdb.NewDatabase(testenv.RealmName)
		if err := db.AddPrincipal("kadmin/history", "go-history-key", 2); err != nil {
			t.Fatal(err)
		}
		if err := db.AddPrincipal("history-user", "go-history-1"); err != nil {
			t.Fatal(err)
		}
		name, err := principal.Parse("history-user@" + testenv.RealmName)
		if err != nil {
			t.Fatal(err)
		}
		record, ok, err := db.Lookup(*name)
		if err != nil || !ok {
			t.Fatalf("lookup history-user: %v, %v", err, ok)
		}
		record.Policy = "history-policy"
		if err := db.UpdatePrincipal(record); err != nil {
			t.Fatal(err)
		}
		policy := &kdb.PolicyRecord{Name: "history-policy", HistoryNum: 3}
		if err := db.ChangePasswordWithPolicy(*name, "go-history-2",
			time.Now().UTC(), policy, true); err != nil {
			t.Fatal(err)
		}
		if err := db.ChangePasswordWithPolicy(*name, "go-history-3",
			time.Now().UTC().Add(time.Second), policy, true); err != nil {
			t.Fatal(err)
		}
		dump, err := mitdump.Dump(db, testenv.MasterKey)
		if err != nil {
			t.Fatalf("dump Go history database: %v", err)
		}
		dumpPath := filepath.Join(mitRealm.Dir, "go-history.dump")
		if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
			t.Fatal(err)
		}
		mitRealm.Run(t, "", "/usr/sbin/kdb5_util", "load", "-update", dumpPath)

		cmd := exec.Command("/usr/sbin/kadmin.local", "-q",
			"cpw -pw go-history-1 history-user")
		cmd.Env = []string{"KRB5_CONFIG=" + mitRealm.Config,
			"KRB5_KDC_PROFILE=" + mitRealm.KDCConfig}
		output, err := cmd.CombinedOutput()
		if !strings.Contains(string(output), "Cannot reuse password") {
			t.Fatalf("MIT password reuse output = %s", output)
		}
	})
}

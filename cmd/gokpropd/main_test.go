package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestParsePropdArgsDefaults(t *testing.T) {
	options, err := parsePropdArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.Port != "754" || options.ReplicaFile != defaultKPropdFile ||
		options.ACL != defaultKPropdACL || options.KDBUtil != "" ||
		options.RunOnce || options.NoDaemon || options.Standalone {
		t.Fatalf("defaults = %#v", options)
	}
}

func TestParsePropdArgsExplicitValues(t *testing.T) {
	options, err := parsePropdArgs([]string{"-r", "EXAMPLE.COM", "-s", "kt",
		"-d", "-D", "-S", "-f", "replica", "-F", "db", "-p", "loader",
		"-x", "foo", "-x", "bar", "-P", "1754", "-a", "acl", "-A", "admin",
		"--pid-file", "pid", "-t"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Realm != "EXAMPLE.COM" || options.Keytab != "kt" ||
		!options.Debug || !options.NoDaemon || !options.Standalone ||
		options.ReplicaFile != "replica" || options.Database != "db" ||
		options.KDBUtil != "loader" || options.Port != "1754" ||
		options.ACL != "acl" || options.AdminServer != "admin" ||
		options.PIDFile != "pid" || !options.RunOnce ||
		!reflect.DeepEqual(options.DBArgs, []string{"foo", "bar"}) {
		t.Fatalf("options = %#v", options)
	}
}

func TestLoadACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kpropd.acl")
	if err := os.WriteFile(path, []byte("# comment\nmaster@EXAMPLE.COM aes256-cts\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authorize, err := loadACL(path)
	if err != nil {
		t.Fatal(err)
	}
	allowed := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"master"}}
	if err := authorize(allowed); err != nil {
		t.Fatalf("authorized principal rejected: %v", err)
	}
	denied := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"other"}}
	if err := authorize(denied); err == nil {
		t.Fatal("unauthorized principal accepted")
	}
}

func TestBuildLoadArgs(t *testing.T) {
	got := buildLoadArgs(propdOptions{
		Realm: "EXAMPLE.COM", Database: "db", ReplicaFile: "replica",
		DBArgs: []string{"a", "b"},
	})
	want := []string{"-r", "EXAMPLE.COM", "load", "-d", "db", "-x", "a", "-x", "b", "replica"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("load args = %#v, want %#v", got, want)
	}
}

func TestLocalIpropPrincipalCanonicalizesHostname(t *testing.T) {
	cfg := &config.Config{
		DNSCanonicalizeHostname: "false",
		QualifyShortname:        "example.test",
		QualifyShortnameSet:     true,
	}
	p, err := localIpropPrincipalForHost(context.Background(), cfg,
		"EXAMPLE.COM", "Replica")
	if err != nil {
		t.Fatal(err)
	}
	want := "kiprop/replica.example.test@EXAMPLE.COM"
	if got := p.String(); got != want {
		t.Fatalf("principal = %q, want %q", got, want)
	}
}

func TestOpenReplicaUlogPersistsCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replica.ulog")
	ulog, cursor, err := openReplicaUlog(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != (iprop.Last{}) {
		t.Fatalf("initial cursor = %#v", cursor)
	}
	if err := ulog.AddUpdate(iprop.Update{
		PrincipalName: "alice@EXAMPLE.COM", EntrySno: 7,
		Time: iprop.Time{Seconds: 12}, Commit: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ulog.Close(); err != nil {
		t.Fatal(err)
	}
	ulog, cursor, err = openReplicaUlog(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer ulog.Close()
	if cursor.LastSno != 7 || cursor.LastTime.Seconds != 12 {
		t.Fatalf("reopened cursor = %#v", cursor)
	}
}

func TestReplicaBackoffMatchesMITInitialBusyDelay(t *testing.T) {
	count := 1
	if got := ipropBackoff(&count); got != 4*time.Second {
		t.Fatalf("backoff = %s, want 4s", got)
	}
}

func TestLoadReceivedDumpInProcess(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.AddPrincipal("master@EXAMPLE.COM", "password"); err != nil {
		t.Fatal(err)
	}
	data, err := mitdump.Dump(db, "master-password")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	options := propdOptions{
		ReplicaFile: filepath.Join(dir, "from_master"),
		Database:    filepath.Join(dir, "principal"),
	}
	if err := loadReceivedDump(bytes.NewReader(data), uint64(len(data)), options); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(options.Database)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("in-process load did not replace database")
	}
}

func TestServeOneGoToGoTransfer(t *testing.T) {
	const realm = "EXAMPLE.COM"
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst,
		Components: []string{"host", "replica"},
	}
	user := principal.Principal{
		Realm: realm, NameType: principal.NTEnterprise,
		Components: []string{"master"},
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey := bytes.Repeat([]byte{0x31}, etype.KeySize())
	sessionKey := bytes.Repeat([]byte{0x42}, etype.KeySize())
	now := time.Now().UTC()
	end := types.KerberosTime{Time: now.Add(time.Hour), Present: true}
	ticketPart := protocol.EncTicketPart{
		Flags: types.TicketInitial, Key: protocol.EncryptionKey{
			KeyType: etype.ID(), KeyValue: sessionKey,
		},
		CRealm: realm,
		CName: protocol.PrincipalName{
			NameType: int32(user.NameType), NameString: user.Components,
		},
		AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: end,
	}
	ticketPlain, err := asn1.Marshal(ticketPart)
	if err != nil {
		t.Fatal(err)
	}
	ticketCipher, err := etype.Encrypt(serviceKey, 2, ticketPlain)
	if err != nil {
		t.Fatal(err)
	}
	ticketDER, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: realm,
		SName: protocol.PrincipalName{
			NameType: int32(service.NameType), NameString: service.Components,
		},
		EncPart: protocol.EncryptedData{
			EType: etype.ID(), Cipher: ticketCipher,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := &client.Credentials{
		Client: user, Server: service,
		Key:    protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: sessionKey},
		Ticket: ticketDER,
	}
	payload := []byte("small MIT dump")
	var loaded []byte
	server := &kprop.Server{
		Keytab: &keytab.Keytab{Entries: []keytab.Entry{{
			Principal: service, KVNO: 1, Enctype: etype.ID(), Key: serviceKey,
		}}},
		Realm: realm,
		Authorize: func(got principal.Principal) error {
			if got.String() != user.String() {
				t.Fatalf("authorized principal = %s", got)
			}
			return nil
		},
		Load: func(reader io.Reader, size uint64) error {
			var err error
			loaded, err = io.ReadAll(reader)
			if err != nil {
				return err
			}
			if uint64(len(loaded)) != size {
				t.Fatalf("loaded size = %d, want %d", len(loaded), size)
			}
			return nil
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveOne(listener, server) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := kprop.Send(context.Background(), conn, credentials,
		bytes.NewReader(payload), uint64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if !bytes.Equal(loaded, payload) {
		t.Fatalf("loaded payload = %q, want %q", loaded, payload)
	}
}

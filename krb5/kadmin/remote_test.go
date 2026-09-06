package kadmin

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestRemoteEngineAgainstKadm5Server(t *testing.T) {
	const realm = "TEST.REALM"
	kt, creds := remoteTestCredentials(t, realm)
	db := kdb.NewDatabase(realm)
	if err := db.AddPrincipal("admin/admin@"+realm, "unused", 1); err != nil {
		t.Fatal(err)
	}
	server := kadm5.NewServer(db, kt)
	server.AdminPrincipal = creds.Client
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.Serve(listener) }()
	rpc, err := kadm5.Dial(t.Context(), nil, creds.Client, creds, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.Close()
	var out, errOut bytes.Buffer
	engine := New(Config{
		Ops: NewRemote(rpc, realm), Realm: realm, Stdout: &out, Stderr: &errOut,
	})
	if _, err := engine.Execute("addprinc -pw initial alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Execute("getprinc alice"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Principal: alice@"+realm)) {
		t.Fatalf("getprinc output = %q", out.String())
	}
	if _, err := engine.Execute("cpw -pw changed alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Execute("listprincs"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("alice@"+realm)) {
		t.Fatalf("listprincs output = %q", out.String())
	}
}

func remoteTestCredentials(t *testing.T, realm string) (*keytab.Keytab, *client.Credentials) {
	t.Helper()
	const enctype = crypto.EnctypeAES128SHA1
	etype, err := crypto.NewRegistry().Get(enctype)
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: realm, NameType: principal.NTSrvInstance, Components: []string{"kadmin", "admin"}}
	admin := principal.Principal{Realm: realm, NameType: principal.NTPrincipal, Components: []string{"admin", "admin"}}
	serviceKey := make([]byte, etype.KeySize())
	sessionKey := make([]byte, etype.KeySize())
	if _, err := rand.Read(serviceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(time.Hour)
	part, err := asn1.Marshal(protocol.EncTicketPart{
		Key:    protocol.EncryptionKey{KeyType: enctype, KeyValue: sessionKey},
		CRealm: realm, CName: protocol.PrincipalName{
			NameType: int32(admin.NameType), NameString: admin.Components,
		},
		AuthTime: types.KerberosTime{Time: now, Present: true},
		EndTime:  types.KerberosTime{Time: end, Present: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := etype.Encrypt(serviceKey, 2, part)
	if err != nil {
		t.Fatal(err)
	}
	kvno := uint32(1)
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: realm,
		SName: protocol.PrincipalName{
			NameType: int32(service.NameType), NameString: service.Components,
		},
		EncPart: protocol.EncryptedData{EType: enctype, KVNO: &kvno, Cipher: cipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &keytab.Keytab{Entries: []keytab.Entry{{
			Principal: service, KVNO: kvno, Enctype: enctype, Key: serviceKey,
		}}}, &client.Credentials{
			Client: admin, Server: service,
			Key:      protocol.EncryptionKey{KeyType: enctype, KeyValue: sessionKey},
			AuthTime: types.KerberosTime{Time: now, Present: true},
			EndTime:  types.KerberosTime{Time: end, Present: true},
			Ticket:   ticket,
		}
}

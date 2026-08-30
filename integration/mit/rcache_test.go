//go:build integration

package mit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/rcache"
)

func TestMITFile2ReplayCacheAgainstGo(t *testing.T) {
	python := requirePythonGSSAPI(t)
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	kclient := &client.Client{Config: cfg, Now: func() time.Time { return now }}
	clientPrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	tgt, err := kclient.ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service, err := kclient.TGSExchange(context.Background(), tgt, principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := gssapi.NewInitiator(service, gssapi.GSSMutualFlag)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	keytabFile, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatal(err)
	}
	kt, err := keytab.Read(keytabFile)
	_ = keytabFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(realm.Dir, "mit.rcache2")
	t.Setenv("KRB5RCACHENAME", "file2:"+cachePath)
	peer := startPythonSPNEGOPeer(t, python, realm, "kerberos-accept")
	defer peer.close()
	if _, err := peer.step(token); err != nil {
		t.Fatal(err)
	}
	cache := &rcache.File2{Path: cachePath}
	acceptor := gssapi.NewAcceptorWithOptions(kt, gssapi.AcceptorOptions{ReplayCache: cache})
	if _, _, err := acceptor.Accept(token, now); !errors.Is(err, krberrors.ErrReplay) {
		t.Fatalf("Go accepted MIT-consumed AP token: %v", err)
	}
}

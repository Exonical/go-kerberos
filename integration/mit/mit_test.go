//go:build integration

package mit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestHarnessSelfTest(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	output := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", realm.Cache)
	t.Logf("MIT klist output:\n%s", output)
	if !strings.Contains(output, testenv.RealmName) {
		t.Fatalf("klist output does not mention realm %s", testenv.RealmName)
	}
	if _, err := os.Stat(realm.Keytab); err != nil {
		t.Fatalf("generated keytab: %v", err)
	}
	if _, err := os.Stat(realm.Cache); err != nil {
		t.Fatalf("generated ccache: %v", err)
	}
}

func TestMITKeytabToGoParser(t *testing.T) {
	realm := testenv.Start(t)
	file, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatalf("open MIT keytab: %v", err)
	}
	defer file.Close()
	if _, err := keytab.Read(file); err != nil {
		t.Fatalf("Go keytab parser: %v", err)
	}
}

func TestMITCCacheToGoParser(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	file, err := os.Open(realm.Cache)
	if err != nil {
		t.Fatalf("open MIT ccache: %v", err)
	}
	defer file.Close()
	if _, err := ccache.Read(file); err != nil {
		t.Fatalf("Go ccache parser: %v", err)
	}
}

func TestGoKeytabToMITKlist(t *testing.T) {
	realm := testenv.Start(t)
	outputPath := filepath.Join(realm.Dir, "go.keytab")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go keytab: %v", err)
	}
	kt := &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: principal.Principal{
			Realm:      testenv.RealmName,
			NameType:   principal.NTSrvHst,
			Components: []string{"host", "service.test"},
		},
		KVNO:    1,
		Enctype: 17,
		Key:     []byte{1, 2, 3, 4},
	}}}
	if err := keytab.Write(output, kt); err != nil {
		output.Close()
		t.Fatalf("Go keytab writer: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go keytab: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-k", "-e", outputPath)
	if !strings.Contains(listing, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain generated principal:\n%s", listing)
	}
}

func TestGoCCacheToMITKlist(t *testing.T) {
	realm := testenv.Start(t)
	outputPath := filepath.Join(realm.Dir, "go.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go ccache: %v", err)
	}
	client := principal.Principal{
		Realm:      testenv.RealmName,
		NameType:   principal.NTPrincipal,
		Components: []string{"alice"},
	}
	cache := &ccache.Cache{
		DefaultPrincipal: client,
		Credentials: []ccache.Credential{{
			Client:      client,
			Server:      client,
			TicketFlags: 0x40000000,
			Ticket:      []byte{1, 2},
		}},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("Go ccache writer: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go ccache: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	if !strings.Contains(listing, testenv.RealmName) {
		t.Fatalf("MIT klist does not contain generated ccache realm:\n%s", listing)
	}
}

func TestGoClientASExchange(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	clientPrincipal := principal.Principal{
		Realm:      testenv.RealmName,
		NameType:   principal.NTPrincipal,
		Components: []string{"alice"},
	}
	credentials, err := (&client.Client{
		Config: cfg,
		Now:    func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}).ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}
	outputPath := filepath.Join(realm.Dir, "go-client.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go client ccache: %v", err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: clientPrincipal,
		Credentials:      []ccache.Credential{credentials.ToCCacheCredential()},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("write Go client ccache: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go client ccache: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	if !strings.Contains(listing, "krbtgt/"+testenv.RealmName+"@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain TGT:\n%s", listing)
	}
}

func TestGoClientFASTASExchange(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	clientPrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	kclient := &client.Client{Config: cfg, Now: func() time.Time { return now }}
	armorTGT, err := kclient.ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatalf("Go armor AS exchange: %v", err)
	}
	credentials, err := kclient.ASExchangeFAST(context.Background(), clientPrincipal, "alice-password", armorTGT)
	if err != nil {
		t.Fatalf("Go FAST AS exchange: %v", err)
	}
	outputPath := filepath.Join(realm.Dir, "go-client-fast.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go FAST ccache: %v", err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: clientPrincipal,
		Credentials:      []ccache.Credential{credentials.ToCCacheCredential()},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("write Go FAST ccache: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go FAST ccache: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	if !strings.Contains(listing, "krbtgt/"+testenv.RealmName+"@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain FAST TGT:\n%s", listing)
	}
}

func TestGoClientTGSExchange(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	clientPrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	kclient := &client.Client{
		Config: cfg, Now: func() time.Time { return now },
	}
	tgt, err := kclient.ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}
	servicePrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	serviceTicket, err := kclient.TGSExchange(context.Background(), tgt, servicePrincipal)
	if err != nil {
		t.Fatalf("Go TGS exchange: %v", err)
	}
	outputPath := filepath.Join(realm.Dir, "go-client-tgs.ccache")
	output, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("create Go client ccache: %v", err)
	}
	cache := &ccache.Cache{
		DefaultPrincipal: clientPrincipal,
		Credentials: []ccache.Credential{
			tgt.ToCCacheCredential(), serviceTicket.ToCCacheCredential(),
		},
	}
	if err := ccache.Write(output, cache); err != nil {
		output.Close()
		t.Fatalf("write Go client ccache: %v", err)
	}
	if err := output.Close(); err != nil {
		t.Fatalf("close Go client ccache: %v", err)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", outputPath)
	for _, expected := range []string{
		"krbtgt/" + testenv.RealmName + "@" + testenv.RealmName,
		"host/service.test@" + testenv.RealmName,
	} {
		if !strings.Contains(listing, expected) {
			t.Fatalf("MIT klist does not contain %s:\n%s", expected, listing)
		}
	}
}

func TestGoClientAPExchange(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	clientPrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	kclient := &client.Client{
		Config: cfg, Now: func() time.Time { return now },
	}
	tgt, err := kclient.ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}
	servicePrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	serviceTicket, err := kclient.TGSExchange(context.Background(), tgt, servicePrincipal)
	if err != nil {
		t.Fatalf("Go TGS exchange: %v", err)
	}
	request, _, err := ap.BuildAPReq(serviceTicket, 0, now)
	if err != nil {
		t.Fatalf("Go AP request: %v", err)
	}
	keytabFile, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatalf("open service keytab: %v", err)
	}
	defer keytabFile.Close()
	serviceKeytab, err := keytab.Read(keytabFile)
	if err != nil {
		t.Fatalf("read service keytab: %v", err)
	}
	verified, err := ap.VerifyAPReq(serviceKeytab, request.DER, now, 5*time.Minute)
	if err != nil {
		t.Fatalf("verify Go AP request: %v", err)
	}
	if verified.Client.String() != clientPrincipal.String() {
		t.Fatalf("verified client = %#v, want %#v", verified.Client, clientPrincipal)
	}
}

func TestGoGSSAPIExchange(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := time.Now().UTC()
	clientPrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	kclient := &client.Client{Config: cfg, Now: func() time.Time { return now }}
	tgt, err := kclient.ASExchange(context.Background(), clientPrincipal, "alice-password")
	if err != nil {
		t.Fatalf("Go AS exchange: %v", err)
	}
	servicePrincipal := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	serviceTicket, err := kclient.TGSExchange(context.Background(), tgt, servicePrincipal)
	if err != nil {
		t.Fatalf("Go TGS exchange: %v", err)
	}
	keytabFile, err := os.Open(realm.Keytab)
	if err != nil {
		t.Fatalf("open MIT keytab: %v", err)
	}
	defer keytabFile.Close()
	kt, err := keytab.Read(keytabFile)
	if err != nil {
		t.Fatalf("read MIT keytab: %v", err)
	}
	initiator, err := gssapi.NewInitiator(serviceTicket, gssapi.GSSMutualFlag|gssapi.GSSIntegrityFlag|gssapi.GSSConfidentialityFlag)
	if err != nil {
		t.Fatalf("new GSS initiator: %v", err)
	}
	token, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatalf("GSS initial token: %v", err)
	}
	acceptorContext, mutual, err := gssapi.NewAcceptor(kt).Accept(token, now)
	if err != nil {
		t.Fatalf("GSS accept: %v", err)
	}
	if err := initiator.VerifyToken(mutual); err != nil {
		t.Fatalf("GSS mutual auth: %v", err)
	}
	message := []byte("GSS interoperability")
	wrapped, err := initiator.Wrap(message, true)
	if err != nil {
		t.Fatalf("GSS initiator wrap: %v", err)
	}
	if got, err := acceptorContext.Unwrap(wrapped); err != nil || !strings.EqualFold(string(got), string(message)) {
		t.Fatalf("GSS acceptor unwrap: got %q, err %v", got, err)
	}
	reply, err := acceptorContext.Wrap(message, false)
	if err != nil {
		t.Fatalf("GSS acceptor wrap: %v", err)
	}
	if got, err := initiator.Unwrap(reply); err != nil || !strings.EqualFold(string(got), string(message)) {
		t.Fatalf("GSS initiator unwrap: got %q, err %v", got, err)
	}
	mic, err := initiator.MIC(message)
	if err != nil {
		t.Fatalf("GSS initiator MIC: %v", err)
	}
	if err := acceptorContext.VerifyMIC(message, mic); err != nil {
		t.Fatalf("GSS acceptor MIC: %v", err)
	}
	mic, err = acceptorContext.MIC(message)
	if err != nil {
		t.Fatalf("GSS acceptor MIC: %v", err)
	}
	if err := initiator.VerifyMIC(message, mic); err != nil {
		t.Fatalf("GSS initiator MIC: %v", err)
	}
}

func TestGoKinitInterop(t *testing.T) {
	realm := testenv.Start(t)
	binaryPath := filepath.Join(realm.Dir, "gokinit")
	realm.Run(t, "", "/usr/local/go/bin/go", "build", "-o", binaryPath, "../../cmd/gokinit")
	realm.Run(t, "alice-password\n", binaryPath, "-c", realm.Cache, "alice")
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", realm.Cache)
	if !strings.Contains(listing, "krbtgt/"+testenv.RealmName+"@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain gokinit TGT:\n%s", listing)
	}
}

func TestGoKlistInterop(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	binaryPath := filepath.Join(realm.Dir, "goklist")
	realm.Run(t, "", "/usr/local/go/bin/go", "build", "-o", binaryPath, "../../cmd/goklist")
	listing := realm.Run(t, "", binaryPath, "-c", realm.Cache, "-e")
	for _, expected := range []string{
		"Default principal: alice@" + testenv.RealmName,
		"krbtgt/" + testenv.RealmName + "@" + testenv.RealmName,
		"aes256-cts-hmac-sha1-96",
	} {
		if !strings.Contains(listing, expected) {
			t.Fatalf("goklist output does not contain %q:\n%s", expected, listing)
		}
	}
}

func TestGoKVNOInterop(t *testing.T) {
	realm := testenv.Start(t)
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", realm.Cache, "alice")
	binaryPath := filepath.Join(realm.Dir, "gokvno")
	realm.Run(t, "", "/usr/local/go/bin/go", "build", "-o", binaryPath, "../../cmd/gokvno")
	output := realm.Run(t, "", binaryPath, "-c", realm.Cache, "host/service.test")
	if !strings.Contains(output, "host/service.test@"+testenv.RealmName+": kvno = ") {
		t.Fatalf("gokvno output does not contain service ticket:\n%s", output)
	}
	listing := realm.Run(t, "", "/usr/bin/klist", "-e", "-c", realm.Cache)
	if !strings.Contains(listing, "host/service.test@"+testenv.RealmName) {
		t.Fatalf("MIT klist does not contain gokvno service ticket:\n%s", listing)
	}
}

func TestFixturePathsRemainStable(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "testdata", "keytabs"),
		filepath.Join(root, "testdata", "ccaches"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("fixture directory %s: %v", path, err)
		}
	}
}

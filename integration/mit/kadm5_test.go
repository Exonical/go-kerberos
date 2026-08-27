//go:build integration

package mit_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoKadm5AdministrativeSubsetAgainstMIT(t *testing.T) {
	realm := testenv.Start(t)
	data, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	now := func() time.Time { return time.Now().UTC().Truncate(time.Second) }
	k := &client.Client{Config: cfg, Now: now}
	admin := principal.Principal{Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"admin", "admin"}}
	service := principal.Principal{Realm: testenv.RealmName, NameType: principal.NTSrvInstance, Components: []string{"kadmin", "admin"}}
	creds, err := k.ASExchangeService(context.Background(), admin, "admin-password", service)
	if err != nil {
		t.Fatalf("obtain admin credentials: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", realm.AdminPort)
	a, err := kadm5.Dial(context.Background(), k, admin, creds, addr)
	if err != nil {
		t.Fatalf("connect kadmind: %v", err)
	}
	defer a.Close()
	target := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal,
		Components: []string{"kadm5-test"},
	}
	if err := a.CreatePrincipal(context.Background(), target, "temporary-password"); err != nil {
		t.Fatalf("create principal: %v", err)
	}
	entry, err := a.GetPrincipal(context.Background(), target)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if entry.Principal.String() != target.String() {
		t.Fatalf("got principal %q, want %q", entry.Principal, target)
	}
	if err := a.ChangePassword(context.Background(), target, "changed-password"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, err := k.ASExchange(context.Background(), target, "changed-password"); err != nil {
		t.Fatalf("AS exchange with changed password: %v", err)
	}
	if err := a.DeletePrincipal(context.Background(), target); err != nil {
		t.Fatalf("delete principal: %v", err)
	}
	if _, err := a.GetPrincipal(context.Background(), target); !errors.Is(err, kadm5.ErrNotFound) {
		t.Fatalf("get deleted principal error = %v, want ErrNotFound", err)
	}
}

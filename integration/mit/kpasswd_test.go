//go:build integration

package mit_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kpasswd"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestGoClientChangesPasswordAgainstMITKadmind(t *testing.T) {
	realm := testenv.Start(t)
	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read realm config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse realm config: %v", err)
	}
	now := func() time.Time { return time.Now().UTC().Truncate(time.Second) }
	goClient := &client.Client{Config: cfg, Now: now}
	alice := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal,
		Components: []string{"alice"},
	}
	_, err = goClient.ASExchange(context.Background(), alice, "alice-password")
	if err != nil {
		t.Fatalf("initial Go AS exchange: %v", err)
	}
	if err := (&kpasswd.Client{Kerberos: goClient}).ChangePassword(context.Background(), alice, "alice-password", "alice-new-password"); err != nil {
		t.Fatalf("Go RFC 3244 password change: %v", err)
	}
	if _, err := goClient.ASExchange(context.Background(), alice, "alice-new-password"); err != nil {
		t.Fatalf("Go AS exchange with changed password: %v", err)
	}
}

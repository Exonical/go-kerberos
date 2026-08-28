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

func TestGoKadm5CommonOperationsAgainstMIT(t *testing.T) {
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
	a, err := kadm5.Dial(context.Background(), k, admin, creds, fmt.Sprintf("127.0.0.1:%d", realm.AdminPort))
	if err != nil {
		t.Fatalf("connect kadmind: %v", err)
	}
	defer a.Close()

	ctx := context.Background()
	name := "kadm5-ops"
	renamed := "kadm5-ops-renamed"
	policyName := "kadm5-ops-policy"
	target := principal.Principal{Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{name}}
	targetRenamed := principal.Principal{Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{renamed}}
	if err := a.CreatePrincipal(ctx, target, "temporary-password"); err != nil {
		t.Fatalf("create principal: %v", err)
	}
	defer func() { _ = a.DeletePrincipal(ctx, targetRenamed); _ = a.DeletePrincipal(ctx, target) }()

	entry, err := a.GetPrincipal(ctx, target)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	entry.Attributes |= 1
	entry.MaxLife = 3600
	if err := a.ModifyPrincipal(ctx, entry, kadm5.KADM5Attributes|kadm5.KADM5MaxLife); err != nil {
		t.Fatalf("modify principal: %v", err)
	}
	entry, err = a.GetPrincipal(ctx, target)
	if err != nil {
		t.Fatalf("get modified principal: %v", err)
	}
	if entry.Attributes&1 == 0 || entry.MaxLife != 3600 {
		t.Fatalf("modified entry = %+v", entry)
	}
	if err := a.RenamePrincipal(ctx, target, targetRenamed); err != nil {
		t.Fatalf("rename principal: %v", err)
	}
	if _, err := a.GetPrincipal(ctx, target); !errors.Is(err, kadm5.ErrNotFound) {
		t.Fatalf("get old principal error = %v, want ErrNotFound", err)
	}
	keys, err := a.RandKey(ctx, targetRenamed)
	if err != nil {
		t.Fatalf("randomize principal key: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("randomize principal returned no keys")
	}
	for _, key := range keys {
		if key.Enctype == 0 || len(key.Key) == 0 {
			t.Fatalf("invalid returned key: enctype=%d length=%d", key.Enctype, len(key.Key))
		}
	}

	policy := kadm5.Policy{
		Name: policyName, MinLife: 0, MaxLife: 0, MinLength: 8,
		MinClasses: 1, HistoryNum: 1, MaxFailure: 3,
		FailureCountInterval: 300, LockoutDuration: 600,
	}
	policyMask := kadm5.KADM5Policy | kadm5.KADM5PWMinLength |
		kadm5.KADM5PWMinClasses | kadm5.KADM5PWHistoryNum |
		kadm5.KADM5PWMaxFailure | kadm5.KADM5PWFailureCountInterval |
		kadm5.KADM5PWLockoutDuration
	if err := a.CreatePolicy(ctx, policy, policyMask); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	defer func() { _ = a.DeletePolicy(ctx, policyName) }()
	gotPolicy, err := a.GetPolicy(ctx, policyName)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if gotPolicy.Name != policyName || gotPolicy.MinLength != policy.MinLength ||
		gotPolicy.MaxFailure != policy.MaxFailure {
		t.Fatalf("policy = %+v", gotPolicy)
	}
	policy.MinLength = 10
	if err := a.ModifyPolicy(ctx, policy, kadm5.KADM5PWMinLength); err != nil {
		t.Fatalf("modify policy: %v", err)
	}
	gotPolicy, err = a.GetPolicy(ctx, policyName)
	if err != nil || gotPolicy.MinLength != policy.MinLength {
		t.Fatalf("modified policy = %+v, err=%v", gotPolicy, err)
	}
	policies, err := a.ListPolicies(ctx, policyName)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	found := false
	for _, name := range policies {
		if name == policyName {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy list %v does not contain %q", policies, policyName)
	}
	entry, err = a.GetPrincipal(ctx, targetRenamed)
	if err != nil {
		t.Fatalf("get renamed principal: %v", err)
	}
	entry.Policy = policyName
	if err := a.ModifyPrincipal(ctx, entry, kadm5.KADM5Policy); err != nil {
		t.Fatalf("attach policy: %v", err)
	}
	entry, err = a.GetPrincipal(ctx, targetRenamed)
	if err != nil || entry.Policy != policyName {
		t.Fatalf("attached policy entry = %+v, err=%v", entry, err)
	}
	second := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal,
		Components: []string{"kadm5-ops-second"},
	}
	if err := a.CreatePrincipal(ctx, second, "second-password"); err != nil {
		t.Fatalf("create second principal: %v", err)
	}
	principals, err := a.ListPrincipals(ctx, "kadm5-ops*")
	if err != nil {
		t.Fatalf("list principals: %v", err)
	}
	foundRenamed, foundSecond := false, false
	for _, name := range principals {
		if name == targetRenamed.String() {
			foundRenamed = true
		}
		if name == second.String() {
			foundSecond = true
		}
	}
	if !foundRenamed || !foundSecond {
		t.Fatalf("principal list %v missing %q or %q", principals, targetRenamed, second)
	}
	if err := a.DeletePrincipal(ctx, second); err != nil {
		t.Fatalf("delete second principal: %v", err)
	}
	if _, err := a.GetPrivs(ctx); err != nil {
		t.Fatalf("get privileges: %v", err)
	}
	entry.Policy = ""
	if err := a.ModifyPrincipal(ctx, entry, kadm5.KADM5PolicyClear); err != nil {
		t.Fatalf("detach policy: %v", err)
	}
	if err := a.DeletePolicy(ctx, policyName); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if err := a.DeletePrincipal(ctx, targetRenamed); err != nil {
		t.Fatalf("delete principal: %v", err)
	}
	if _, err := a.GetPrincipal(ctx, targetRenamed); !errors.Is(err, kadm5.ErrNotFound) {
		t.Fatalf("get deleted principal error = %v, want ErrNotFound", err)
	}
}

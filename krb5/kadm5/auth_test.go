package kadm5

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

type authTestModule struct {
	name     string
	decision AuthDecision
}

func (m authTestModule) Name() string { return m.name }
func (m authTestModule) AuthGetPrinc(principal.Principal, principal.Principal) AuthDecision {
	return m.decision
}

type authRestrictionModule struct{}

func (authRestrictionModule) Name() string { return "restriction" }
func (authRestrictionModule) AuthAddPrinc(_ principal.Principal, _ principal.Principal,
	_ *PrincipalEntry, _ int64) (AuthDecision, *AuthRestrictions) {
	return AuthAuthorize, &AuthRestrictions{
		Mask:             int64(KADM5Attributes | KADM5Policy | KADM5PrincExpireTime | KADM5PWExpiration | KADM5MaxLife | KADM5MaxRenewableLife),
		RequireAttrs:     0x02,
		ForbidAttrs:      0x04,
		PrincLifetime:    100,
		PWLifetime:       200,
		MaxLife:          300,
		MaxRenewableLife: 400,
		Policy:           "restricted",
	}
}

func authTestPrincipal(t *testing.T, value string) principal.Principal {
	t.Helper()
	p, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func TestAuthCombinationSemantics(t *testing.T) {
	client := authTestPrincipal(t, "admin@EXAMPLE.COM")
	target := authTestPrincipal(t, "user@EXAMPLE.COM")
	tests := []struct {
		name    string
		modules []AuthModule
		want    bool
	}{
		{
			name:    "authorize and deny",
			modules: []AuthModule{authTestModule{"allow", AuthAuthorize}, authTestModule{"deny", AuthDeny}},
		},
		{
			name:    "pass only",
			modules: []AuthModule{authTestModule{"pass", AuthPass}},
		},
		{
			name:    "authorize without deny",
			modules: []AuthModule{authTestModule{"pass", AuthPass}, authTestModule{"allow", AuthAuthorize}},
			want:    true,
		},
		{
			name:    "unknown decision denies",
			modules: []AuthModule{authTestModule{"unknown", AuthDecision(99)}, authTestModule{"allow", AuthAuthorize}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{AuthModules: test.modules}
			if got := server.authorizeRequest(authRequest{
				operation: "get", client: client, target: target,
			}); got != test.want {
				t.Fatalf("authorization = %v, want %v", got, test.want)
			}
		})
	}
}

func TestApplyAuthRestrictions(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()
	entry := PrincipalEntry{
		Attributes:       0x07,
		PrincExpireTime:  2_000,
		PWExpiration:     2_000,
		MaxLife:          600,
		MaxRenewableLife: 700,
	}
	mask := int64(KADM5Attributes | KADM5PrincExpireTime | KADM5PWExpiration |
		KADM5MaxLife | KADM5MaxRenewableLife)
	ApplyAuthRestrictions(&entry, &mask, &AuthRestrictions{
		Mask:             int64(KADM5Attributes | KADM5PrincExpireTime | KADM5PWExpiration | KADM5MaxLife | KADM5MaxRenewableLife),
		RequireAttrs:     0x08,
		ForbidAttrs:      0x02,
		PrincLifetime:    100,
		PWLifetime:       200,
		MaxLife:          300,
		MaxRenewableLife: 400,
	}, now)
	if entry.Attributes != 0x0d || entry.PrincExpireTime != 1_100 ||
		entry.PWExpiration != 1_200 || entry.MaxLife != 300 ||
		entry.MaxRenewableLife != 400 {
		t.Fatalf("restriction result = %#v", entry)
	}
	for _, bit := range []int32{KADM5Attributes, KADM5PrincExpireTime,
		KADM5PWExpiration, KADM5MaxLife, KADM5MaxRenewableLife} {
		if mask&int64(bit) == 0 {
			t.Fatalf("restriction did not set mask bit %#x", bit)
		}
	}
	entry.Policy = "old"
	mask = int64(KADM5Policy)
	ApplyAuthRestrictions(&entry, &mask, &AuthRestrictions{
		Mask:   int64(KADM5PolicyClear),
		Policy: "ignored",
	}, now)
	if entry.Policy != "" || mask&int64(KADM5PolicyClear) == 0 ||
		mask&int64(KADM5Policy) != 0 {
		t.Fatalf("policy clear result policy=%q mask=%#x", entry.Policy, mask)
	}
}

func TestSelfAuthModule(t *testing.T) {
	self := authTestPrincipal(t, "alice@EXAMPLE.COM")
	other := authTestPrincipal(t, "bob@EXAMPLE.COM")
	module := SelfAuthModule{}
	for _, operation := range []string{"change-password", "randkey", "purgekeys", "get", "get-strings"} {
		if decision, _ := authDecision(module, authRequest{
			operation: operation, client: self, target: self,
		}); decision != AuthAuthorize {
			t.Fatalf("%s self decision = %v", operation, decision)
		}
		if decision, _ := authDecision(module, authRequest{
			operation: operation, client: self, target: other,
		}); decision != AuthPass {
			t.Fatalf("%s other decision = %v", operation, decision)
		}
	}
	if module.AuthGetPol(self, "users", "users") != AuthAuthorize ||
		module.AuthGetPol(self, "admins", "users") != AuthPass {
		t.Fatal("self policy authorization mismatch")
	}
}

func TestACLAuthModuleOperationMappings(t *testing.T) {
	client := authTestPrincipal(t, "admin@EXAMPLE.COM")
	source := authTestPrincipal(t, "source@EXAMPLE.COM")
	destination := authTestPrincipal(t, "destination@EXAMPLE.COM")
	var operations []string
	module := ACLAuthModule{Check: func(_ principal.Principal, operation string, target principal.Principal) bool {
		operations = append(operations, operation)
		return target.Components[0] != "blocked"
	}}
	if module.AuthRenPrinc(client, source, destination) != AuthAuthorize {
		t.Fatal("rename should require delete and add")
	}
	if len(operations) != 2 || operations[0] != "delete" || operations[1] != "create" {
		t.Fatalf("rename operations = %#v", operations)
	}
	operations = nil
	if module.AuthAddAlias(client, source, destination) != AuthAuthorize {
		t.Fatal("alias should require add and modify")
	}
	if len(operations) != 2 || operations[0] != "create" || operations[1] != "modify" {
		t.Fatalf("alias operations = %#v", operations)
	}
}

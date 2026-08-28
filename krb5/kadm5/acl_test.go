package kadm5

import (
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func aclPrincipal(t *testing.T, name string) principal.Principal {
	t.Helper()
	p, err := principal.Parse(name)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func TestParseACLPermissionsAndFirstMatch(t *testing.T) {
	acl, err := ParseACL(strings.NewReader(`
# comments and blank lines are ignored
admin/admin@EXAMPLE.COM aAd
admin/admin@EXAMPLE.COM *
`))
	if err != nil {
		t.Fatal(err)
	}
	client := aclPrincipal(t, "admin/admin@EXAMPLE.COM")
	target := aclPrincipal(t, "user@EXAMPLE.COM")
	if acl.Check(client, "create", target) {
		t.Fatal("uppercase A did not deny add")
	}
	if !acl.Check(client, "delete", target) {
		t.Fatal("lowercase d did not grant delete")
	}
	if acl.Check(client, "modify", target) {
		t.Fatal("later ACL entry overrode the first matching entry")
	}

	acl, err = ParseACL(strings.NewReader(
		"admin/admin@EXAMPLE.COM, a\n" +
			"admin/admin@EXAMPLE.COM a\\\n" +
			"d\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !acl.Check(client, "create", target) {
		t.Fatal("comma-separated ACL fields did not parse")
	}
}

func TestACLPermissionsShorthandAndExtraction(t *testing.T) {
	acl, err := ParseACL(strings.NewReader("* *\n"))
	if err != nil {
		t.Fatal(err)
	}
	client := aclPrincipal(t, "admin@EXAMPLE.COM")
	target := aclPrincipal(t, "host/server@EXAMPLE.COM")
	for _, operation := range []string{
		"create", "delete", "modify", "change-password", "get", "list",
		"set-key",
	} {
		if !acl.Check(client, operation, target) {
			t.Fatalf("ACL * did not grant %s", operation)
		}
	}
	if acl.Check(client, "extract-keys", target) {
		t.Fatal("ACL * unexpectedly granted extraction")
	}
	acl, err = ParseACL(strings.NewReader("* e\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !acl.Check(client, "extract-keys", target) {
		t.Fatal("ACL e did not grant extraction")
	}
	if !acl.Check(client, "get-privs", target) {
		t.Fatal("get-privs should not require an ACL grant")
	}
}

func TestACLComponentWildcardsAndTargetBackreferences(t *testing.T) {
	acl, err := ParseACL(strings.NewReader(
		`*/admin@EXAMPLE.COM i *1/service@EXAMPLE.COM
`))
	if err != nil {
		t.Fatal(err)
	}
	client := aclPrincipal(t, "alice/admin@EXAMPLE.COM")
	if !acl.Check(client, "get", aclPrincipal(t, "alice/service@EXAMPLE.COM")) {
		t.Fatal("target backreference did not match")
	}
	if acl.Check(client, "get", aclPrincipal(t, "bob/service@EXAMPLE.COM")) {
		t.Fatal("target backreference matched the wrong component")
	}
	if acl.Check(client, "get", aclPrincipal(t, "alice/service/http@EXAMPLE.COM")) {
		t.Fatal("component wildcard changed the principal component count")
	}

	acl, err = ParseACL(strings.NewReader(
		`*/admin@EXAMPLE.COM i */service@EXAMPLE.COM
`))
	if err != nil {
		t.Fatal(err)
	}
	if !acl.Check(client, "get", aclPrincipal(t, "alice/service@EXAMPLE.COM")) {
		t.Fatal("target component wildcard did not match")
	}
}

func TestParseACLRejectsMalformedEntriesAndRestrictions(t *testing.T) {
	for _, input := range []string{
		"admin/admin@EXAMPLE.COM\n",
		"admin/admin@EXAMPLE.COM q\n",
		"admin/admin@EXAMPLE.COM i user@EXAMPLE.COM -maxlife 1h\n",
		"admin/admin@EXAMPLE.COM i not-a-principal\n",
	} {
		if _, err := ParseACL(strings.NewReader(input)); err == nil {
			t.Fatalf("ParseACL accepted %q", input)
		}
	}
}

func TestACLSelfPasswordChange(t *testing.T) {
	acl, err := ParseACL(strings.NewReader("* i\n"))
	if err != nil {
		t.Fatal(err)
	}
	self := aclPrincipal(t, "user@EXAMPLE.COM")
	if !acl.Check(self, "change-password", self) ||
		!acl.Check(self, "randkey", self) {
		t.Fatal("ACL self key change was denied")
	}

	server := &Server{ACL: func(principal.Principal, string, principal.Principal) bool {
		return false
	}}
	if !server.authorize(self, "change-password", self) {
		t.Fatal("self password change was denied")
	}
	other := aclPrincipal(t, "other@EXAMPLE.COM")
	if server.authorize(self, "change-password", other) {
		t.Fatal("password change for another principal was allowed")
	}
}

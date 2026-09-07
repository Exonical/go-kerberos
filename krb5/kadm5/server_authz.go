package kadm5

import (
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func (s *Server) authorize(client principal.Principal, op string, target principal.Principal) bool {
	if op == "get-privs" {
		return true
	}
	if s.AuthModules != nil {
		return s.authorizeRequest(authRequest{operation: op, client: client, target: target})
	}
	if op == "randkey" {
		op = "change-password"
	} else if op == "set-string" || op == "get-strings" {
		op = map[string]string{"set-string": "modify", "get-strings": "get"}[op]
	}
	if op == "change-password" && principalEqual(client, target) {
		return true
	}
	if s.ACL != nil {
		return s.ACL(client, op, target)
	}
	if s.AdminPrincipal.Realm == "" {
		return false
	}
	a, _ := s.AdminPrincipal.Format()
	b, _ := client.Format()
	return strings.EqualFold(a, b)
}

func (s *Server) authorizePair(client principal.Principal, op string,
	first, second principal.Principal) bool {
	if s.AuthModules != nil && op == "add-alias" {
		return s.authorizeRequest(authRequest{
			operation: op, client: client, source: first, destination: second,
		})
	}
	if s.ACL != nil {
		return s.ACL(client, op, first) && s.ACL(client, op, second)
	}
	return s.authorize(client, op, first)
}

func (s *Server) authorizeRename(client, source, destination principal.Principal) bool {
	if s.AuthModules != nil {
		return s.authorizeRequest(authRequest{
			operation: "rename", client: client, source: source, destination: destination,
		})
	}
	if s.ACL != nil {
		return s.ACL(client, "delete", source) &&
			s.ACL(client, "create", destination)
	}
	return s.authorize(client, "rename", source)
}

func principalEqual(a, b principal.Principal) bool {
	if !strings.EqualFold(a.Realm, b.Realm) ||
		len(a.Components) != len(b.Components) {
		return false
	}
	for i := range a.Components {
		if a.Components[i] != b.Components[i] {
			return false
		}
	}
	return true
}

func validKadmService(service principal.Principal, realm string) bool {
	return len(service.Components) == 2 && service.Realm == realm &&
		service.Components[0] == "kadmin" && service.Components[1] != "history"
}

func isChangePasswordService(service principal.Principal) bool {
	return len(service.Components) == 2 && service.Components[0] == "kadmin" &&
		service.Components[1] == "changepw"
}

func (s *Server) checkSelfKeyChange(client, target principal.Principal) uint32 {
	return s.checkSelfKeyChangeWithInitial(client, target, true)
}

func (s *Server) checkSelfKeyChangeWithInitial(client, target principal.Principal, initial bool) uint32 {
	if !principalEqual(client, target) {
		return 0
	}
	if !initial {
		return authInitial
	}
	record, ok, err := s.Database.Lookup(target)
	if err != nil || !ok || record.Policy == "" {
		return 0
	}
	policy, err := s.Database.GetPolicy(record.Policy)
	if err != nil {
		return kdbCode(err)
	}
	if policy.MinLife > 0 && !record.LastPasswordChange.IsZero() &&
		s.now().Before(record.LastPasswordChange.Add(time.Duration(policy.MinLife)*time.Second)) {
		return passTooSoon
	}
	return 0
}

func (s *Server) checkLockdown(target principal.Principal) uint32 {
	record, ok, err := s.Database.Lookup(target)
	if err == nil && ok && record.Flags&flagLockdownKeys != 0 {
		return protectKeys
	}
	return 0
}

// The in-memory KDB represents keepold as retaining the prior key set, rather
// than a count of key versions. Its retained set is bounded to one prior set,
// which is within MIT's MAX_SELF_KEEPOLD limit of five for self changes.
func clampSelfKeepOld(client, target principal.Principal, keepOld bool) bool {
	if !keepOld {
		return false
	}
	return true
}

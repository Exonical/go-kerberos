package kadm5

import (
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

// AuthDecision is the result of a kadm5 authorization module check.
type AuthDecision int

const (
	// AuthPass indicates that a module neither authorizes nor denies a request.
	AuthPass AuthDecision = iota
	// AuthAuthorize explicitly authorizes a request.
	AuthAuthorize
	// AuthDeny explicitly denies a request.
	AuthDeny
)

// AuthRestrictions limits fields a module may authorize on principal changes.
type AuthRestrictions struct {
	Mask             int64
	RequireAttrs     int32
	ForbidAttrs      int32
	PrincLifetime    int32
	PWLifetime       int32
	MaxLife          int32
	MaxRenewableLife int32
	Policy           string
}

// AuthModule is the common identity shared by optional authorization methods.
type AuthModule interface {
	Name() string
}

type AuthAddPrinc interface {
	AuthAddPrinc(client, target principal.Principal, ent *PrincipalEntry, mask int64) (AuthDecision, *AuthRestrictions)
}

type AuthModPrinc interface {
	AuthModPrinc(client, target principal.Principal, ent *PrincipalEntry, mask int64) (AuthDecision, *AuthRestrictions)
}

type AuthSetString interface {
	AuthSetString(client, target principal.Principal, key string, value *string) AuthDecision
}

type AuthCpw interface {
	AuthCpw(client, target principal.Principal) AuthDecision
}

type AuthChRand interface {
	AuthChRand(client, target principal.Principal) AuthDecision
}

type AuthSetKey interface {
	AuthSetKey(client, target principal.Principal) AuthDecision
}

type AuthPurgeKeys interface {
	AuthPurgeKeys(client, target principal.Principal) AuthDecision
}

type AuthDelPrinc interface {
	AuthDelPrinc(client, target principal.Principal) AuthDecision
}

type AuthRenPrinc interface {
	AuthRenPrinc(client, source, destination principal.Principal) AuthDecision
}

type AuthGetPrinc interface {
	AuthGetPrinc(client, target principal.Principal) AuthDecision
}

type AuthGetStrings interface {
	AuthGetStrings(client, target principal.Principal) AuthDecision
}

type AuthExtract interface {
	AuthExtract(client, target principal.Principal) AuthDecision
}

type AuthListPrincs interface {
	AuthListPrincs(client principal.Principal) AuthDecision
}

type AuthAddPol interface {
	AuthAddPol(client principal.Principal, policy string, ent *Policy, mask int64) AuthDecision
}

type AuthModPol interface {
	AuthModPol(client principal.Principal, policy string, ent *Policy, mask int64) AuthDecision
}

type AuthDelPol interface {
	AuthDelPol(client principal.Principal, policy string) AuthDecision
}

type AuthGetPol interface {
	AuthGetPol(client principal.Principal, policy, clientPolicy string) AuthDecision
}

type AuthListPols interface {
	AuthListPols(client principal.Principal) AuthDecision
}

type AuthIprop interface {
	AuthIprop(client principal.Principal) AuthDecision
}

type AuthAddAlias interface {
	AuthAddAlias(client, alias, target principal.Principal) AuthDecision
}

type AuthEnd interface {
	AuthEnd()
}

// ACLAuthModule adapts a legacy ACL callback to the kadm5_auth interface.
type ACLAuthModule struct {
	Check func(client principal.Principal, operation string, target principal.Principal) bool
}

func (m ACLAuthModule) Name() string { return "acl" }

func (m ACLAuthModule) check(client principal.Principal, operation string, target principal.Principal) AuthDecision {
	if m.Check != nil && m.Check(client, operation, target) {
		return AuthAuthorize
	}
	return AuthPass
}

func (m ACLAuthModule) AuthAddPrinc(c, t principal.Principal, _ *PrincipalEntry, _ int64) (AuthDecision, *AuthRestrictions) {
	return m.check(c, "create", t), nil
}
func (m ACLAuthModule) AuthModPrinc(c, t principal.Principal, _ *PrincipalEntry, _ int64) (AuthDecision, *AuthRestrictions) {
	return m.check(c, "modify", t), nil
}
func (m ACLAuthModule) AuthSetString(c, t principal.Principal, _ string, _ *string) AuthDecision {
	return m.check(c, "modify", t)
}
func (m ACLAuthModule) AuthCpw(c, t principal.Principal) AuthDecision {
	return m.check(c, "change-password", t)
}
func (m ACLAuthModule) AuthChRand(c, t principal.Principal) AuthDecision {
	return m.check(c, "change-password", t)
}
func (m ACLAuthModule) AuthSetKey(c, t principal.Principal) AuthDecision {
	return m.check(c, "set-key", t)
}
func (m ACLAuthModule) AuthPurgeKeys(c, t principal.Principal) AuthDecision {
	return m.check(c, "modify", t)
}
func (m ACLAuthModule) AuthDelPrinc(c, t principal.Principal) AuthDecision {
	return m.check(c, "delete", t)
}
func (m ACLAuthModule) AuthRenPrinc(c, src, dest principal.Principal) AuthDecision {
	if m.Check != nil && m.Check(c, "delete", src) && m.Check(c, "create", dest) {
		return AuthAuthorize
	}
	return AuthPass
}
func (m ACLAuthModule) AuthGetPrinc(c, t principal.Principal) AuthDecision {
	return m.check(c, "get", t)
}
func (m ACLAuthModule) AuthGetStrings(c, t principal.Principal) AuthDecision {
	return m.check(c, "get", t)
}
func (m ACLAuthModule) AuthExtract(c, t principal.Principal) AuthDecision {
	return m.check(c, "extract-keys", t)
}
func (m ACLAuthModule) AuthListPrincs(c principal.Principal) AuthDecision {
	return m.check(c, "list", principal.Principal{})
}
func (m ACLAuthModule) AuthAddPol(c principal.Principal, _ string, _ *Policy, _ int64) AuthDecision {
	return m.check(c, "create-policy", principal.Principal{})
}
func (m ACLAuthModule) AuthModPol(c principal.Principal, _ string, _ *Policy, _ int64) AuthDecision {
	return m.check(c, "modify-policy", principal.Principal{})
}
func (m ACLAuthModule) AuthDelPol(c principal.Principal, _ string) AuthDecision {
	return m.check(c, "delete-policy", principal.Principal{})
}
func (m ACLAuthModule) AuthGetPol(c principal.Principal, _, _ string) AuthDecision {
	return m.check(c, "get-policy", principal.Principal{})
}
func (m ACLAuthModule) AuthListPols(c principal.Principal) AuthDecision {
	return m.check(c, "list-policy", principal.Principal{})
}
func (m ACLAuthModule) AuthIprop(c principal.Principal) AuthDecision {
	return m.check(c, "iprop", principal.Principal{})
}
func (m ACLAuthModule) AuthAddAlias(c, alias, target principal.Principal) AuthDecision {
	if m.Check != nil && m.Check(c, "create", alias) && m.Check(c, "modify", target) {
		return AuthAuthorize
	}
	return AuthPass
}

// SelfAuthModule implements MIT's self-service authorization module.
type SelfAuthModule struct{}

func (SelfAuthModule) Name() string { return "self" }
func (SelfAuthModule) self(c, t principal.Principal) AuthDecision {
	if principalEqual(c, t) {
		return AuthAuthorize
	}
	return AuthPass
}
func (m SelfAuthModule) AuthCpw(c, t principal.Principal) AuthDecision       { return m.self(c, t) }
func (m SelfAuthModule) AuthChRand(c, t principal.Principal) AuthDecision    { return m.self(c, t) }
func (m SelfAuthModule) AuthPurgeKeys(c, t principal.Principal) AuthDecision { return m.self(c, t) }
func (m SelfAuthModule) AuthGetPrinc(c, t principal.Principal) AuthDecision  { return m.self(c, t) }
func (m SelfAuthModule) AuthGetStrings(c, t principal.Principal) AuthDecision {
	return m.self(c, t)
}
func (SelfAuthModule) AuthGetPol(c principal.Principal, policy, clientPolicy string) AuthDecision {
	if clientPolicy != "" && policy == clientPolicy {
		return AuthAuthorize
	}
	return AuthPass
}

type authRequest struct {
	operation            string
	client, target       principal.Principal
	source, destination  principal.Principal
	key                  string
	value                *string
	policy, clientPolicy string
	entry                *PrincipalEntry
	mask                 int64
	policyEntry          *Policy
}

func authDecision(m AuthModule, req authRequest) (AuthDecision, *AuthRestrictions) {
	switch req.operation {
	case "create":
		if v, ok := m.(AuthAddPrinc); ok {
			return v.AuthAddPrinc(req.client, req.target, req.entry, req.mask)
		}
	case "modify":
		if v, ok := m.(AuthModPrinc); ok {
			return v.AuthModPrinc(req.client, req.target, req.entry, req.mask)
		}
	case "set-string":
		if v, ok := m.(AuthSetString); ok {
			return v.AuthSetString(req.client, req.target, req.key, req.value), nil
		}
	case "change-password":
		if v, ok := m.(AuthCpw); ok {
			return v.AuthCpw(req.client, req.target), nil
		}
	case "randkey":
		if v, ok := m.(AuthChRand); ok {
			return v.AuthChRand(req.client, req.target), nil
		}
	case "set-key":
		if v, ok := m.(AuthSetKey); ok {
			return v.AuthSetKey(req.client, req.target), nil
		}
	case "purgekeys":
		if v, ok := m.(AuthPurgeKeys); ok {
			return v.AuthPurgeKeys(req.client, req.target), nil
		}
	case "delete":
		if v, ok := m.(AuthDelPrinc); ok {
			return v.AuthDelPrinc(req.client, req.target), nil
		}
	case "rename":
		if v, ok := m.(AuthRenPrinc); ok {
			return v.AuthRenPrinc(req.client, req.source, req.destination), nil
		}
	case "get":
		if v, ok := m.(AuthGetPrinc); ok {
			return v.AuthGetPrinc(req.client, req.target), nil
		}
	case "get-strings":
		if v, ok := m.(AuthGetStrings); ok {
			return v.AuthGetStrings(req.client, req.target), nil
		}
	case "extract-keys":
		if v, ok := m.(AuthExtract); ok {
			return v.AuthExtract(req.client, req.target), nil
		}
	case "list":
		if v, ok := m.(AuthListPrincs); ok {
			return v.AuthListPrincs(req.client), nil
		}
	case "create-policy":
		if v, ok := m.(AuthAddPol); ok {
			return v.AuthAddPol(req.client, req.policy, req.policyEntry, req.mask), nil
		}
	case "modify-policy":
		if v, ok := m.(AuthModPol); ok {
			return v.AuthModPol(req.client, req.policy, req.policyEntry, req.mask), nil
		}
	case "delete-policy":
		if v, ok := m.(AuthDelPol); ok {
			return v.AuthDelPol(req.client, req.policy), nil
		}
	case "get-policy":
		if v, ok := m.(AuthGetPol); ok {
			return v.AuthGetPol(req.client, req.policy, req.clientPolicy), nil
		}
	case "list-policy":
		if v, ok := m.(AuthListPols); ok {
			return v.AuthListPols(req.client), nil
		}
	case "iprop":
		if v, ok := m.(AuthIprop); ok {
			return v.AuthIprop(req.client), nil
		}
	case "add-alias":
		if v, ok := m.(AuthAddAlias); ok {
			return v.AuthAddAlias(req.client, req.source, req.destination), nil
		}
	}
	return AuthPass, nil
}

// ApplyAuthRestrictions applies MIT kadm5_auth restrictions to a principal
// entry and its field mask.
func ApplyAuthRestrictions(ent *PrincipalEntry, mask *int64, rs *AuthRestrictions, now time.Time) {
	if ent == nil || mask == nil || rs == nil {
		return
	}
	if rs.Mask&int64(KADM5Attributes) != 0 {
		ent.Attributes |= rs.RequireAttrs
		ent.Attributes &^= rs.ForbidAttrs
		*mask |= int64(KADM5Attributes)
	}
	if rs.Mask&int64(KADM5PolicyClear) != 0 {
		ent.Policy = ""
		*mask &^= int64(KADM5Policy)
		*mask |= int64(KADM5PolicyClear)
	} else if rs.Mask&int64(KADM5Policy) != 0 {
		ent.Policy = rs.Policy
		*mask |= int64(KADM5Policy)
		*mask &^= int64(KADM5PolicyClear)
	}
	nowUnix := now.Unix()
	clamp := func(field *int32, bit int32, lifetime int32) {
		if rs.Mask&int64(bit) == 0 {
			return
		}
		limit := nowUnix + int64(lifetime)
		if *mask&int64(bit) == 0 || int64(*field) > limit {
			*field = int32(limit)
		}
		*mask |= int64(bit)
	}
	clamp(&ent.PrincExpireTime, KADM5PrincExpireTime, rs.PrincLifetime)
	clamp(&ent.PWExpiration, KADM5PWExpiration, rs.PWLifetime)
	if rs.Mask&int64(KADM5MaxLife) != 0 {
		if *mask&int64(KADM5MaxLife) == 0 || ent.MaxLife > rs.MaxLife {
			ent.MaxLife = rs.MaxLife
		}
		*mask |= int64(KADM5MaxLife)
	}
	if rs.Mask&int64(KADM5MaxRenewableLife) != 0 {
		if *mask&int64(KADM5MaxRenewableLife) == 0 || ent.MaxRenewableLife > rs.MaxRenewableLife {
			ent.MaxRenewableLife = rs.MaxRenewableLife
		}
		*mask |= int64(KADM5MaxRenewableLife)
	}
}

func authModulesForServer(s *Server) []AuthModule {
	modules := make([]AuthModule, 0, len(s.AuthModules)+2)
	if s.ACL != nil {
		modules = append(modules, ACLAuthModule{Check: s.ACL})
	}
	modules = append(modules, s.AuthModules...)
	modules = append(modules, SelfAuthModule{})
	return modules
}

func (s *Server) authorizeRequest(req authRequest) bool {
	authorized := false
	for _, module := range authModulesForServer(s) {
		decision, restrictions := authDecision(module, req)
		if restrictions != nil {
			ApplyAuthRestrictions(req.entry, &req.mask, restrictions, s.now())
		}
		switch decision {
		case AuthAuthorize:
			authorized = true
		case AuthPass:
			continue
		case AuthDeny:
			return false
		default:
			return false
		}
	}
	return authorized
}

func (s *Server) authorizePrincipal(client principal.Principal, operation string,
	entry *PrincipalEntry, mask *int32) bool {
	if s.AuthModules == nil {
		return s.authorize(client, operation, entry.Principal)
	}
	req := authRequest{operation: operation, client: client, target: entry.Principal, entry: entry, mask: int64(*mask)}
	authorized := s.authorizeRequest(req)
	*mask = int32(req.mask)
	return authorized
}

func (s *Server) authorizeString(client, target principal.Principal,
	key string, value *string) bool {
	if s.AuthModules == nil {
		return s.authorize(client, "set-string", target)
	}
	return s.authorizeRequest(authRequest{
		operation: "set-string", client: client, target: target,
		key: key, value: value,
	})
}

func (s *Server) authorizePolicy(client principal.Principal, operation string,
	policy string, ent *Policy, mask int32, clientPolicy string) bool {
	if s.AuthModules == nil {
		return s.authorize(client, operation, principal.Principal{})
	}
	return s.authorizeRequest(authRequest{operation: operation, client: client,
		policy: policy, policyEntry: ent, mask: int64(mask), clientPolicy: clientPolicy})
}

func (s *Server) endAuth() {
	for _, module := range authModulesForServer(s) {
		if end, ok := module.(AuthEnd); ok {
			end.AuthEnd()
		}
	}
}

var _ AuthModule = ACLAuthModule{}
var _ AuthModule = SelfAuthModule{}

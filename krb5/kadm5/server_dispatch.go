package kadm5

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/trace"
)

const initProcedure = 13

const flagLockdownKeys uint32 = 1 << 19

func knownProcedure(proc uint32) bool {
	switch proc {
	case initProcedure, createPrincipal, deletePrincipal, modifyPrincipal,
		renamePrincipal, getPrincipal, chpassPrincipal, chpassPrincipal3, chrandPrincipal,
		createPolicy, deletePolicy, modifyPolicy, getPolicy, getPrivs,
		getPrincs, getPolicies, getStrings, setString, setkeyPrincipal4,
		extractKeys, createPrincipal3, chrandPrincipal3, setkeyPrincipal,
		setkeyPrincipal3, purgeKeys, createAlias:
		return true
	default:
		return false
	}
}

func (s *Server) dispatch(client, service principal.Principal, proc uint32, body []byte, initial bool) []byte {
	defer s.endAuth()
	if s.Trace != nil {
		s.Trace(fmt.Sprintf("kadm5: request from %s procedure %d",
			trace.Principal(client), proc))
	}
	r := xdrReader{b: body}
	api, err := r.u32()
	if err != nil {
		return statusReply(s.API, 43787548)
	}
	if api < APIv2 || api > APIv4 || api > s.API {
		return statusReply(s.API, apiUnsupported)
	}
	status := func(code uint32) []byte { return statusReply(api, code) }
	readPrincipal := func() (principal.Principal, error) { return r.principal() }
	switch proc {
	case initProcedure:
		if err := r.done(); err != nil {
			return status(43787548)
		}
		return status(0)
	case createPrincipal:
		if isChangePasswordService(service) {
			return status(authAdd)
		}
		entry, err := decodeEntry(&r, api)
		if err != nil {
			return status(43787548)
		}
		mask, err := r.i32()
		if err != nil {
			return status(43787548)
		}
		password, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorizePrincipal(client, "create", &entry, &mask) {
			return status(authAdd)
		}
		policyName := ""
		if mask&KADM5Policy != 0 && mask&KADM5PolicyClear == 0 {
			policyName = entry.Policy
		}
		if policyName != "" {
			policy, policyErr := s.Database.GetPolicy(policyName)
			if policyErr != nil {
				return status(kdbCode(policyErr))
			}
			if qualityErr := checkPolicy(password, &policy); qualityErr != nil {
				return status(kdbCode(qualityErr))
			}
		}
		if qualityErr := s.checkPasswordQuality(password, policyName, entry.Principal); qualityErr != nil {
			return status(kdbCode(qualityErr))
		}
		event := HookEvent{Operation: "create", Principal: entry.Principal, Entry: entry, Mask: mask, Password: password}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		var selectedPolicy *kdb.PolicyRecord
		if policyName != "" {
			policy, policyErr := s.Database.GetPolicy(policyName)
			if policyErr != nil {
				return status(kdbCode(policyErr))
			}
			selectedPolicy = &policy
		}
		if err := s.Database.CreatePrincipalWithOptions(formatPrincipal(entry.Principal), password, selectedPolicy); err != nil {
			return status(kdbCode(err))
		}
		_ = s.runHooks(HookPostCommit, event)
		_ = mask
		return status(0)
	case createPrincipal3:
		if isChangePasswordService(service) {
			return status(authAdd)
		}
		entry, err := decodeEntry(&r, api)
		if err != nil {
			return status(43787548)
		}
		mask, err := r.i32()
		if err != nil {
			return status(43787548)
		}
		tuples, err := readKeySaltTuples(&r)
		if err != nil {
			return status(43787548)
		}
		password, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorizePrincipal(client, "create", &entry, &mask) {
			return status(authAdd)
		}
		policyName := ""
		if mask&KADM5Policy != 0 && mask&KADM5PolicyClear == 0 {
			policyName = entry.Policy
		}
		if policyName != "" {
			policy, policyErr := s.Database.GetPolicy(policyName)
			if policyErr != nil {
				return status(kdbCode(policyErr))
			}
			if qualityErr := checkPolicy(password, &policy); qualityErr != nil {
				return status(kdbCode(qualityErr))
			}
		}
		if qualityErr := s.checkPasswordQuality(password, policyName, entry.Principal); qualityErr != nil {
			return status(kdbCode(qualityErr))
		}
		event := HookEvent{Operation: "create", Principal: entry.Principal, Entry: entry,
			Mask: mask, Password: password}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		var selectedPolicy *kdb.PolicyRecord
		if policyName != "" {
			policy, policyErr := s.Database.GetPolicy(policyName)
			if policyErr != nil {
				return status(kdbCode(policyErr))
			}
			selectedPolicy = &policy
		}
		err = s.Database.CreatePrincipalWithKeySaltsAndOptions(formatPrincipal(entry.Principal),
			password, toKDBKeySaltTuples(tuples), selectedPolicy)
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case deletePrincipal:
		if isChangePasswordService(service) {
			return status(authDelete)
		}
		p, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "delete", p) {
			return status(authDelete)
		}
		if code := s.checkLockdown(p); code != 0 {
			return status(authDelete)
		}
		event := HookEvent{Operation: "remove", Principal: p}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		err = s.Database.DeletePrincipal(p)
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case modifyPrincipal:
		if isChangePasswordService(service) {
			return status(authModify)
		}
		entry, err := decodeEntry(&r, api)
		if err != nil {
			return status(43787548)
		}
		mask, err := r.i32()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorizePrincipal(client, "modify", &entry, &mask) {
			return status(authModify)
		}
		record, ok, err := s.Database.Lookup(entry.Principal)
		if err != nil || !ok {
			return status(43787534)
		}
		if record.Flags&flagLockdownKeys != 0 && mask&KADM5Attributes != 0 &&
			uint32(entry.Attributes)&flagLockdownKeys == 0 {
			return status(authModify)
		}
		applyEntry(&record, entry, mask)
		event := HookEvent{Operation: "modify", Principal: entry.Principal, Entry: entry, Mask: mask}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		err = s.Database.UpdatePrincipal(record)
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case renamePrincipal:
		if isChangePasswordService(service) {
			return status(authInsufficient)
		}
		src, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		dest, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorizeRename(client, src, dest) {
			return status(authModify)
		}
		if code := s.checkLockdown(src); code != 0 {
			return status(authDelete)
		}
		event := HookEvent{Operation: "rename", Principal: src, NewPrincipal: dest}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		err = s.Database.RenamePrincipal(src, dest)
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case getPrincipal:
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		if _, err = r.i32(); err != nil || r.done() != nil {
			return status(43787548)
		}
		if (!isChangePasswordService(service) || !principalEqual(client, p)) &&
			!s.authorize(client, "get", p) {
			return status(authGet)
		}
		record, ok, err := s.Database.Lookup(p)
		if err != nil || !ok {
			return status(43787534)
		}
		w := xdrWriter{}
		w.raw(status(0))
		writeEntryWithModifier(&w, recordEntry(record), KADM5Policy, true)
		return w.bytes()
	case chpassPrincipal, chpassPrincipal3:
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		var keepOld bool
		var tuples []kdb.KeySaltTuple
		if proc == chpassPrincipal3 {
			keepOld, err = r.boolean()
			if err != nil {
				return status(43787548)
			}
			count, err := r.u32()
			if err != nil || count > 1024 {
				return status(43787548)
			}
			tuples = make([]kdb.KeySaltTuple, count)
			for i := uint32(0); i < count; i++ {
				enctype, err := r.i32()
				if err != nil {
					return status(43787548)
				}
				salt, err := r.i32()
				if err != nil {
					return status(43787548)
				}
				tuples[i] = kdb.KeySaltTuple{Enctype: enctype, SaltType: salt}
			}
		}
		password, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "change-password", p) {
			return status(authChangePass)
		}
		if code := s.checkLockdown(p); code != 0 {
			return status(authChangePass)
		}
		if code := s.checkSelfKeyChangeWithInitial(client, p, initial); code != 0 {
			return status(code)
		}
		if isChangePasswordService(service) && !principalEqual(client, p) {
			return status(authChangePass)
		}
		record, ok, err := s.Database.Lookup(p)
		if err != nil || !ok {
			return status(43787534)
		}
		if record.Flags&flagLockdownKeys != 0 {
			return status(protectKeys)
		}
		var policy *kdb.PolicyRecord
		if record.Policy != "" {
			value, policyErr := s.Database.GetPolicy(record.Policy)
			if policyErr != nil {
				return status(kdbCode(policyErr))
			}
			policy = &value
		}
		bypassMinLife := !principalEqual(client, p) &&
			s.authorize(client, "modify", p)
		if policyErr := s.Database.CheckPasswordPolicy(p, password, s.now(), policy, bypassMinLife); policyErr != nil {
			return status(kdbCode(policyErr))
		}
		if qualityErr := s.checkPasswordQuality(password, record.Policy, p); qualityErr != nil {
			return status(kdbCode(qualityErr))
		}
		event := HookEvent{Operation: "chpass", Principal: p, Password: password, KeepOld: keepOld}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		if proc == chpassPrincipal3 {
			if backend, ok := s.Database.(passwordKeySaltBackend); ok {
				err = backend.ChangePasswordWithKeySaltsAndPolicy(p, password, s.now(), policy, bypassMinLife, keepOld, tuples)
			} else {
				err = s.Database.ChangePasswordWithPolicyAndKeepOld(p, password, s.now(), policy, bypassMinLife, keepOld)
			}
		} else {
			err = s.Database.ChangePasswordWithPolicyAndKeepOld(p, password, s.now(), policy, bypassMinLife, keepOld)
		}
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case chrandPrincipal:
		p, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "randkey", p) {
			return status(authChangePass)
		}
		if isChangePasswordService(service) && !principalEqual(client, p) {
			return status(authChangePass)
		}
		if code := s.checkSelfKeyChangeWithInitial(client, p, initial); code != 0 {
			return status(code)
		}
		keys, err := s.Database.RandomizeKeys(p)
		if err != nil {
			return status(kdbCode(err))
		}
		if s.checkLockdown(p) == protectKeys {
			keys = nil
		}
		w := xdrWriter{}
		w.raw(status(0))
		w.u32(uint32(len(keys)))
		for _, key := range keys {
			w.i32(key.Enctype)
			w.opaque(key.Key)
		}
		return w.bytes()
	case chrandPrincipal3:
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		keepOld, err := r.boolean()
		if err != nil {
			return status(43787548)
		}
		tuples, err := readKeySaltTuples(&r)
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "randkey", p) {
			return status(authChangePass)
		}
		if isChangePasswordService(service) && !principalEqual(client, p) {
			return status(authChangePass)
		}
		if code := s.checkSelfKeyChangeWithInitial(client, p, initial); code != 0 {
			return status(code)
		}
		keepOld = clampSelfKeepOld(client, p, keepOld)
		keys, err := s.Database.RandomizeKeysWithKeySalts(p, keepOld, toKDBKeySaltTuples(tuples))
		if err != nil {
			return status(kdbCode(err))
		}
		if s.checkLockdown(p) == protectKeys {
			keys = nil
		}
		w := xdrWriter{}
		w.raw(status(0))
		w.u32(uint32(len(keys)))
		for _, key := range keys {
			w.i32(key.Enctype)
			w.opaque(key.Key)
		}
		return w.bytes()
	case setkeyPrincipal, setkeyPrincipal3:
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		keepOld := false
		var tuples []KeySaltTuple
		if proc == setkeyPrincipal3 {
			keepOld, err = r.boolean()
			if err != nil {
				return status(43787548)
			}
			tuples, err = readKeySaltTuples(&r)
			if err != nil {
				return status(43787548)
			}
		}
		keys, err := readKeyBlocks(&r)
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if isChangePasswordService(service) {
			return status(authSetKey)
		}
		if !s.authorize(client, "set-key", p) {
			return status(authSetKey)
		}
		if code := s.checkLockdown(p); code != 0 {
			return status(authSetKey)
		}
		if code := s.checkSelfKeyChangeWithInitial(client, p, initial); code != 0 {
			return status(code)
		}
		_ = tuples
		err = s.Database.SetKeys(p, keys, keepOld)
		return status(kdbCode(err))
	case purgeKeys:
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		keepKVNO, err := r.i32()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "purgekeys", p) {
			return status(authModify)
		}
		if isChangePasswordService(service) {
			return status(authModify)
		}
		return status(kdbCode(s.Database.PurgeKeys(p, keepKVNO)))
	case createAlias:
		alias, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		target, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !strings.EqualFold(alias.Realm, target.Realm) {
			return status(43787549)
		}
		if isChangePasswordService(service) {
			return status(authInsufficient)
		}
		if !s.authorizePair(client, "add-alias", alias, target) {
			return status(authAdd)
		}
		event := HookEvent{Operation: "alias", Principal: alias, NewPrincipal: target}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		err = s.Database.AddAlias(formatPrincipal(alias), formatPrincipal(target))
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case getPrincs:
		if isChangePasswordService(service) {
			return status(authList)
		}
		expr, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "list", principal.Principal{}) {
			return status(authList)
		}
		names := s.listPrincipals(expr)
		return stringListReply(api, names)
	case createPolicy, modifyPolicy:
		if isChangePasswordService(service) {
			if proc == createPolicy {
				return status(authAdd)
			}
			return status(authModify)
		}
		policy, err := readPolicy(&r, api)
		if err != nil {
			return status(43787548)
		}
		mask, err := r.i32()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if proc == modifyPolicy && !validPolicyMask(mask, api) {
			return status(43787548)
		}
		kp := policyRecord(policy)
		policyOperation := map[uint32]string{createPolicy: "create-policy", modifyPolicy: "modify-policy"}[proc]
		if !s.authorizePolicy(client, policyOperation, policy.Name, &policy, mask, "") {
			return status(authAdd)
		}
		if proc == createPolicy {
			err = s.Database.CreatePolicy(kp)
		} else {
			old, getErr := s.Database.GetPolicy(policy.Name)
			if getErr == nil {
				applyPolicy(&old, kp, mask)
				if !validateModifiedPolicy(old, mask) {
					err = errors.New("kadm5: invalid policy values")
				} else {
					err = s.Database.UpdatePolicy(old)
				}
			} else {
				err = getErr
			}
		}
		return status(kdbCode(err))
	case deletePolicy:
		if isChangePasswordService(service) {
			return status(authDelete)
		}
		name, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorizePolicy(client, "delete-policy", name, nil, 0, "") {
			return status(authDelete)
		}
		return status(kdbCode(s.Database.DeletePolicy(name)))
	case getPolicy:
		name, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		clientPolicy := ""
		if record, ok, _ := s.Database.Lookup(client); ok {
			clientPolicy = record.Policy
		}
		if isChangePasswordService(service) && (clientPolicy == "" || clientPolicy != name) {
			return status(authGet)
		}
		if !s.authorizePolicy(client, "get-policy", name, nil, 0, clientPolicy) {
			return status(authGet)
		}
		policy, err := s.Database.GetPolicy(name)
		if err != nil {
			return status(kdbCode(err))
		}
		w := xdrWriter{}
		w.raw(status(0))
		writePolicy(&w, policyValue(policy), api)
		return w.bytes()
	case getPolicies:
		if isChangePasswordService(service) {
			return status(authList)
		}
		expr, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "list-policy", principal.Principal{}) {
			return status(authList)
		}
		var names []string
		for _, name := range s.Database.ListPolicies() {
			if expr == "" || globMatch(expr, name) {
				names = append(names, name)
			}
		}
		return stringListReply(api, names)
	case getPrivs:
		if r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "get-privs", principal.Principal{}) {
			return status(authGet)
		}
		w := xdrWriter{}
		w.raw(status(0))
		w.i32(0x7fffffff)
		return w.bytes()
	case getStrings:
		if isChangePasswordService(service) {
			return status(authGet)
		}
		p, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "get-strings", p) {
			return status(authGet)
		}
		values, err := s.Database.GetStrings(p)
		if err != nil {
			return status(kdbCode(err))
		}
		w := xdrWriter{}
		w.raw(status(0))
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		w.i32(int32(len(keys)))
		w.u32(uint32(len(keys)))
		for _, key := range keys {
			writeStringAttribute(&w, StringAttribute{Key: key, Value: values[key]})
		}
		return w.bytes()
	case setString:
		if isChangePasswordService(service) {
			return status(authModify)
		}
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		key, err := r.nullableString()
		if err != nil {
			return status(43787548)
		}
		value, err := r.nullableString()
		if err != nil || key == nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorizeString(client, p, *key, value) {
			return status(authModify)
		}
		return status(kdbCode(s.Database.SetString(p, *key, value)))
	case extractKeys:
		if isChangePasswordService(service) {
			return status(authExtract)
		}
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		kvno, err := r.u32()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "extract-keys", p) {
			return status(authExtract)
		}
		record, ok, err := s.Database.Lookup(p)
		if err != nil || !ok {
			return status(43787534)
		}
		if record.Flags&flagLockdownKeys != 0 {
			return status(authExtract)
		}
		keys := make([]KeyData, 0, len(record.Keys))
		for _, key := range record.Keys {
			if kvno == 0 || key.KVNO == kvno {
				keys = append(keys, KeyData{KVNO: key.KVNO, Enctype: key.Enctype, Key: key.Key})
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].Enctype < keys[j].Enctype })
		w := xdrWriter{}
		w.raw(status(0))
		w.u32(uint32(len(keys)))
		for _, key := range keys {
			writeKeyData(&w, key)
		}
		return w.bytes()
	case setkeyPrincipal4:
		p, err := readPrincipal()
		if err != nil {
			return status(43787548)
		}
		keepOld, err := r.boolean()
		if err != nil {
			return status(43787548)
		}
		keys, err := readKeyData(&r)
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if isChangePasswordService(service) {
			return status(authSetKey)
		}
		if !s.authorize(client, "set-key", p) {
			return status(authSetKey)
		}
		if code := s.checkLockdown(p); code != 0 {
			return status(authSetKey)
		}
		if code := s.checkSelfKeyChangeWithInitial(client, p, initial); code != 0 {
			return status(code)
		}
		out := make([]kdb.Key, 0, len(keys))
		for _, key := range keys {
			out = append(out, kdb.Key{Enctype: key.Enctype, KVNO: key.KVNO, Key: key.Key, Salt: string(key.Salt)})
		}
		return status(kdbCode(s.Database.SetKeys(p, out, keepOld)))
	default:
		return status(43787548)
	}
}

func statusReply(api, code uint32) []byte {
	w := xdrWriter{}
	w.u32(api)
	w.u32(code)
	return w.bytes()
}

func (s *Server) listPrincipals(expr string) []string {
	var out []string
	if expr != "" && !strings.Contains(expr, "@") {
		expr += "@" + s.Database.GetRealm()
	}
	for _, name := range s.Database.ListPrincipals() {
		if expr == "" || globMatch(expr, name) {
			out = append(out, name)
		}
	}
	return out
}

func globMatch(expr, name string) bool {
	var pattern strings.Builder
	pattern.WriteByte('^')
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '*':
			pattern.WriteString(".*")
		case '?':
			pattern.WriteByte('.')
		case '\\':
			if i+1 == len(expr) {
				return false
			}
			i++
			pattern.WriteString(regexp.QuoteMeta(expr[i : i+1]))
		case '[':
			end := i + 1
			if end < len(expr) && (expr[end] == '!' || expr[end] == '^') {
				end++
			}
			if end < len(expr) && expr[end] == ']' {
				end++
			}
			for end < len(expr) && expr[end] != ']' {
				end++
			}
			if end == len(expr) {
				return false
			}
			class := expr[i : end+1]
			if class[1] == '!' {
				class = "[^" + class[2:]
			}
			pattern.WriteString(class)
			i = end
		default:
			pattern.WriteString(regexp.QuoteMeta(expr[i : i+1]))
		}
	}
	pattern.WriteByte('$')
	compiled, err := regexp.Compile(pattern.String())
	if err != nil {
		return false
	}
	return compiled.MatchString(name)
}

func stringListReply(api uint32, names []string) []byte {
	sort.Strings(names)
	w := xdrWriter{}
	w.raw(statusReply(api, 0))
	w.i32(int32(len(names)))
	w.u32(uint32(len(names)))
	for _, name := range names {
		w.nullString(name)
	}
	return w.bytes()
}

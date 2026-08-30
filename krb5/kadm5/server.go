package kadm5

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	// ServerMaxRecord is the largest RPC record accepted by Server.
	ServerMaxRecord = 16 << 20
	authGet         = 43787521
	authAdd         = 43787522
	authModify      = 43787523
	authDelete      = 43787524
	authChangePass  = 43787572
	authSetKey      = 43787577
	authExtract     = 43787587
	authList        = 43787571
	apiUnsupported  = 43787530
	passTooShort    = 43787542
	passClass       = 43787543
	passReuse       = 43787545
	passTooSoon     = 43787546
)

// Server implements the kadm5 RPC service over a TCP listener.
//
// Keytab must contain the kadmin/admin service key.  Database is required for
// the mutable in-memory implementation.  ACL, when non-nil, is consulted for
// every operation; otherwise only AdminPrincipal is authorized.
type Server struct {
	Database       *kdb.Database
	Keytab         *keytab.Keytab
	AdminPrincipal principal.Principal
	ACL            func(client principal.Principal, operation string, target principal.Principal) bool
	API            uint32
	ErrorLog       func(error)
	Now            func() time.Time
	// PasswordQualityModules are evaluated after the named policy. A nil value
	// uses MIT's built-in empty and princ modules.
	PasswordQualityModules []PasswordQualityModule
	// Hooks run in order around principal mutations.
	Hooks []Kadm5Hook
	// DictionaryFile configures the optional MIT dictionary module.
	DictionaryFile string

	wg sync.WaitGroup
}

// NewServer creates a v4 kadm5 server.
func NewServer(database *kdb.Database, serviceKeytab *keytab.Keytab) *Server {
	return &Server{Database: database, Keytab: serviceKeytab, API: APIv4}
}

// Serve accepts kadm5 RPC connections until the listener fails.
func (s *Server) Serve(listener net.Listener) error {
	if s == nil || s.Database == nil || s.Keytab == nil {
		return errors.New("kadm5: incomplete server configuration")
	}
	if s.API < APIv2 || s.API > APIv4 {
		s.API = APIv4
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.wg.Wait()
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.serveConn(conn)
		}()
	}
}

type serverSession struct {
	ctx       *gssapi.Context
	client    principal.Principal
	handle    []byte
	next      uint32
	gssSeqSet bool
}

func (s *Server) serveConn(conn net.Conn) error {
	defer conn.Close()
	var session *serverSession
	for {
		record, err := readRPCRecord(conn)
		if err != nil {
			return err
		}
		call, err := parseRPCCall(record)
		if err != nil {
			if s.ErrorLog != nil {
				s.ErrorLog(err)
			}
			return err
		}
		var reply []byte
		if call.flavor == rpcsecGSS {
			reply, session, err = s.handleGSS(conn, call, session)
		} else {
			if s.ErrorLog != nil {
				s.ErrorLog(errors.New("kadm5: unsupported RPC authentication flavor"))
			}
			reply = rpcErrorReply(call.xid, 1)
			err = nil
		}
		if err != nil {
			if s.ErrorLog != nil {
				s.ErrorLog(err)
			}
			return err
		}
		if err := writeRPCRecord(conn, reply); err != nil {
			if s.ErrorLog != nil {
				s.ErrorLog(err)
			}
			return err
		}
	}
}

type rpcCall struct {
	xid        uint32
	proc       uint32
	flavor     uint32
	credential []byte
	verifier   []byte
	body       []byte
	prefix     []byte
}

func parseRPCCall(record []byte) (rpcCall, error) {
	r := xdrReader{b: record}
	xid, err := r.u32()
	if err != nil {
		return rpcCall{}, err
	}
	if msg, err := r.u32(); err != nil || msg != msgCall {
		return rpcCall{}, errors.New("kadm5: invalid RPC call type")
	}
	if version, err := r.u32(); err != nil || version != rpcVersion {
		return rpcCall{}, errors.New("kadm5: unsupported RPC version")
	}
	if program, err := r.u32(); err != nil || program != Program {
		return rpcCall{}, errors.New("kadm5: unexpected RPC program")
	}
	if version, err := r.u32(); err != nil || version != Version {
		return rpcCall{}, errors.New("kadm5: unexpected RPC program version")
	}
	proc, err := r.u32()
	if err != nil {
		return rpcCall{}, err
	}
	flavor, credential, err := r.opaqueAuth()
	if err != nil {
		return rpcCall{}, err
	}
	prefixEnd := r.off
	_, verifier, err := r.opaqueAuth()
	if err != nil {
		return rpcCall{}, err
	}
	return rpcCall{
		xid: xid, proc: proc, flavor: flavor, credential: credential,
		verifier: verifier, body: record[r.off:],
		prefix: record[:prefixEnd],
	}, nil
}

func (s *Server) handleGSS(_ net.Conn, call rpcCall, session *serverSession) ([]byte, *serverSession, error) {
	r := xdrReader{b: call.credential}
	version, err := r.u32()
	if err != nil || version != 1 {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	proc, err := r.u32()
	if err != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	seq, err := r.u32()
	if err != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	service, err := r.u32()
	if err != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	handle, err := r.opaque()
	if err != nil || r.done() != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if service != rpcsecGSSPrivacy && service != rpcsecGSSData {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	recordBody := call.body
	if len(recordBody) == 0 {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if proc == rpcsecGSSInit || proc == rpcsecGSSCont {
		if session == nil {
			if proc != rpcsecGSSInit || len(handle) != 0 {
				return rpcErrorReply(call.xid, 1), session, nil
			}
		} else if proc != rpcsecGSSCont || !bytesEqual(handle, session.handle) {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		bodyReader := xdrReader{b: recordBody}
		token, err := bodyReader.opaque()
		if err != nil || bodyReader.done() != nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		if proc == rpcsecGSSCont && session == nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		acceptor := gssapi.NewAcceptor(s.Keytab)
		var ctx *gssapi.Context
		var client principal.Principal
		var responseToken []byte
		if session == nil {
			ctx, client, responseToken, err = acceptor.AcceptWithPrincipal(token, nowUTC())
			if err != nil {
				return rpcErrorReply(call.xid, 1), nil, nil
			}
			handle = make([]byte, 16)
			if _, err := rand.Read(handle); err != nil {
				return nil, nil, err
			}
			session = &serverSession{ctx: ctx, client: client, handle: handle, next: 1}
		} else {
			ctx, _, responseToken, err = acceptor.AcceptWithPrincipal(token, nowUTC())
			if err != nil {
				return rpcErrorReply(call.xid, 1), session, nil
			}
			session.ctx = ctx
		}
		// The client validates a MIC over the negotiated sequence window.
		window := uint32(0x7fffffff)
		verifier, err := session.ctx.MIC(seqBytes(window))
		if err != nil {
			return nil, nil, err
		}
		body := xdrWriter{}
		body.opaque(session.handle)
		body.u32(0)
		body.u32(0)
		body.u32(window)
		body.opaque(responseToken)
		return rpcReply(call.xid, rpcsecGSS, verifier, body.bytes()), session, nil
	}
	if session == nil || !bytesEqual(handle, session.handle) || proc != rpcsecGSSData {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if seq != session.next {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	protectedReader := xdrReader{b: recordBody}
	protected, err := protectedReader.opaque()
	if err != nil || protectedReader.done() != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if len(protected) < 16 || len(call.verifier) < 16 {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	protectedSeq := binary.BigEndian.Uint64(protected[8:16])
	verifierSeq := binary.BigEndian.Uint64(call.verifier[8:16])
	if !session.gssSeqSet {
		if protectedSeq+1 == verifierSeq {
			session.ctx.SetReceiveSequence(protectedSeq)
		} else if verifierSeq+1 == protectedSeq {
			session.ctx.SetReceiveSequence(verifierSeq)
		} else {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		session.gssSeqSet = true
	}
	var plain []byte
	if protectedSeq+1 == verifierSeq {
		plain, err = session.ctx.Unwrap(protected)
		if err != nil || len(plain) < 4 || binary.BigEndian.Uint32(plain[:4]) != seq {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		if err := session.ctx.VerifyMIC(call.prefix, call.verifier); err != nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
	} else if verifierSeq+1 == protectedSeq {
		if err := session.ctx.VerifyMIC(call.prefix, call.verifier); err != nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		plain, err = session.ctx.Unwrap(protected)
		if err != nil || len(plain) < 4 || binary.BigEndian.Uint32(plain[:4]) != seq {
			return rpcErrorReply(call.xid, 1), session, nil
		}
	} else {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if !knownProcedure(call.proc) {
		return rpcErrorReply(call.xid, 3), session, nil
	}
	session.next++
	result := s.dispatch(session.client, call.proc, plain[4:])
	replyPlain := append(seqBytes(seq), result...)
	var wrapped, replyVerifier []byte
	if verifierSeq+1 == protectedSeq {
		replyVerifier, err = session.ctx.MIC(seqBytes(seq))
		if err == nil {
			wrapped, err = session.ctx.Wrap(replyPlain, true)
		}
	} else {
		wrapped, err = session.ctx.Wrap(replyPlain, true)
		if err == nil {
			replyVerifier, err = session.ctx.MIC(seqBytes(seq))
		}
	}
	if err != nil {
		return nil, session, err
	}
	body := xdrWriter{}
	body.opaque(wrapped)
	return rpcReply(call.xid, rpcsecGSS, replyVerifier, body.bytes()), session, nil
}

func knownProcedure(proc uint32) bool {
	switch proc {
	case initProcedure, createPrincipal, deletePrincipal, modifyPrincipal,
		renamePrincipal, getPrincipal, chpassPrincipal, chpassPrincipal3, chrandPrincipal,
		createPolicy, deletePolicy, modifyPolicy, getPolicy, getPrivs,
		getPrincs, getPolicies, getStrings, setString, setkeyPrincipal4,
		extractKeys:
		return true
	default:
		return false
	}
}

func nowUTC() time.Time           { return time.Now().UTC() }
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func rpcReply(xid, flavor uint32, verifier, body []byte) []byte {
	w := xdrWriter{}
	w.u32(xid)
	w.u32(msgReply)
	w.u32(replyAccepted)
	w.opaqueAuth(flavor, verifier)
	w.u32(acceptSuccess)
	w.raw(body)
	return w.bytes()
}

func rpcErrorReply(xid, status uint32) []byte {
	w := xdrWriter{}
	w.u32(xid)
	w.u32(msgReply)
	w.u32(replyAccepted)
	w.opaqueAuth(0, nil)
	w.u32(status)
	return w.bytes()
}

func (s *Server) authorize(client principal.Principal, op string, target principal.Principal) bool {
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

func (s *Server) authorizeRename(client, source, destination principal.Principal) bool {
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

func (s *Server) dispatch(client principal.Principal, proc uint32, body []byte) []byte {
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
		if !s.authorize(client, "create", entry.Principal) {
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
		if err := s.Database.CreatePrincipal(formatPrincipal(entry.Principal), password); err != nil {
			return status(kdbCode(err))
		}
		if mask&KADM5Policy != 0 {
			policy := policyName
			if mask&KADM5PolicyClear != 0 {
				policy = ""
			}
			if err := s.Database.SetPrincipalPolicy(entry.Principal, policy); err != nil {
				return status(kdbCode(err))
			}
		}
		_ = s.runHooks(HookPostCommit, event)
		_ = mask
		return status(0)
	case deletePrincipal:
		p, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "delete", p) {
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
		entry, err := decodeEntry(&r, api)
		if err != nil {
			return status(43787548)
		}
		mask, err := r.i32()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "modify", entry.Principal) {
			return status(authModify)
		}
		record, ok, err := s.Database.Lookup(entry.Principal)
		if err != nil || !ok {
			return status(43787534)
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
		if !s.authorize(client, "get", p) {
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
		if proc == chpassPrincipal3 {
			keepOld, err = r.boolean()
			if err != nil {
				return status(43787548)
			}
			count, err := r.u32()
			if err != nil || count > 1024 {
				return status(43787548)
			}
			for i := uint32(0); i < count; i++ {
				if _, err := r.i32(); err != nil {
					return status(43787548)
				}
				if _, err := r.i32(); err != nil {
					return status(43787548)
				}
			}
		}
		password, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "change-password", p) {
			return status(authChangePass)
		}
		record, ok, err := s.Database.Lookup(p)
		if err != nil || !ok {
			return status(43787534)
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
		if qualityErr := s.checkPasswordQuality(password, record.Policy, p); qualityErr != nil {
			return status(kdbCode(qualityErr))
		}
		event := HookEvent{Operation: "chpass", Principal: p, Password: password, KeepOld: keepOld}
		if hookErr := s.runHooks(HookPreCommit, event); hookErr != nil {
			return status(kdbCode(hookErr))
		}
		err = s.Database.ChangePasswordWithPolicy(p, password, s.now(), policy, bypassMinLife)
		if err == nil {
			_ = s.runHooks(HookPostCommit, event)
		}
		return status(kdbCode(err))
	case chrandPrincipal:
		p, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "change-password", p) {
			return status(authChangePass)
		}
		keys, err := s.Database.RandomizeKeys(p)
		if err != nil {
			return status(kdbCode(err))
		}
		w := xdrWriter{}
		w.raw(status(0))
		w.u32(uint32(len(keys)))
		for _, key := range keys {
			w.i32(key.Enctype)
			w.opaque(key.Key)
		}
		return w.bytes()
	case getPrincs:
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
		policy, err := readPolicy(&r, api)
		if err != nil {
			return status(43787548)
		}
		mask, err := r.i32()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, map[uint32]string{createPolicy: "create-policy", modifyPolicy: "modify-policy"}[proc], principal.Principal{}) {
			return status(authAdd)
		}
		kp := policyRecord(policy)
		if proc == createPolicy {
			err = s.Database.CreatePolicy(kp)
		} else {
			old, getErr := s.Database.GetPolicy(policy.Name)
			if getErr == nil {
				applyPolicy(&old, kp, mask)
				err = s.Database.UpdatePolicy(old)
			} else {
				err = getErr
			}
		}
		return status(kdbCode(err))
	case deletePolicy:
		name, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "delete-policy", principal.Principal{}) {
			return status(authDelete)
		}
		return status(kdbCode(s.Database.DeletePolicy(name)))
	case getPolicy:
		name, err := r.nullString()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "get-policy", principal.Principal{}) {
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
		p, err := readPrincipal()
		if err != nil || r.done() != nil {
			return status(43787548)
		}
		if !s.authorize(client, "get", p) {
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
		if !s.authorize(client, "modify", p) {
			return status(authModify)
		}
		return status(kdbCode(s.Database.SetString(p, *key, value)))
	case extractKeys:
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
		if !s.authorize(client, "set-key", p) {
			return status(authSetKey)
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

const initProcedure = 13

func statusReply(api, code uint32) []byte {
	w := xdrWriter{}
	w.u32(api)
	w.u32(code)
	return w.bytes()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func kdbCode(err error) uint32 {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, kdb.ErrPrincipalExists):
		return 43787527
	case errors.Is(err, kdb.ErrPrincipalNotFound):
		return 43787534
	case errors.Is(err, kdb.ErrPolicyExists):
		return 43787527
	case errors.Is(err, kdb.ErrPolicyNotFound):
		return 43787533
	case errors.Is(err, kdb.ErrPolicyInUse):
		return 43787547
	case errors.Is(err, kdb.ErrPasswordTooShort):
		return passTooShort
	case errors.Is(err, kdb.ErrPasswordClasses):
		return passClass
	case errors.Is(err, kdb.ErrPasswordReuse):
		return passReuse
	case errors.Is(err, kdb.ErrPasswordTooSoon):
		return passTooSoon
	case qualityCode(err) != 0:
		return qualityCode(err)
	default:
		return 43787548
	}
}

func formatPrincipal(p principal.Principal) string {
	s, _ := p.Format()
	return s
}

func recordEntry(r kdb.PrincipalRecord) PrincipalEntry {
	expire, pwExpire := int32(0), int32(0)
	if !r.Expiration.IsZero() {
		expire = int32(r.Expiration.Unix())
	}
	if !r.PasswordExpiration.IsZero() {
		pwExpire = int32(r.PasswordExpiration.Unix())
	}
	return PrincipalEntry{
		Principal: r.Name, PrincExpireTime: expire,
		LastPwdChange: unixSeconds(r.LastPasswordChange), PWExpiration: pwExpire,
		MaxLife: int32(r.MaxLife / time.Second), Attributes: int32(r.Flags),
		KVNO: r.KVNO, Policy: r.Policy, MaxRenewableLife: int32(r.MaxRenew / time.Second),
	}
}

func applyEntry(r *kdb.PrincipalRecord, e PrincipalEntry, mask int32) {
	if mask&KADM5Attributes != 0 {
		r.Flags = uint32(e.Attributes)
	}
	if mask&KADM5PrincExpireTime != 0 {
		r.Expiration = unixTime(e.PrincExpireTime)
	}
	if mask&KADM5LastPwdChange != 0 {
		r.LastPasswordChange = unixTime(e.LastPwdChange)
	}
	if mask&KADM5PWExpiration != 0 {
		r.PasswordExpiration = unixTime(e.PWExpiration)
	}
	if mask&KADM5MaxLife != 0 {
		r.MaxLife = time.Duration(e.MaxLife) * time.Second
	}
	if mask&KADM5MaxRenewableLife != 0 {
		r.MaxRenew = time.Duration(e.MaxRenewableLife) * time.Second
	}
	if mask&KADM5Policy != 0 {
		if mask&KADM5PolicyClear != 0 {
			r.Policy = ""
		} else {
			r.Policy = e.Policy
		}
	}
}

func unixTime(value int32) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0).UTC()
}

func unixSeconds(value time.Time) int32 {
	if value.IsZero() {
		return 0
	}
	return int32(value.Unix())
}

func policyRecord(p Policy) kdb.PolicyRecord {
	return kdb.PolicyRecord{Name: p.Name, MinLife: p.MinLife, MaxLife: p.MaxLife, MinLength: p.MinLength,
		MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure,
		FailureCountInterval: p.FailureCountInterval, LockoutDuration: p.LockoutDuration,
		Attributes: p.Attributes, MaxTicketLife: p.MaxTicketLife, MaxRenewableLife: p.MaxRenewableLife}
}

func policyValue(p kdb.PolicyRecord) Policy {
	return Policy{Name: p.Name, MinLife: p.MinLife, MaxLife: p.MaxLife, MinLength: p.MinLength,
		MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure,
		FailureCountInterval: p.FailureCountInterval, LockoutDuration: p.LockoutDuration,
		Attributes: p.Attributes, MaxTicketLife: p.MaxTicketLife, MaxRenewableLife: p.MaxRenewableLife}
}

func applyPolicy(dst *kdb.PolicyRecord, src kdb.PolicyRecord, mask int32) {
	if mask&KADM5PWMinLife != 0 {
		dst.MinLife = src.MinLife
	}
	if mask&KADM5PWMaxLife != 0 {
		dst.MaxLife = src.MaxLife
	}
	if mask&KADM5PWMinLength != 0 {
		dst.MinLength = src.MinLength
	}
	if mask&KADM5PWMinClasses != 0 {
		dst.MinClasses = src.MinClasses
	}
	if mask&KADM5PWHistoryNum != 0 {
		dst.HistoryNum = src.HistoryNum
	}
	if mask&KADM5PWMaxFailure != 0 {
		dst.MaxFailure = src.MaxFailure
	}
	if mask&KADM5PWFailureCountInterval != 0 {
		dst.FailureCountInterval = src.FailureCountInterval
	}
	if mask&KADM5PWLockoutDuration != 0 {
		dst.LockoutDuration = src.LockoutDuration
	}
	if mask&KADM5PolicyAttributes != 0 {
		dst.Attributes = src.Attributes
	}
	if mask&KADM5PolicyMaxLife != 0 {
		dst.MaxTicketLife = src.MaxTicketLife
	}
	if mask&KADM5PolicyMaxRenewableLife != 0 {
		dst.MaxRenewableLife = src.MaxRenewableLife
	}
}

func (s *Server) listPrincipals(expr string) []string {
	var out []string
	if expr != "" && !strings.Contains(expr, "@") {
		expr += "@" + s.Database.Realm
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

func readRPCRecord(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	var out []byte
	for {
		size := int(n & 0x7fffffff)
		if size > ServerMaxRecord-len(out) {
			return nil, errors.New("kadm5: oversized RPC record")
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if n&0x80000000 != 0 {
			return out, nil
		}
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, err
		}
		n = binary.BigEndian.Uint32(header[:])
	}
}

func writeRPCRecord(conn net.Conn, data []byte) error {
	if len(data) > ServerMaxRecord {
		return errors.New("kadm5: oversized RPC record")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data))|0x80000000)
	if err := writeAll(conn, header[:]); err != nil {
		return err
	}
	return writeAll(conn, data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

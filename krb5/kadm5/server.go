package kadm5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/klog"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/trace"
)

const (
	// ServerMaxRecord is the largest RPC record accepted by Server.
	ServerMaxRecord  = 16 << 20
	authGet          = 43787521
	authAdd          = 43787522
	authModify       = 43787523
	authDelete       = 43787524
	authChangePass   = 43787572
	authSetKey       = 43787577
	authExtract      = 43787587
	authList         = 43787571
	authInsufficient = 43787525
	protectKeys      = 43787588
	apiUnsupported   = 43787530
	passTooShort     = 43787542
	passClass        = 43787543
	passReuse        = 43787545
	passTooSoon      = 43787546
	authInitial      = 43787581
)

// Server implements the kadm5 RPC service over a TCP listener.
//
// Keytab must contain the kadmin/admin service key.  Database is required for
// the mutable in-memory implementation.  ACL, when non-nil, is consulted for
// every operation; otherwise only AdminPrincipal is authorized.
type Server struct {
	Database Backend
	// Trace is invoked synchronously from concurrent request goroutines;
	// callbacks must be safe for concurrent use.
	Trace          trace.Callback
	Keytab         *keytab.Keytab
	AdminPrincipal principal.Principal
	ACL            func(client principal.Principal, operation string, target principal.Principal) bool
	// AuthModules enables MIT-shaped pluggable authorization. When non-nil,
	// including an empty non-nil list, the configured modules are combined with
	// the optional ACL adapter and the built-in self-service module. This
	// replaces the legacy admin-only fallback and allows self-service
	// cpw/chrand/purgekeys/getprinc/getstrs operations.
	AuthModules []AuthModule
	API         uint32
	ErrorLog    func(error)
	Logger      *klog.Logger
	Now         func() time.Time
	// PasswordQualityModules are evaluated after the named policy. A nil value
	// uses MIT's built-in empty and princ modules.
	PasswordQualityModules []PasswordQualityModule
	// Hooks run in order around principal mutations.
	Hooks []Kadm5Hook
	// DictionaryFile configures the optional MIT dictionary module.
	DictionaryFile string

	wg            sync.WaitGroup
	dictionaryMu  sync.Mutex
	dictionary    *DictionaryPasswordQuality
	dictionaryKey string
}

func (s *Server) reportError(err error) {
	if err == nil {
		return
	}
	if s.Trace != nil {
		s.Trace(fmt.Sprintf("kadm5: error: %v", err))
	}
	if s.Logger != nil {
		s.Logger.Error("%v", err)
	}
	if s.ErrorLog != nil {
		s.ErrorLog(err)
	}
}

// Backend is the mutable principal and policy store used by the kadm5 server.
// Implementations should return the kdb sentinel errors used by the RPC
// mapping, such as ErrPrincipalExists, ErrPrincipalNotFound, and
// ErrBadKeySalts, so callers receive the correct kadm5 status. Each method
// should apply its operation atomically.
type Backend interface {
	Lookup(principal.Principal) (kdb.PrincipalRecord, bool, error)
	CreatePrincipalWithOptions(string, string, *kdb.PolicyRecord) error
	CreatePrincipalWithKeySaltsAndOptions(string, string, []kdb.KeySaltTuple, *kdb.PolicyRecord) error
	DeletePrincipal(principal.Principal) error
	UpdatePrincipal(kdb.PrincipalRecord) error
	RenamePrincipal(principal.Principal, principal.Principal) error
	ChangePasswordWithPolicyAndKeepOld(principal.Principal, string, time.Time, *kdb.PolicyRecord, bool, bool) error
	RandomizeKeys(principal.Principal) ([]kdb.Key, error)
	RandomizeKeysWithKeySalts(principal.Principal, bool, []kdb.KeySaltTuple) ([]kdb.Key, error)
	SetKeys(principal.Principal, []kdb.Key, bool) error
	PurgeKeys(principal.Principal, int32) error
	AddAlias(string, string) error
	GetPolicy(string) (kdb.PolicyRecord, error)
	CreatePolicy(kdb.PolicyRecord) error
	UpdatePolicy(kdb.PolicyRecord) error
	DeletePolicy(string) error
	ListPolicies() []string
	GetStrings(principal.Principal) (map[string]string, error)
	SetString(principal.Principal, string, *string) error
	ListPrincipals() []string
	CheckPasswordPolicy(principal.Principal, string, time.Time, *kdb.PolicyRecord, bool) error
	GetRealm() string
}

type passwordKeySaltBackend interface {
	ChangePasswordWithKeySaltsAndPolicy(principal.Principal, string, time.Time,
		*kdb.PolicyRecord, bool, bool, []kdb.KeySaltTuple) error
}

var _ Backend = (*kdb.Database)(nil)

func backendIsNil(backend Backend) bool {
	if backend == nil {
		return true
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// NewServer creates a v4 kadm5 server.
func NewServer(database Backend, serviceKeytab *keytab.Keytab) *Server {
	return &Server{Database: database, Keytab: serviceKeytab, API: APIv4}
}

// Serve accepts kadm5 RPC connections until the listener fails.
func (s *Server) Serve(listener net.Listener) error {
	if s == nil || backendIsNil(s.Database) || s.Keytab == nil {
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

// ServeWithIPROP serves kadm5 and the separately registered MIT KIPROP
// service. MIT kadmind uses distinct listeners and ports for these RPC
// programs, so the listeners must be configured from kadm5_port and
// iprop_port respectively.
func (s *Server) ServeWithIPROP(kadmListener, ipropListener net.Listener,
	ipropServer *iprop.Server) error {
	if ipropServer == nil {
		return errors.New("kadm5: nil iprop server")
	}
	errs := make(chan error, 2)
	go func() { errs <- s.Serve(kadmListener) }()
	go func() { errs <- ipropServer.Serve(ipropListener) }()
	err := <-errs
	_ = kadmListener.Close()
	_ = ipropListener.Close()
	<-errs
	return err
}

type serverSession struct {
	ctx       *gssapi.Context
	client    principal.Principal
	initial   bool
	service   principal.Principal
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
			s.reportError(err)
			return err
		}
		var reply []byte
		if call.flavor == rpcsecGSS {
			reply, session, err = s.handleGSS(conn, call, session)
		} else {
			s.reportError(errors.New("kadm5: unsupported RPC authentication flavor"))
			reply = rpcErrorReply(call.xid, 1)
			err = nil
		}
		if err != nil {
			s.reportError(err)
			return err
		}
		if err := writeRPCRecord(conn, reply); err != nil {
			s.reportError(err)
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

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
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

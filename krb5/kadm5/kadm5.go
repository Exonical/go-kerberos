// Package kadm5 implements the minimal MIT kadm5 administrative RPC client.
package kadm5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	Program          = 2112
	Version          = 2
	APIv2            = 0x12345702
	APIv3            = 0x12345703
	APIv4            = 0x12345704
	AuthGSSAPI       = 300001
	rpcVersion       = 2
	msgCall          = 0
	msgReply         = 1
	replyAccepted    = 0
	acceptSuccess    = 0
	authGSSInit      = 1
	authGSSCont      = 2
	authGSSMsg       = 3
	authGSSDestroy   = 4
	rpcsecGSS        = 6
	rpcsecGSSData    = 0
	rpcsecGSSInit    = 1
	rpcsecGSSCont    = 2
	rpcsecGSSPrivacy = 3
	getPrincipal     = 5
	createPrincipal  = 1
	deletePrincipal  = 2
	modifyPrincipal  = 3
	renamePrincipal  = 4
	chpassPrincipal  = 6
	chpassPrincipal3 = 19
	chrandPrincipal  = 7
	createPolicy     = 8
	deletePolicy     = 9
	modifyPolicy     = 10
	getPolicy        = 11
	getPrivs         = 12
	getPrincs        = 14
	getPolicies      = 15
	setkeyPrincipal4 = 25
	extractKeys      = 26
	createPrincipal3 = 18
	chrandPrincipal3 = 20
	setkeyPrincipal  = 16
	setkeyPrincipal3 = 21
	purgeKeys        = 22
	createAlias      = 27
	getStrings       = 23
	setString        = 24
)

var xidCounter uint32 = uint32(time.Now().UnixNano())

// ErrNotFound indicates that the requested principal does not exist.
var ErrNotFound = errors.New("kadm5: principal not found")

// Common MIT kadm5 operation errors.
var (
	ErrDuplicate     = errors.New("kadm5: principal or policy already exists")
	ErrUnknownPolicy = errors.New("kadm5: policy not found")
	ErrPolicyInUse   = errors.New("kadm5: policy is in use")
)

const (
	// Principal entry field masks from kadm5/admin.h.
	KADM5Principal        int32 = 0x000001
	KADM5PrincExpireTime  int32 = 0x000002
	KADM5PWExpiration     int32 = 0x000004
	KADM5LastPwdChange    int32 = 0x000008
	KADM5Attributes       int32 = 0x000010
	KADM5MaxLife          int32 = 0x000020
	KADM5ModTime          int32 = 0x000040
	KADM5ModName          int32 = 0x000080
	KADM5KVNO             int32 = 0x000100
	KADM5MKVNO            int32 = 0x000200
	KADM5AuxAttributes    int32 = 0x000400
	KADM5Policy           int32 = 0x000800
	KADM5PolicyClear      int32 = 0x001000
	KADM5MaxRenewableLife int32 = 0x002000
	KADM5LastSuccess      int32 = 0x004000
	KADM5LastFailed       int32 = 0x008000
	KADM5FailAuthCount    int32 = 0x010000
	KADM5KeyData          int32 = 0x020000
	KADM5TLData           int32 = 0x040000

	// Policy entry field masks from kadm5/admin.h.
	KADM5PWMaxLife              int32 = 0x004000
	KADM5PWMinLife              int32 = 0x008000
	KADM5PWMinLength            int32 = 0x010000
	KADM5PWMinClasses           int32 = 0x020000
	KADM5PWHistoryNum           int32 = 0x040000
	KADM5RefCount               int32 = 0x080000
	KADM5PWMaxFailure           int32 = 0x100000
	KADM5PWFailureCountInterval int32 = 0x200000
	KADM5PWLockoutDuration      int32 = 0x400000
	KADM5PolicyAttributes       int32 = 0x800000
	KADM5PolicyMaxLife          int32 = 0x01000000
	KADM5PolicyMaxRenewableLife int32 = 0x02000000
	KADM5PolicyAllowedKeysalts  int32 = 0x04000000
	KADM5PolicyTLData           int32 = 0x08000000
)

// PrincipalEntry is the safe subset of a kadm5 principal entry returned by
// GET_PRINCIPAL.  The wire record contains additional administrative fields.
type PrincipalEntry struct {
	Principal        principal.Principal
	PrincExpireTime  int32
	LastPwdChange    int32
	PWExpiration     int32
	MaxLife          int32
	Attributes       int32
	KVNO             uint32
	MKVNO            uint32
	Policy           string
	AuxAttributes    int32
	MaxRenewableLife int32
	LastSuccess      int32
	LastFailed       int32
	FailAuthCount    uint32
}

// Key is a keyblock returned by RandKey. Key material is returned to the
// caller and is never logged by this package.
type Key struct {
	Enctype int32
	Key     []byte
}

// KeySaltTuple selects an enctype and salt type for key generation.
type KeySaltTuple struct {
	Enctype  int32
	SaltType int32
}

// StringAttribute is a per-principal string attribute.
type StringAttribute struct {
	Key   string
	Value string
}

// KeyData is a principal key and its associated salt metadata.
type KeyData struct {
	KVNO     uint32
	Enctype  int32
	Key      []byte
	SaltType int16
	Salt     []byte
}

// Policy is the safe common subset of an MIT kadm5 policy entry.
type Policy struct {
	Name                 string
	MinLife              int32
	MaxLife              int32
	MinLength            int32
	MinClasses           int32
	HistoryNum           int32
	MaxFailure           uint32
	FailureCountInterval int32
	LockoutDuration      int32
	Attributes           int32
	MaxTicketLife        int32
	MaxRenewableLife     int32
	AllowedKeySalts      string
}

// Client is a pure-Go client for the MIT kadmind RPC service.
type Client struct {
	Conn             net.Conn
	AdminCredentials *client.Credentials
	Timeout          time.Duration
	API              uint32
	auth             *rpcAuth
}

// Dial obtains a kadmin/admin service ticket and connects to kadmind.
func Dial(ctx context.Context, kerberos *client.Client, admin principal.Principal,
	credentials *client.Credentials, address string) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("kadm5: nil context")
	}
	if credentials == nil {
		return nil, errors.New("kadm5: missing admin credentials")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("kadm5 dial: %w", err)
	}
	c := &Client{Conn: conn, AdminCredentials: credentials, Timeout: 25 * time.Second, API: APIv4}
	if err := c.authenticate(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.initAPI(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// New creates a client over an already connected socket. It is useful for
// synthetic tests and callers that control dialing themselves.
func New(conn net.Conn, credentials *client.Credentials) *Client {
	return &Client{Conn: conn, AdminCredentials: credentials, Timeout: 25 * time.Second, API: APIv4}
}

func (c *Client) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

// GetPrincipal reads a principal entry.
func (c *Client) GetPrincipal(ctx context.Context, p principal.Principal) (PrincipalEntry, error) {
	body := xdrWriter{}
	body.u32(c.API)
	body.principal(p)
	body.i32(KADM5Principal | KADM5PrincExpireTime | KADM5Attributes |
		KADM5MaxLife | KADM5MaxRenewableLife | KADM5Policy)
	reply, err := c.call(ctx, getPrincipal, body.bytes())
	if err != nil {
		return PrincipalEntry{}, err
	}
	r := xdrReader{b: reply}
	api, err := r.u32()
	if err != nil {
		return PrincipalEntry{}, err
	}
	code, err := r.u32()
	if err != nil {
		return PrincipalEntry{}, err
	}
	if api != c.API && api != APIv2 && api != APIv3 && api != APIv4 {
		return PrincipalEntry{}, fmt.Errorf("kadm5: unsupported reply API %#x", api)
	}
	if code != 0 {
		return PrincipalEntry{}, operationError("GET_PRINCIPAL", code)
	}
	entry, err := decodeEntry(&r, c.API)
	if err != nil {
		return PrincipalEntry{}, err
	}
	if err := r.done(); err != nil {
		return PrincipalEntry{}, err
	}
	return entry, nil
}

// CreatePrincipal creates a principal with the supplied password.
func (c *Client) CreatePrincipal(ctx context.Context, p principal.Principal, password string) error {
	body := xdrWriter{}
	body.u32(c.API)
	writeEmptyEntry(&body, p)
	body.i32(1)
	body.nullString(password)
	return c.genericCall(ctx, createPrincipal, body.bytes())
}

// DeletePrincipal deletes a principal.
func (c *Client) DeletePrincipal(ctx context.Context, p principal.Principal) error {
	body := xdrWriter{}
	body.u32(c.API)
	body.principal(p)
	return c.genericCall(ctx, deletePrincipal, body.bytes())
}

// ChangePassword changes a principal's password.
func (c *Client) ChangePassword(ctx context.Context, p principal.Principal, password string) error {
	body := xdrWriter{}
	body.u32(c.API)
	body.principal(p)
	body.nullString(password)
	return c.genericCall(ctx, chpassPrincipal, body.bytes())
}

func (c *Client) genericCall(ctx context.Context, proc uint32, body []byte) error {
	reply, err := c.call(ctx, proc, body)
	if err != nil {
		return err
	}
	r := xdrReader{b: reply}
	api, err := r.u32()
	if err != nil {
		return err
	}
	code, err := r.u32()
	if err != nil {
		return err
	}
	if api != c.API && api != APIv2 && api != APIv3 && api != APIv4 {
		return fmt.Errorf("kadm5: unsupported reply API %#x", api)
	}
	if code != 0 {
		return operationError("RPC operation", code)
	}
	return r.done()
}

func (c *Client) authenticate(ctx context.Context) error {
	if c.AdminCredentials == nil {
		return errors.New("kadm5: missing credentials")
	}
	i, err := gssapi.NewInitiator(c.AdminCredentials, gssapi.GSSMutualFlag|gssapi.GSSReplayFlag|gssapi.GSSIntegrityFlag|gssapi.GSSConfidentialityFlag)
	if err != nil {
		return err
	}
	local, localOK := c.Conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := c.Conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || local.IP.To4() == nil || remote.IP.To4() == nil {
		return errors.New("kadm5: AUTH_GSSAPI requires TCP/IPv4 addresses")
	}
	token, err := i.InitialTokenWithChannelBindings(time.Now().UTC(), local.IP.To4(), remote.IP.To4())
	if err != nil {
		return err
	}
	proc := uint32(rpcsecGSSInit)
	for {
		cred := xdrWriter{}
		cred.u32(1)
		cred.u32(proc)
		cred.u32(0)
		cred.u32(rpcsecGSSPrivacy)
		cred.opaque(nil)
		arg := xdrWriter{}
		arg.opaque(token)
		xid := atomic.AddUint32(&xidCounter, 1)
		reply, verfFlavor, verf, err := c.rawCallFlavorXID(ctx, xid, 0, rpcsecGSS, cred.bytes(), nil, arg.bytes())
		if err != nil {
			return fmt.Errorf("kadm5 RPCSEC_GSS_INIT: %w", err)
		}
		r := xdrReader{b: reply}
		handle, err := r.opaque()
		if err != nil {
			return err
		}
		major, err := r.u32()
		if err != nil {
			return err
		}
		minor, err := r.u32()
		if err != nil {
			return err
		}
		win, err := r.u32()
		if err != nil {
			return err
		}
		next, err := r.opaque()
		if err != nil {
			return err
		}
		if err := r.done(); err != nil {
			return err
		}
		if major != 0 && major != 1 {
			return fmt.Errorf("kadm5: GSS init failed (%d, %d)", major, minor)
		}
		if len(next) != 0 {
			if err := i.VerifyToken(next); err != nil {
				return err
			}
		}
		if major == 1 {
			token = next
			proc = rpcsecGSSCont
			continue
		}
		gctx, err := i.Context()
		if err != nil {
			return err
		}
		if sequence, ok := i.SequenceNumber(); ok {
			gctx.SetSendSequence(uint64(sequence))
		} else {
			return errors.New("kadm5: missing AP-REQ sequence number")
		}
		if verfFlavor != rpcsecGSS {
			return errors.New("kadm5: invalid RPCSEC_GSS init verifier flavor")
		}
		if len(verf) < 16 {
			return errors.New("kadm5: truncated RPCSEC_GSS init verifier")
		}
		gctx.SetReceiveSequence(binary.BigEndian.Uint64(verf[8:16]))
		window := seqBytes(win)
		if err := gctx.VerifyMIC(window, verf); err != nil {
			return fmt.Errorf("kadm5: invalid RPCSEC_GSS init verifier: %w", err)
		}
		c.auth = &rpcAuth{ctx: gctx, handle: handle, seq: 1}
		return nil
	}
}

type rpcAuth struct {
	ctx    *gssapi.Context
	handle []byte
	seq    uint32
}

func (c *Client) initAPI(ctx context.Context) error {
	body := xdrWriter{}
	body.u32(c.API)
	reply, err := c.call(ctx, 13, body.bytes())
	if err != nil {
		return err
	}
	r := xdrReader{b: reply}
	api, err := r.u32()
	if err != nil {
		return err
	}
	code, err := r.u32()
	if err != nil {
		return err
	}
	if code == 43787530 && c.API > APIv2 {
		c.API--
		return c.initAPI(ctx)
	}
	if code != 0 {
		return fmt.Errorf("kadm5: INIT failed with code %d", code)
	}
	if api != c.API {
		return fmt.Errorf("kadm5: INIT API mismatch %#x", api)
	}
	return r.done()
}

func (c *Client) call(ctx context.Context, proc uint32, body []byte) ([]byte, error) {
	if c.auth == nil {
		return nil, errors.New("kadm5: unauthenticated client")
	}
	seq := c.auth.seq
	plain := append(seqBytes(seq), body...)
	protected, err := c.auth.ctx.Wrap(plain, true)
	if err != nil {
		return nil, err
	}
	cred := xdrWriter{}
	cred.u32(1)
	cred.u32(rpcsecGSSData)
	cred.u32(seq)
	cred.u32(rpcsecGSSPrivacy)
	cred.opaque(c.auth.handle)
	xid := atomic.AddUint32(&xidCounter, 1)
	prefix := c.rpcPrefix(xid, proc, rpcsecGSS, cred.bytes())
	verifier, err := c.auth.ctx.MIC(prefix)
	if err != nil {
		return nil, err
	}
	reply, verfFlavor, verf, err := c.rawCallFlavorXID(ctx, xid, proc, rpcsecGSS, cred.bytes(), verifier, xdrWriterBytes(opaque(protected)))
	if err != nil {
		return nil, err
	}
	if verfFlavor != rpcsecGSS {
		return nil, errors.New("kadm5: invalid RPCSEC_GSS reply verifier flavor")
	}
	if len(verf) < 16 {
		return nil, errors.New("kadm5: truncated RPCSEC_GSS reply verifier")
	}
	c.auth.ctx.SetReceiveSequence(binary.BigEndian.Uint64(verf[8:16]))
	if err := c.auth.ctx.VerifyMIC(seqBytes(seq), verf); err != nil {
		return nil, fmt.Errorf("kadm5: invalid reply verifier: %w", err)
	}
	r := xdrReader{b: reply}
	protectedReply, err := r.opaque()
	if err != nil {
		return nil, err
	}
	if len(protectedReply) < 16 {
		return nil, errors.New("kadm5: truncated protected reply token")
	}
	c.auth.ctx.SetReceiveSequence(binary.BigEndian.Uint64(protectedReply[8:16]))
	plainReply, err := c.auth.ctx.Unwrap(protectedReply)
	if err != nil {
		return nil, fmt.Errorf("kadm5: invalid protected reply: %w", err)
	}
	if len(plainReply) < 4 {
		return nil, errors.New("kadm5: truncated protected reply")
	}
	got := binary.BigEndian.Uint32(plainReply[:4])
	if got != seq {
		return nil, fmt.Errorf("kadm5: unexpected reply sequence %d", got)
	}
	c.auth.seq++
	return plainReply[4:], nil
}

func (c *Client) rawCallFlavor(ctx context.Context, proc uint32, flavor uint32, cred, verf, body []byte) ([]byte, error) {
	xid := atomic.AddUint32(&xidCounter, 1)
	reply, _, _, err := c.rawCallFlavorXID(ctx, xid, proc, flavor, cred, verf, body)
	return reply, err
}

func (c *Client) rawCallFlavorXID(ctx context.Context, xid uint32, proc uint32, flavor uint32, cred, verf, body []byte) ([]byte, uint32, []byte, error) {
	if c.Conn == nil {
		return nil, 0, nil, errors.New("kadm5: nil connection")
	}
	w := xdrWriter{}
	w.u32(xid)
	w.u32(msgCall)
	w.u32(rpcVersion)
	w.u32(Program)
	w.u32(Version)
	w.u32(proc)
	w.opaqueAuth(flavor, cred)
	if verf == nil {
		w.opaqueAuth(0, nil)
	} else {
		w.opaqueAuth(flavor, verf)
	}
	w.raw(body)
	if err := c.writeRecord(ctx, w.bytes()); err != nil {
		return nil, 0, nil, err
	}
	reply, err := c.readRecord(ctx)
	if err != nil {
		return nil, 0, nil, err
	}
	r := xdrReader{b: reply}
	got, err := r.u32()
	if err != nil {
		return nil, 0, nil, err
	}
	if got != xid {
		return nil, 0, nil, errors.New("kadm5: mismatched RPC XID")
	}
	msg, err := r.u32()
	if err != nil || msg != msgReply {
		return nil, 0, nil, errors.New("kadm5: invalid RPC reply type")
	}
	astat, err := r.u32()
	if err != nil {
		return nil, 0, nil, err
	}
	if astat != replyAccepted {
		reject, _ := r.u32()
		return nil, 0, nil, fmt.Errorf("kadm5: RPC reply rejected (%d, %d)", astat, reject)
	}
	replyFlavor, replyVerifier, err := r.opaqueAuth()
	if err != nil {
		return nil, 0, nil, err
	}
	stat, err := r.u32()
	if err != nil || stat != acceptSuccess {
		return nil, 0, nil, fmt.Errorf("kadm5: RPC call failed (%d)", stat)
	}
	return append([]byte(nil), r.b[r.off:]...), replyFlavor, replyVerifier, nil
}

func seqBytes(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func (c *Client) rpcPrefix(xid, proc, flavor uint32, cred []byte) []byte {
	w := xdrWriter{}
	w.u32(xid)
	w.u32(msgCall)
	w.u32(rpcVersion)
	w.u32(Program)
	w.u32(Version)
	w.u32(proc)
	w.opaqueAuth(flavor, cred)
	return w.bytes()
}

func (c *Client) writeRecord(ctx context.Context, data []byte) error {
	if len(data) > 16<<20 {
		return errors.New("kadm5: oversized RPC record")
	}
	if err := c.deadline(ctx); err != nil {
		return err
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(data))|0x80000000)
	if _, err := c.Conn.Write(h[:]); err != nil {
		return err
	}
	_, err := c.Conn.Write(data)
	return err
}
func (c *Client) readRecord(ctx context.Context) ([]byte, error) {
	if err := c.deadline(ctx); err != nil {
		return nil, err
	}
	var h [4]byte
	if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n&0x7fffffff > 16<<20 {
		return nil, errors.New("kadm5: oversized RPC fragment")
	}
	var out []byte
	for {
		size := int(n & 0x7fffffff)
		chunk := make([]byte, size)
		if _, err := io.ReadFull(c.Conn, chunk); err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > 16<<20 {
			return nil, errors.New("kadm5: oversized RPC record")
		}
		if n&0x80000000 != 0 {
			return out, nil
		}
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return nil, err
		}
		n = binary.BigEndian.Uint32(h[:])
		if n&0x7fffffff > 16<<20 {
			return nil, errors.New("kadm5: oversized RPC fragment")
		}
	}
}
func (c *Client) deadline(ctx context.Context) error {
	if ctx == nil {
		return errors.New("kadm5: nil context")
	}
	d, ok := ctx.Deadline()
	if !ok && c.Timeout > 0 {
		d = time.Now().Add(c.Timeout)
	}
	if ok || c.Timeout > 0 {
		return c.Conn.SetDeadline(d)
	}
	return nil
}

type initReply struct {
	version                  uint32
	handle, token, signedISN []byte
	major, minor             uint32
}

func parseInitReply(data []byte) (initReply, error) {
	r := xdrReader{b: data}
	v, e := r.u32()
	if e != nil {
		return initReply{}, e
	}
	h, e := r.opaque()
	if e != nil {
		return initReply{}, e
	}
	ma, e := r.u32()
	if e != nil {
		return initReply{}, e
	}
	mi, e := r.u32()
	if e != nil {
		return initReply{}, e
	}
	t, e := r.opaque()
	if e != nil {
		return initReply{}, e
	}
	s, e := r.opaque()
	if e != nil {
		return initReply{}, e
	}
	if e = r.done(); e != nil {
		return initReply{}, e
	}
	return initReply{v, h, t, s, ma, mi}, nil
}

func decodeEntry(r *xdrReader, api uint32) (PrincipalEntry, error) {
	p, e := r.principal()
	if e != nil {
		return PrincipalEntry{}, e
	}
	expire, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	lastPwd, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	pwExpire, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	maxLife, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	has, e := r.boolean()
	if e != nil {
		return PrincipalEntry{}, e
	}
	if !has {
		if _, e = r.principal(); e != nil {
			return PrincipalEntry{}, e
		}
	}
	if _, e = r.i32(); e != nil { // modification time
		return PrincipalEntry{}, e
	}
	attrs, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	kvno, e := r.u32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	mkvno, e := r.u32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	policy, e := r.nullString()
	if e != nil {
		return PrincipalEntry{}, e
	}
	aux, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	maxRenew, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	if _, e = r.i32(); e != nil { // last success
		return PrincipalEntry{}, e
	}
	lastFailed, e := r.i32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	failCount, e := r.u32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	nKeyData, e := r.i16()
	if e != nil {
		return PrincipalEntry{}, e
	}
	nTLData, e := r.i16()
	if e != nil {
		return PrincipalEntry{}, e
	}
	if nKeyData < 0 || nTLData < 0 {
		return PrincipalEntry{}, errors.New("kadm5: negative principal data count")
	}
	more, e := r.boolean()
	if e != nil {
		return PrincipalEntry{}, e
	}
	tlCount := 0
	if !more {
		more, e = r.boolean()
		for more {
			tlCount++
			if _, e = r.i16(); e != nil {
				return PrincipalEntry{}, e
			}
			if _, e = r.opaque(); e != nil {
				return PrincipalEntry{}, e
			}
			more, e = r.boolean()
			if e != nil {
				return PrincipalEntry{}, e
			}
		}
	}
	if tlCount != int(nTLData) {
		return PrincipalEntry{}, errors.New("kadm5: principal TL data count mismatch")
	}
	n, e := r.u32()
	if e != nil {
		return PrincipalEntry{}, e
	}
	if n > 1<<20 {
		return PrincipalEntry{}, errors.New("kadm5: oversized key data array")
	}
	if n != uint32(nKeyData) {
		return PrincipalEntry{}, errors.New("kadm5: principal key data count mismatch")
	}
	for i := uint32(0); i < n; i++ {
		ver, e := r.i16()
		if e != nil {
			return PrincipalEntry{}, e
		}
		if _, e = r.u16(); e != nil {
			return PrincipalEntry{}, e
		}
		if _, e = r.i16(); e != nil {
			return PrincipalEntry{}, e
		}
		if ver > 1 {
			if _, e = r.i16(); e != nil {
				return PrincipalEntry{}, e
			}
		}
	}
	return PrincipalEntry{
		Principal: p, PrincExpireTime: expire, LastPwdChange: lastPwd,
		PWExpiration: pwExpire, MaxLife: maxLife, Attributes: attrs,
		KVNO: kvno, MKVNO: mkvno, Policy: policy, AuxAttributes: aux,
		MaxRenewableLife: maxRenew, LastFailed: lastFailed,
		FailAuthCount: failCount,
	}, nil
}

func writeEmptyEntry(w *xdrWriter, p principal.Principal) {
	writeEntry(w, PrincipalEntry{Principal: p}, 0)
}

func writeEntry(w *xdrWriter, entry PrincipalEntry, mask int32) {
	writeEntryWithModifier(w, entry, mask, false)
}

func writeEntryWithModifier(w *xdrWriter, entry PrincipalEntry, mask int32, modifier bool) {
	p := entry.Principal
	w.principal(p)
	w.i32(entry.PrincExpireTime)
	w.i32(entry.LastPwdChange)
	w.i32(entry.PWExpiration)
	w.i32(entry.MaxLife)
	w.boolean(!modifier)
	if modifier {
		w.principal(p)
	}
	w.i32(0)
	w.i32(entry.Attributes)
	w.u32(entry.KVNO)
	w.u32(entry.MKVNO)
	if mask&KADM5Policy != 0 && mask&KADM5PolicyClear == 0 {
		w.nullString(entry.Policy)
	} else {
		w.nullString("")
	}
	w.i32(entry.AuxAttributes)
	w.i32(entry.MaxRenewableLife)
	w.i32(entry.LastSuccess)
	w.i32(entry.LastFailed)
	w.u32(entry.FailAuthCount)
	w.i16(0)
	w.i16(0)
	w.boolean(true)
	w.u32(0)
}

func operationError(operation string, code uint32) error {
	switch code {
	case 43787527:
		return fmt.Errorf("kadm5: %s: %w", operation, ErrDuplicate)
	case 43787529, 43787532, 43787534, 43787535:
		return fmt.Errorf("kadm5: %s: %w", operation, ErrNotFound)
	case 43787533:
		return fmt.Errorf("kadm5: %s: %w", operation, ErrUnknownPolicy)
	case 43787547:
		return fmt.Errorf("kadm5: %s: %w", operation, ErrPolicyInUse)
	default:
		return fmt.Errorf("kadm5: %s failed with code %d", operation, code)
	}
}

type xdrWriter struct{ b bytes.Buffer }

func (w *xdrWriter) raw(v []byte) { w.b.Write(v) }
func (w *xdrWriter) u32(v uint32) { binary.Write(&w.b, binary.BigEndian, v) }
func (w *xdrWriter) i32(v int32)  { w.u32(uint32(v)) }
func (w *xdrWriter) u16(v uint16) { w.u32(uint32(v)) }
func (w *xdrWriter) i16(v int16)  { w.i32(int32(v)) }
func (w *xdrWriter) boolean(v bool) {
	if v {
		w.u32(1)
	} else {
		w.u32(0)
	}
}
func (w *xdrWriter) opaque(v []byte) {
	w.u32(uint32(len(v)))
	w.b.Write(v)
	for (w.b.Len() % 4) != 0 {
		w.b.WriteByte(0)
	}
}
func (w *xdrWriter) nullString(v string) {
	if v == "" {
		w.u32(0)
		return
	}
	w.opaque(append([]byte(v), 0))
}
func (w *xdrWriter) nullableString(v *string) {
	if v == nil {
		w.u32(0)
		return
	}
	w.opaque(append([]byte(*v), 0))
}
func (w *xdrWriter) principal(p principal.Principal)    { s, _ := p.Format(); w.nullString(s) }
func (w *xdrWriter) opaqueAuth(flavor uint32, v []byte) { w.u32(flavor); w.opaque(v) }
func (w *xdrWriter) bytes() []byte                      { return w.b.Bytes() }
func xdrWriterBytes(v []byte) []byte                    { return v }
func opaque(v []byte) []byte                            { w := xdrWriter{}; w.opaque(v); return w.bytes() }

type xdrReader struct {
	b   []byte
	off int
}

func (r *xdrReader) need(n int) error {
	if n < 0 || r.off > len(r.b)-n {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (r *xdrReader) u32() (uint32, error) {
	if e := r.need(4); e != nil {
		return 0, e
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, nil
}
func (r *xdrReader) i32() (int32, error)  { v, e := r.u32(); return int32(v), e }
func (r *xdrReader) u16() (uint16, error) { v, e := r.u32(); return uint16(v), e }
func (r *xdrReader) i16() (int16, error)  { v, e := r.i32(); return int16(v), e }
func (r *xdrReader) boolean() (bool, error) {
	v, e := r.u32()
	if e != nil {
		return false, e
	}
	if v > 1 {
		return false, errors.New("kadm5: invalid boolean")
	}
	return v != 0, nil
}
func (r *xdrReader) opaque() ([]byte, error) {
	n, e := r.u32()
	if e != nil {
		return nil, e
	}
	if n > 16<<20 {
		return nil, errors.New("kadm5: oversized XDR opaque")
	}
	p := int(n)
	if e = r.need(p); e != nil {
		return nil, e
	}
	v := append([]byte(nil), r.b[r.off:r.off+p]...)
	r.off += p
	pad := (4 - p%4) % 4
	if e = r.need(pad); e != nil {
		return nil, e
	}
	for _, b := range r.b[r.off : r.off+pad] {
		if b != 0 {
			return nil, errors.New("kadm5: non-zero XDR padding")
		}
	}
	r.off += pad
	return v, nil
}
func (r *xdrReader) nullString() (string, error) {
	v, e := r.nullableString()
	if e != nil {
		return "", e
	}
	if v == nil {
		return "", nil
	}
	return *v, nil
}
func (r *xdrReader) nullableString() (*string, error) {
	v, e := r.opaque()
	if e != nil {
		return nil, e
	}
	if len(v) == 0 {
		return nil, nil
	}
	if v[len(v)-1] != 0 || bytes.IndexByte(v[:len(v)-1], 0) >= 0 {
		return nil, errors.New("kadm5: invalid null string")
	}
	s := string(v[:len(v)-1])
	return &s, nil
}
func (r *xdrReader) principal() (principal.Principal, error) {
	s, e := r.nullString()
	if e != nil {
		return principal.Principal{}, e
	}
	if s == "" {
		return principal.Principal{}, errors.New("kadm5: nil principal")
	}
	p, e := principal.Parse(s)
	if e != nil {
		return principal.Principal{}, e
	}
	return *p, nil
}
func (r *xdrReader) opaqueAuth() (uint32, []byte, error) {
	f, e := r.u32()
	if e != nil {
		return 0, nil, e
	}
	v, e := r.opaque()
	if e != nil {
		return 0, nil, e
	}
	return f, v, nil
}
func (r *xdrReader) done() error {
	if r.off != len(r.b) {
		return errors.New("kadm5: trailing XDR data")
	}
	return nil
}

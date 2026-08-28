package iprop

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	msgCall       uint32 = 0
	msgReply      uint32 = 1
	rpcVersion    uint32 = 2
	authNone      uint32 = 0
	authRPCSecGSS uint32 = 6
	gssData       uint32 = 0
	gssInit       uint32 = 1
	gssCont       uint32 = 2
	gssPrivacy    uint32 = 3
	maxRecord            = 16 << 20
)

var xidCounter uint32

// Client is an authenticated iprop RPC client. Credentials must contain a
// service ticket for kiprop/<master-host>@REALM.
type Client struct {
	Conn        net.Conn
	Credentials *client.Credentials
	Timeout     time.Duration
	auth        *rpcAuth
}

// NewClient creates a client on an already-connected TCP socket.
func NewClient(conn net.Conn, credentials *client.Credentials) *Client {
	return &Client{Conn: conn, Credentials: credentials, Timeout: 25 * time.Second}
}

// Authenticate establishes the RPCSEC_GSS context for a connected client.
func (c *Client) Authenticate(ctx context.Context) error {
	if c == nil {
		return errors.New("iprop: nil client")
	}
	if c.auth != nil {
		return nil
	}
	return c.authenticate(ctx)
}

// Dial creates and authenticates an iprop client over an existing address.
func Dial(ctx context.Context, address string, credentials *client.Credentials) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("iprop: nil context")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	c := NewClient(conn, credentials)
	if err := c.Authenticate(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

// Null performs the authenticated RPC NULL procedure.
func (c *Client) Null(ctx context.Context) error {
	if err := c.ensureAuth(ctx); err != nil {
		return err
	}
	_, err := c.call(ctx, ProcNull, nil)
	return err
}

func (c *Client) GetUpdates(ctx context.Context, last Last) (IncrementalResult, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return IncrementalResult{}, err
	}
	reply, err := c.call(ctx, ProcGetUpdates, last.MarshalXDR())
	if err != nil {
		return IncrementalResult{}, err
	}
	return UnmarshalIncrementalResult(reply)
}

func (c *Client) FullResync(ctx context.Context) (FullResyncResult, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return FullResyncResult{}, err
	}
	reply, err := c.call(ctx, ProcFullResync, nil)
	if err != nil {
		return FullResyncResult{}, err
	}
	return UnmarshalFullResyncResult(reply)
}

func (c *Client) FullResyncExt(ctx context.Context, version uint32) (FullResyncResult, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return FullResyncResult{}, err
	}
	var w writer
	w.u32(version)
	reply, err := c.call(ctx, ProcFullResyncExt, w.bytes())
	if err != nil {
		return FullResyncResult{}, err
	}
	return UnmarshalFullResyncResult(reply)
}

func (c *Client) ensureAuth(ctx context.Context) error {
	if c == nil || c.auth == nil {
		return errors.New("iprop: unauthenticated client")
	}
	if ctx == nil {
		return errors.New("iprop: nil context")
	}
	return nil
}

type rpcAuth struct {
	ctx    *gssapi.Context
	handle []byte
	seq    uint32
}

func (c *Client) authenticate(ctx context.Context) error {
	if c == nil || c.Conn == nil || c.Credentials == nil {
		return errors.New("iprop: incomplete client")
	}
	if ctx == nil {
		return errors.New("iprop: nil context")
	}
	i, err := gssapi.NewInitiator(c.Credentials,
		gssapi.GSSMutualFlag|gssapi.GSSReplayFlag|gssapi.GSSIntegrityFlag|gssapi.GSSConfidentialityFlag)
	if err != nil {
		return err
	}
	local, lok := c.Conn.LocalAddr().(*net.TCPAddr)
	remote, rok := c.Conn.RemoteAddr().(*net.TCPAddr)
	if !lok || !rok || local.IP.To4() == nil || remote.IP.To4() == nil {
		return errors.New("iprop: RPCSEC_GSS requires TCP/IPv4 addresses")
	}
	token, err := i.InitialTokenWithChannelBindings(time.Now().UTC(), local.IP.To4(), remote.IP.To4())
	if err != nil {
		return err
	}
	proc := gssInit
	for {
		var cred writer
		cred.u32(1)
		cred.u32(proc)
		cred.u32(0)
		cred.u32(gssPrivacy)
		cred.opaque(nil)
		var arg writer
		arg.opaque(token)
		xid := atomic.AddUint32(&xidCounter, 1)
		reply, flavor, verifier, err := c.rawCall(ctx, xid, 0, authRPCSecGSS, cred.bytes(), nil, arg.bytes())
		if err != nil {
			return fmt.Errorf("iprop RPCSEC_GSS_INIT: %w", err)
		}
		r := reader{data: reply}
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
		window, err := r.u32()
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
			return fmt.Errorf("iprop GSS init failed (%d,%d)", major, minor)
		}
		if len(next) != 0 {
			if err := i.VerifyToken(next); err != nil {
				return err
			}
		}
		if major == 1 {
			token = next
			proc = gssCont
			continue
		}
		gctx, err := i.Context()
		if err != nil {
			return err
		}
		sequence, ok := i.SequenceNumber()
		if !ok {
			return errors.New("iprop: missing GSS sequence")
		}
		gctx.SetSendSequence(uint64(sequence))
		if flavor != authRPCSecGSS || len(verifier) < 16 {
			return errors.New("iprop: invalid GSS init verifier")
		}
		gctx.SetReceiveSequence(binary.BigEndian.Uint64(verifier[8:16]))
		var windowData [4]byte
		binary.BigEndian.PutUint32(windowData[:], window)
		if err := gctx.VerifyMIC(windowData[:], verifier); err != nil {
			return err
		}
		c.auth = &rpcAuth{ctx: gctx, handle: handle, seq: 1}
		return nil
	}
}

func (c *Client) call(ctx context.Context, proc uint32, body []byte) ([]byte, error) {
	seq := c.auth.seq
	plain := append(seqBytes(seq), body...)
	protected, err := c.auth.ctx.Wrap(plain, true)
	if err != nil {
		return nil, err
	}
	var cred writer
	cred.u32(1)
	cred.u32(gssData)
	cred.u32(seq)
	cred.u32(gssPrivacy)
	cred.opaque(c.auth.handle)
	xid := atomic.AddUint32(&xidCounter, 1)
	prefix := c.rpcPrefix(xid, proc, authRPCSecGSS, cred.bytes())
	verifier, err := c.auth.ctx.MIC(prefix)
	if err != nil {
		return nil, err
	}
	reply, flavor, replyVerifier, err := c.rawCall(ctx, xid, proc, authRPCSecGSS, cred.bytes(), verifier, opaqueBytes(protected))
	if err != nil {
		return nil, err
	}
	if flavor != authRPCSecGSS || len(replyVerifier) < 16 {
		return nil, errors.New("iprop: invalid GSS reply")
	}
	c.auth.ctx.SetReceiveSequence(binary.BigEndian.Uint64(replyVerifier[8:16]))
	if err := c.auth.ctx.VerifyMIC(seqBytes(seq), replyVerifier); err != nil {
		return nil, err
	}
	r := reader{data: reply}
	wrapped, err := r.opaque()
	if err != nil {
		return nil, err
	}
	if err = r.done(); err != nil {
		return nil, err
	}
	if len(wrapped) < 16 {
		return nil, errors.New("iprop: truncated protected reply")
	}
	c.auth.ctx.SetReceiveSequence(binary.BigEndian.Uint64(wrapped[8:16]))
	plainReply, err := c.auth.ctx.Unwrap(wrapped)
	if err != nil {
		return nil, err
	}
	if len(plainReply) < 4 {
		return nil, errors.New("iprop: truncated reply")
	}
	if binary.BigEndian.Uint32(plainReply[:4]) != seq {
		return nil, errors.New("iprop: unexpected reply sequence")
	}
	c.auth.seq++
	return plainReply[4:], nil
}

func opaqueBytes(data []byte) []byte { var w writer; w.opaque(data); return w.bytes() }
func seqBytes(value uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	return b[:]
}

func (c *Client) rpcPrefix(xid, proc, flavor uint32, cred []byte) []byte {
	var w writer
	w.u32(xid)
	w.u32(msgCall)
	w.u32(rpcVersion)
	w.u32(Program)
	w.u32(Version)
	w.u32(proc)
	w.auth(flavor, cred)
	return w.bytes()
}

func (c *Client) rawCall(ctx context.Context, xid, proc, flavor uint32, cred, verifier, body []byte) ([]byte, uint32, []byte, error) {
	var w writer
	w.u32(xid)
	w.u32(msgCall)
	w.u32(rpcVersion)
	w.u32(Program)
	w.u32(Version)
	w.u32(proc)
	w.auth(flavor, cred)
	if verifier == nil {
		w.auth(authNone, nil)
	} else {
		w.auth(flavor, verifier)
	}
	w.raw(body)
	if err := c.writeRecord(ctx, w.bytes()); err != nil {
		return nil, 0, nil, err
	}
	reply, err := c.readRecord(ctx)
	if err != nil {
		return nil, 0, nil, err
	}
	r := reader{data: reply}
	got, err := r.u32()
	if err != nil {
		return nil, 0, nil, err
	}
	if got != xid {
		return nil, 0, nil, errors.New("iprop: mismatched RPC XID")
	}
	kind, err := r.u32()
	if err != nil || kind != msgReply {
		return nil, 0, nil, errors.New("iprop: invalid RPC reply")
	}
	replyStat, err := r.u32()
	if err != nil || replyStat != 0 {
		return nil, 0, nil, errors.New("iprop: RPC call rejected")
	}
	flavor, verifier, err = r.auth()
	if err != nil {
		return nil, 0, nil, err
	}
	acceptStat, err := r.u32()
	if err != nil || acceptStat != 0 {
		return nil, 0, nil, errors.New("iprop: RPC call failed")
	}
	body, err = r.take(len(r.data) - r.off)
	if err != nil {
		return nil, 0, nil, err
	}
	return body, flavor, verifier, nil
}

func (c *Client) writeRecord(ctx context.Context, data []byte) error {
	if len(data) > maxRecord {
		return errors.New("iprop: RPC record too large")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.Conn.SetWriteDeadline(deadline)
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
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.Conn.SetReadDeadline(deadline)
	}
	var h [4]byte
	if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n&0x80000000 == 0 || n&0x7fffffff > maxRecord {
		return nil, errors.New("iprop: unsupported RPC fragments")
	}
	data := make([]byte, n&0x7fffffff)
	_, err := io.ReadFull(c.Conn, data)
	return data, err
}

// Server implements the MIT iprop RPC master. Full-resync replies are
// implemented, but the separate kprop dump push is intentionally not started
// by this package; callers must seed a replica before incremental polling.
type Server struct {
	Database        *kdb.Database
	Keytab          *keytab.Keytab
	AllowedReplicas map[string]bool
	Authorize       func(principal.Principal) bool
	ErrorLog        func(error)
	Now             func() time.Time
	wg              sync.WaitGroup
}

func NewServer(database *kdb.Database, serviceKeytab *keytab.Keytab) *Server {
	return &Server{Database: database, Keytab: serviceKeytab}
}

func (s *Server) Serve(listener net.Listener) error {
	if s == nil || s.Database == nil || s.Keytab == nil {
		return errors.New("iprop: incomplete server configuration")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			s.wg.Wait()
			return err
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); _ = s.serveConn(conn) }()
	}
}

type serverSession struct {
	ctx       *gssapi.Context
	client    principal.Principal
	handle    []byte
	next      uint32
	gssSeqSet bool
}
type rpcCall struct {
	xid, proc, flavor                  uint32
	credential, verifier, body, prefix []byte
}

func (s *Server) serveConn(conn net.Conn) error {
	defer conn.Close()
	var session *serverSession
	for {
		record, err := readRecord(conn)
		if err != nil {
			return err
		}
		call, err := parseCall(record)
		if err != nil {
			return err
		}
		var reply []byte
		if call.flavor == authRPCSecGSS {
			reply, session, err = s.handleGSS(call, session)
		} else {
			reply = rpcError(call.xid, 1)
		}
		if err != nil {
			return err
		}
		if err = writeRecord(conn, reply); err != nil {
			return err
		}
	}
}

func parseCall(record []byte) (rpcCall, error) {
	r := reader{data: record}
	xid, err := r.u32()
	if err != nil {
		return rpcCall{}, err
	}
	if v, _ := r.u32(); v != msgCall {
		return rpcCall{}, errors.New("iprop: invalid RPC call")
	}
	if v, _ := r.u32(); v != rpcVersion {
		return rpcCall{}, errors.New("iprop: invalid RPC version")
	}
	if v, _ := r.u32(); v != Program {
		return rpcCall{}, errors.New("iprop: unexpected RPC program")
	}
	if v, _ := r.u32(); v != Version {
		return rpcCall{}, errors.New("iprop: unexpected RPC version")
	}
	proc, err := r.u32()
	if err != nil {
		return rpcCall{}, err
	}
	flavor, cred, err := r.auth()
	if err != nil {
		return rpcCall{}, err
	}
	prefixEnd := r.off
	_, verifier, err := r.auth()
	if err != nil {
		return rpcCall{}, err
	}
	return rpcCall{xid: xid, proc: proc, flavor: flavor, credential: cred, verifier: verifier, body: record[r.off:], prefix: record[:prefixEnd]}, nil
}

func (s *Server) handleGSS(call rpcCall, session *serverSession) ([]byte, *serverSession, error) {
	r := reader{data: call.credential}
	version, err := r.u32()
	if err != nil || version != 1 {
		return rpcError(call.xid, 1), session, nil
	}
	proc, err := r.u32()
	if err != nil {
		return rpcError(call.xid, 1), session, nil
	}
	seq, err := r.u32()
	if err != nil {
		return rpcError(call.xid, 1), session, nil
	}
	service, err := r.u32()
	if err != nil || service != gssPrivacy && service != gssData {
		return rpcError(call.xid, 1), session, nil
	}
	handle, err := r.opaque()
	if err != nil || r.done() != nil {
		return rpcError(call.xid, 1), session, nil
	}
	bodyReader := reader{data: call.body}
	protected, err := bodyReader.opaque()
	if err != nil || bodyReader.done() != nil {
		return rpcError(call.xid, 1), session, nil
	}
	if proc == gssInit || proc == gssCont {
		if session != nil && (!bytesEqual(handle, session.handle) || proc != gssCont) {
			return rpcError(call.xid, 1), session, nil
		}
		if session == nil && (proc != gssInit || len(handle) != 0) {
			return rpcError(call.xid, 1), session, nil
		}
		acceptor := gssapi.NewAcceptor(s.Keytab)
		ctx, clientName, response, err := acceptor.AcceptWithPrincipal(protected, now(s.Now))
		if err != nil {
			return rpcError(call.xid, 1), nil, nil
		}
		if session == nil {
			handle = make([]byte, 16)
			if _, err := rand.Read(handle); err != nil {
				return nil, nil, err
			}
			session = &serverSession{handle: handle, next: 1, client: clientName}
		}
		session.ctx = ctx
		window := uint32(0x7fffffff)
		verifier, err := session.ctx.MIC(seqBytes(window))
		if err != nil {
			return nil, nil, err
		}
		var b writer
		b.opaque(session.handle)
		b.u32(0)
		b.u32(0)
		b.u32(window)
		b.opaque(response)
		return rpcReply(call.xid, authRPCSecGSS, verifier, b.bytes()), session, nil
	}
	if session == nil || !bytesEqual(handle, session.handle) || proc != gssData || seq != session.next {
		return rpcError(call.xid, 1), session, nil
	}
	if len(protected) < 16 || len(call.verifier) < 16 {
		return rpcError(call.xid, 1), session, nil
	}
	protectedSeq := binary.BigEndian.Uint64(protected[8:16])
	verifierSeq := binary.BigEndian.Uint64(call.verifier[8:16])
	if !session.gssSeqSet {
		if protectedSeq+1 == verifierSeq {
			session.ctx.SetReceiveSequence(protectedSeq)
		} else if verifierSeq+1 == protectedSeq {
			session.ctx.SetReceiveSequence(verifierSeq)
		} else {
			return rpcError(call.xid, 1), session, nil
		}
		session.gssSeqSet = true
	}
	var plain []byte
	if protectedSeq+1 == verifierSeq {
		plain, err = session.ctx.Unwrap(protected)
		if err == nil && len(plain) >= 4 && binary.BigEndian.Uint32(plain[:4]) == seq {
			err = session.ctx.VerifyMIC(call.prefix, call.verifier)
		}
	} else if verifierSeq+1 == protectedSeq {
		err = session.ctx.VerifyMIC(call.prefix, call.verifier)
		if err == nil {
			plain, err = session.ctx.Unwrap(protected)
			if err == nil && len(plain) >= 4 && binary.BigEndian.Uint32(plain[:4]) != seq {
				err = errors.New("iprop: bad sequence")
			}
		}
	} else {
		err = errors.New("iprop: bad GSS sequence")
	}
	if err != nil {
		return rpcError(call.xid, 1), session, nil
	}
	session.next++
	result := s.dispatch(session.client, call.proc, plain[4:])
	replyPlain := append(seqBytes(seq), result...)
	wrapped, err := session.ctx.Wrap(replyPlain, true)
	if err != nil {
		return nil, session, err
	}
	replyVerifier, err := session.ctx.MIC(seqBytes(seq))
	if err != nil {
		return nil, session, err
	}
	var b writer
	b.opaque(wrapped)
	return rpcReply(call.xid, authRPCSecGSS, replyVerifier, b.bytes()), session, nil
}

func (s *Server) dispatch(clientName principal.Principal, proc uint32, body []byte) []byte {
	var last Last
	var err error
	switch proc {
	case ProcGetUpdates:
		last, err = UnmarshalLast(body)
		if err != nil {
			return IncrementalResult{Ret: UpdateError}.MarshalXDR()
		}
	case ProcFullResync, ProcFullResyncExt:
		if proc == ProcFullResyncExt {
			r := reader{data: body}
			_, err = r.u32()
			if err == nil {
				err = r.done()
			}
			if err != nil {
				return FullResyncResult{Ret: UpdateError}.MarshalXDR()
			}
		}
	case ProcNull:
		if len(body) != 0 {
			return nil
		}
		return nil
	default:
		return nil
	}
	if !s.authorized(clientName) {
		if proc == ProcGetUpdates {
			return IncrementalResult{Ret: UpdatePermDenied}.MarshalXDR()
		}
		return FullResyncResult{Ret: UpdatePermDenied}.MarshalXDR()
	}
	sno, stamp := s.Database.UpdateLog.Last()
	current := Last{LastSno: sno, LastTime: timeValue(stamp)}
	if proc != ProcGetUpdates {
		return FullResyncResult{LastEntry: current, Ret: UpdateOK}.MarshalXDR()
	}
	status, entries := s.Database.UpdateLog.Entries(last.LastSno, last.LastTime.Time())
	result := IncrementalResult{LastEntry: current, Ret: UpdateStatus(status)}
	for _, entry := range entries {
		result.Updates = append(result.Updates, Update{PrincipalName: entry.Name.String(), EntrySno: entry.Serial, Time: timeValue(entry.Time), Entry: EntryFromRecord(entry.Record), Deleted: entry.Deleted, Commit: entry.Commit})
	}
	return result.MarshalXDR()
}

func (s *Server) authorized(clientName principal.Principal) bool {
	if s.Authorize != nil {
		return s.Authorize(clientName)
	}
	return s.AllowedReplicas[clientName.String()]
}

func now(fn func() time.Time) time.Time {
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func rpcReply(xid, flavor uint32, verifier, body []byte) []byte {
	var w writer
	w.u32(xid)
	w.u32(msgReply)
	w.u32(0)
	w.auth(flavor, verifier)
	w.raw(body)
	return w.bytes()
}
func rpcError(xid, status uint32) []byte {
	var w writer
	w.u32(xid)
	w.u32(msgReply)
	w.u32(0)
	w.auth(authNone, nil)
	w.u32(status)
	return w.bytes()
}
func readRecord(conn net.Conn) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n&0x80000000 == 0 || n&0x7fffffff > maxRecord {
		return nil, errors.New("iprop: unsupported RPC fragment")
	}
	data := make([]byte, n&0x7fffffff)
	_, err := io.ReadFull(conn, data)
	return data, err
}
func writeRecord(conn net.Conn, data []byte) error {
	if len(data) > maxRecord {
		return errors.New("iprop: RPC record too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(data))|0x80000000)
	if _, err := conn.Write(h[:]); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// Replica applies incremental updates to a local Database and persists its
// cursor in memory. Seed the database and cursor from a dump before polling.
type Replica struct {
	Client   *Client
	Database *kdb.Database
	Cursor   Last
}

func (r *Replica) Poll(ctx context.Context) (UpdateStatus, error) {
	if r == nil || r.Client == nil || r.Database == nil {
		return UpdateError, errors.New("iprop: incomplete replica")
	}
	result, err := r.Client.GetUpdates(ctx, r.Cursor)
	if err != nil {
		return UpdateError, err
	}
	if result.Ret != UpdateOK {
		return result.Ret, nil
	}
	if err := r.apply(result.Updates); err != nil {
		return UpdateError, err
	}
	r.Cursor = result.LastEntry
	return result.Ret, nil
}

func (r *Replica) apply(updates []Update) error {
	for _, update := range updates {
		if !update.Commit {
			continue
		}
		name, err := principal.Parse(update.PrincipalName)
		if err != nil {
			return err
		}
		if update.Deleted {
			if err := r.Database.ApplyPrincipal(kdb.PrincipalRecord{Name: *name}, true); err != nil {
				return err
			}
			continue
		}
		record, err := RecordFromEntry(*name, update.Entry)
		if err != nil {
			return err
		}
		if err := r.Database.ApplyPrincipal(record, false); err != nil {
			return err
		}
	}
	return nil
}

// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"context"
	stdcrypto "crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/internal/random"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/klog"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
	"github.com/Exonical/go-kerberos/krb5/trace"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	maxReplayEntries       = 10000
	defaultMaxDatagramSize = 65536
	defaultTCPIdleTimeout  = time.Minute
	defaultTCPConnections  = 45
	defaultUDPWorkers      = 1024
	spakeCookieLifetime    = 10 * time.Minute
	paTGSReq               = 1
	paEncTimestamp         = 2
	paEncryptedChallenge   = protocol.PADataEncryptedChallenge
	paFXCookie             = 133
	paSPAKE                = 151
	kdcErrCPrincipal       = 6
	kdcErrSPrincipal       = 7
	kdcErrNameExpired      = 1
	kdcErrServiceExpired   = 2
	kdcErrPreauthFailed    = 24
	kdcErrPreauthRequired  = 25
	kdcErrDHKeyParameters  = 65
	kdcErrMorePreauth      = 91
	kdcErrGeneric          = 60
	kdcErrServiceUnknown   = 7
	kdcErrBadOption        = 13
	kdcErrPolicy           = 12
	kdcErrServerNoMatch    = 26
	kdcErrCannotPostdate   = 10
	kdcErrClientRevoked    = 18
	kdcErrKeyExpired       = 23
	kdcErrMustUseUser2User = 27
	kdcErrClientNotTrusted = 62
	kdcErrPreauthExpired   = 90
	krbAPErrBadIntegrity   = 31
	krbAPErrTktExpired     = 32
	krbAPErrTktNYV         = 33
	krbAPErrRepeat         = 34
	krbAPErrSkew           = 37
	krbAPErrInKeyUsage     = 44
	keyUsagePAPKINITKX     = 44
)

// OTPVerifier validates raw RFC 6560 OTP values and returns ticket
// authentication indicators.
type OTPVerifier interface {
	VerifyOTP(client principal.Principal, otpValue []byte) ([]string, error)
}

// Server is a Kerberos KDC backed by a pluggable principal store.
type Server struct {
	Realm string
	DB    kdb.Store
	// Trace is invoked synchronously from concurrent request goroutines;
	// callbacks must be safe for concurrent use.
	Trace         trace.Callback
	Logger        *klog.Logger
	Now           func() time.Time
	ClockSkew     time.Duration
	MaxTicketLife time.Duration
	// DefaultTicketLife applies when a request omits its maximum till time.
	DefaultTicketLife time.Duration
	MaxRenewableLife  time.Duration
	// UDPPorts and TCPPorts retain kdc.conf listener settings for callers
	// constructing listeners. ListenAndServe does not create listeners itself.
	UDPPorts []int
	TCPPorts []int
	// DefaultRenewableLife applies when RENEWABLE omits its rtime.
	DefaultRenewableLife time.Duration
	// DisablePreauth disables the server-wide preauthentication requirement.
	// MIT normally configures this per principal with requires_preauth.
	DisablePreauth bool
	// Policy optionally restricts forwardable, renewable, and proxiable flags.
	Policy *Policy
	// Capaths optionally configures permitted server-side transited paths.
	Capaths map[string]map[string][]string
	// CheckAllowedToDelegate mirrors MIT's KDB check_allowed_to_delegate
	// method. impersonated is nil for the S4U2Self ok-to-auth-as-delegate
	// query, and target is nil for that query too. A nil hook permits
	// non-forwardable S4U2Self but denies S4U2Proxy.
	CheckAllowedToDelegate func(impersonated *principal.Principal, service principal.Principal, target *principal.Principal) error
	// PKINITCertificate and PKINITSigner identify the KDC for PKINIT replies.
	PKINITCertificate *x509.Certificate
	PKINITSigner      stdcrypto.Signer
	// PKINITDHMinBits applies MIT's pkinit_dh_min_bits group policy.
	PKINITDHMinBits string
	// PKINITClientCAs trusts client certificates for PKINIT authentication.
	PKINITClientCAs *x509.CertPool
	// CertAuthModules are additional PKINIT certificate authorization modules.
	// Built-in modules always run before these modules.
	CertAuthModules []CertAuthModule
	// PreauthModules contains compile-time registered KDC preauthentication
	// modules. Built-in mechanisms retain precedence for their PA types.
	PreauthModules []KDCPreauthModule
	// AuthDataModules add MIT-shaped KDC authorization data to issued tickets.
	// A nil list leaves authorization-data module handling disabled.
	AuthDataModules []AuthDataModule
	// DisablePAC suppresses PAC issuance while retaining authentication
	// indicators and other authorization data.
	DisablePAC bool
	// RejectBadTransit controls whether a failed transited-policy check
	// rejects the TGS request. MIT defaults this to true.
	RejectBadTransit    bool
	RejectBadTransitSet bool
	// RestrictAnonymousToTGT permits anonymous tickets only for local TGTs.
	RestrictAnonymousToTGT bool
	// HostBasedServices controls referral eligibility for NT-UNKNOWN services.
	HostBasedServices []string
	// NoHostReferral suppresses referrals for listed service types.
	NoHostReferral []string
	// PKINITRequireFreshness requires RFC 8070 freshness tokens on signed
	// PKINIT requests. Clients which advertise freshness receive an opaque
	// token in PREAUTH_REQUIRED and must echo it in PKAuthenticator.
	PKINITRequireFreshness bool
	// Authorize optionally mirrors MIT's kdcpolicy plugin hook for authenticated
	// AS exchanges and validated TGS requests. A nil hook permits all requests.
	// Hook KRBError codes in the protocol range are returned unchanged; other
	// errors default to KDC_ERR_POLICY or KRB_ERR_GENERIC as appropriate.
	Authorize func(client, service principal.Principal, asExchange bool) error
	// KDCPolicyModules apply ordered MIT-style AS and TGS issuance policy.
	KDCPolicyModules []KDCPolicyModule
	// OTPValidator enables RFC 6560 preauthentication for the named
	// principals. OTP is accepted only inside FAST.
	OTPValidator func(principal.Principal, string) error
	// OTPVerifier validates raw RFC 6560 OTP values, typically through an
	// external backend. It takes precedence over OTPValidator when set.
	OTPVerifier OTPVerifier
	// OTPTokenInfo supplies the token metadata advertised in the challenge.
	// A nil hook uses an unspecified token format.
	OTPTokenInfo func(principal.Principal) []otp.TokenInfo
	// EnablePAC enables opt-in MS-PAC issuance and TGS re-signing.
	EnablePAC bool
	// GeneratePAC supplies opaque logon-info bytes for newly issued PACs.
	// The package deliberately does not interpret the Microsoft NDR payload.
	GeneratePAC func(client, service principal.Principal) ([]byte, error)
	// GeneratePACIdentity supplies structured MS-PAC identity data.
	GeneratePACIdentity func(client, service principal.Principal) (*PACIdentity, error)
	// GeneratePACCredentials supplies opaque PAC_CREDENTIAL_DATA plaintext for
	// an AS reply whose reply key was replaced by preauthentication. The
	// returned enctype must match replacedReplyKey.Enctype; the KDC encrypts
	// the data with that key using the MS-PAC usage 16.
	GeneratePACCredentials func(client, service principal.Principal,
		replacedReplyKey kdb.Key) ([]byte, int32, error)
	// EncryptedChallengeIndicator is asserted after successful
	// PA-ENCRYPTED-CHALLENGE preauthentication.
	EncryptedChallengeIndicator string
	// SPAKEPreauthIndicators are asserted after successful PA-SPAKE
	// preauthentication.
	SPAKEPreauthIndicators []string
	// PKINITIndicators are asserted after successful signed, non-anonymous
	// PKINIT preauthentication.
	PKINITIndicators []string
	// OTPIndicators are asserted after successful PA-OTP preauthentication.
	OTPIndicators []string
	// AuditModules receive KDC lifecycle and AS/TGS events in order.
	AuditModules []AuditModule
	// AuditErrorLog receives audit sink failures; sink failures never alter
	// protocol replies.
	AuditErrorLog func(error)

	// MaxDatagramReplySize limits UDP replies. Zero uses MIT's default
	// MAX_DGRAM_SIZE value of 65536 bytes.
	MaxDatagramReplySize int
	// TCPIdleTimeout bounds each TCP read and write operation. Zero uses the
	// approved one-minute KDC TCP idle timeout.
	TCPIdleTimeout time.Duration
	// MaxTCPConnections bounds concurrent TCP connections. Zero uses MIT's
	// default max_stream_data_connections value of 45.
	MaxTCPConnections int
	// MaxUDPWorkers bounds concurrent UDP request handlers. Zero uses a
	// Go-side default of 1024; MIT processes datagrams serially.
	MaxUDPWorkers int
	// EnableSPAKE advertises PA-SPAKE in the initial PREAUTH_REQUIRED
	// method data. MIT sends an empty PA-SPAKE hint unless an optimistic
	// challenge is configured; the default is disabled.
	EnableSPAKE bool
	// SPAKEGroups lists the groups permitted for PA-SPAKE. An empty list
	// preserves MIT's default KDC configuration: SPAKE is disabled until
	// explicitly enabled, and when enabled only edwards25519 is permitted.
	SPAKEGroups []int32

	replayMu       sync.Mutex
	replays        map[string]time.Time
	lookasideMu    sync.Mutex
	lookaside      *lookasideCache
	tcpMu          sync.Mutex
	tcpConns       map[*tcpConnection]struct{}
	tcpOrder       uint64
	spakeCookieKey []byte
	spakeCookieMu  sync.Mutex
}

// PACIdentity describes structured PAC logon and UPN/DNS identity fields.
type PACIdentity struct {
	LogonInfo     *pac.LogonInfo
	UPN           string
	DNSDomainName string
	SAMName       string
	SID           pac.SID
	Flags         uint32
}

type tcpConnection struct {
	conn    net.Conn
	started time.Time
	order   uint64
}

// HandleMessage handles one DER-encoded AS-REQ or TGS-REQ.
func (s *Server) HandleMessage(data []byte) []byte {
	return s.handleMessage(data, "")
}

func (s *Server) handleMessage(data []byte, remoteAddr string) []byte {
	if s == nil || s.DB == nil || s.Realm == "" {
		return s.errorResponse(kdcErrGeneric, nil)
	}
	if len(data) == 0 {
		return s.errorResponse(kdcErrGeneric, nil)
	}
	switch data[0] {
	case 0x6a:
		var request protocol.ASReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			s.tracef("AS-REQ: malformed request")
			return s.errorResponse(kdcErrGeneric, nil)
		}
		client, service := traceRequestPrincipals(request.ReqBody.CName,
			request.ReqBody.SName, request.ReqBody.Realm)
		s.tracef("AS-REQ: client %s for %s", client, service)
		if len(request.PAData) > 0 {
			s.tracef("AS-REQ: received preauthentication data")
		}
		response := s.handleASReq(request, data, remoteAddr)
		if isKRBErrorResponse(response) {
			s.tracef("AS-REQ: error response")
		} else {
			s.tracef("AS-REQ: issuing ticket for %s", client)
		}
		return response
	case 0x6c:
		var request protocol.TGSReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			s.tracef("TGS-REQ: malformed request")
			return s.errorResponse(kdcErrGeneric, nil)
		}
		_, service := traceRequestPrincipals(nil, request.ReqBody.SName, request.ReqBody.Realm)
		s.tracef("TGS-REQ: service %s", service)
		if len(request.PAData) > 0 {
			s.tracef("TGS-REQ: received preauthentication data")
		}
		response := s.handleTGSReq(request, data, remoteAddr)
		if isKRBErrorResponse(response) {
			s.tracef("TGS-REQ: error response")
		} else {
			s.tracef("TGS-REQ: issuing ticket for %s", service)
		}
		return response
	default:
		s.tracef("KDC: unsupported message type")
		return s.errorResponse(kdcErrGeneric, nil)
	}
}

func (s *Server) tracef(format string, args ...any) {
	if s != nil && s.Trace != nil {
		s.Trace(fmt.Sprintf(format, args...))
	}
}

func traceRequestPrincipals(clientName, serviceName *protocol.PrincipalName,
	realm string) (string, string) {
	client := "(unknown)"
	if clientName != nil {
		client = trace.Principal(principalFromProtocol(*clientName, realm))
	}
	service := "(unknown)"
	if serviceName != nil {
		service = trace.Principal(principalFromProtocol(*serviceName, realm))
	}
	return client, service
}

// ListenAndServe serves Kerberos requests on the supplied UDP and TCP
// endpoints until ctx is canceled or either listener fails.
func (s *Server) ListenAndServe(ctx context.Context, udpConn net.PacketConn, tcpListener net.Listener) error {
	if s == nil {
		return fmt.Errorf("KDC listen: nil server")
	}
	if ctx == nil {
		return fmt.Errorf("KDC listen: nil context")
	}
	if udpConn == nil || tcpListener == nil {
		return fmt.Errorf("KDC listen: nil listener")
	}
	if udpConn.LocalAddr() == nil || tcpListener.Addr() == nil {
		return fmt.Errorf("KDC listen: invalid listener")
	}
	s.AuditKDCStart(true)
	serveSuccess := false
	defer func() { s.AuditKDCStop(serveSuccess) }()
	errs := make(chan error, 2)
	go func() { errs <- s.serveUDP(udpConn) }()
	go func() { errs <- s.serveTCP(tcpListener) }()
	select {
	case <-ctx.Done():
		_ = udpConn.Close()
		_ = tcpListener.Close()
		serveSuccess = true
		return nil
	case err := <-errs:
		_ = udpConn.Close()
		_ = tcpListener.Close()
		return err
	}
}

func (s *Server) serveUDP(conn net.PacketConn) error {
	buffer := make([]byte, transport.DefaultMaxFrameSize)
	limit := s.MaxUDPWorkers
	if limit <= 0 {
		limit = defaultUDPWorkers
	}
	workers := make(chan struct{}, limit)
	for {
		n, address, err := conn.ReadFrom(buffer)
		if err != nil {
			if isClosedNetworkError(err) {
				return nil
			}
			if s.Logger != nil {
				s.Logger.Error("KDC UDP read: %v", err)
			}
			return fmt.Errorf("KDC UDP read: %w", err)
		}
		request := append([]byte(nil), buffer[:n]...)
		workers <- struct{}{}
		go func() {
			defer func() { <-workers }()
			s.handleUDP(conn, address, request)
		}()
	}
}

func (s *Server) handleUDP(conn net.PacketConn, address net.Addr, request []byte) {
	response := s.dispatchWithRemote(request, false, address.String())
	if len(response) == 0 {
		return
	}
	_, _ = conn.WriteTo(response, address)
}

func (s *Server) serveTCP(listener net.Listener) error {
	limit := s.MaxTCPConnections
	if limit <= 0 {
		limit = defaultTCPConnections
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedNetworkError(err) {
				return nil
			}
			if s.Logger != nil {
				s.Logger.Error("KDC TCP accept: %v", err)
			}
			return fmt.Errorf("KDC TCP accept: %w", err)
		}
		tracked, evicted := s.trackTCPConnection(conn)
		if evicted != nil {
			_ = evicted.conn.Close()
		}
		go func() {
			defer s.untrackTCPConnection(tracked)
			s.handleTCPConn(tracked.conn)
		}()
	}
}

func (s *Server) trackTCPConnection(conn net.Conn) (*tcpConnection, *tcpConnection) {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	if s.tcpConns == nil {
		s.tcpConns = make(map[*tcpConnection]struct{})
	}
	s.tcpOrder++
	tracked := &tcpConnection{conn: conn, started: time.Now(), order: s.tcpOrder}
	s.tcpConns[tracked] = struct{}{}
	if len(s.tcpConns) <= s.maxTCPConnections() {
		return tracked, nil
	}
	var oldest *tcpConnection
	for candidate := range s.tcpConns {
		if candidate == tracked ||
			(oldest != nil && (candidate.started.After(oldest.started) ||
				(candidate.started.Equal(oldest.started) && candidate.order > oldest.order))) {
			continue
		}
		oldest = candidate
	}
	if oldest != nil {
		delete(s.tcpConns, oldest)
	}
	return tracked, oldest
}

func (s *Server) untrackTCPConnection(conn *tcpConnection) {
	s.tcpMu.Lock()
	delete(s.tcpConns, conn)
	s.tcpMu.Unlock()
}

func (s *Server) maxTCPConnections() int {
	if s.MaxTCPConnections > 0 {
		return s.MaxTCPConnections
	}
	return defaultTCPConnections
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	timeout := s.TCPIdleTimeout
	if timeout <= 0 {
		timeout = defaultTCPIdleTimeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	request, err := transport.ReadTCPFrame(conn, transport.DefaultMaxFrameSize)
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}
	response := s.dispatchWithRemote(request, true, remoteAddr)
	if len(response) == 0 {
		return
	}
	_ = transport.WriteTCPFrame(conn, response)
}

func (s *Server) dispatch(request []byte, isTCP bool) []byte {
	return s.dispatchWithRemote(request, isTCP, "")
}

func (s *Server) dispatchWithRemote(request []byte, isTCP bool, remoteAddr string) []byte {
	cache := s.getLookaside()
	if cached, hit := cache.begin(request, s.now()); hit {
		if len(cached) == 0 {
			return nil
		}
		return s.limitDatagramReply(cached, isTCP)
	}
	response := s.handleMessage(request, remoteAddr)
	cache.complete(request, response, s.now())
	return s.limitDatagramReply(response, isTCP)
}

func (s *Server) getLookaside() *lookasideCache {
	s.lookasideMu.Lock()
	defer s.lookasideMu.Unlock()
	if s.lookaside == nil {
		s.lookaside = newLookasideCache()
	}
	return s.lookaside
}

func (s *Server) limitDatagramReply(response []byte, isTCP bool) []byte {
	if isTCP || len(response) <= s.maxDatagramReplySize() {
		return response
	}
	return s.errorResponse(transport.ResponseTooBigCode, nil)
}

func (s *Server) maxDatagramReplySize() int {
	if s.MaxDatagramReplySize > 0 {
		return s.MaxDatagramReplySize
	}
	return defaultMaxDatagramSize
}

type fastContext struct {
	etype  crypto.EType
	key    []byte
	nonce  uint32
	cookie *protocol.PAData
}

// Policy controls optional ticket-flag issuance. A nil policy preserves the
// permissive defaults; disallowed flags are cleared, matching MIT's KDC
// behavior for per-principal flag restrictions.
type Policy struct {
	AllowForwardable bool
	AllowRenewable   bool
	AllowProxiable   bool
}

func (s *Server) errorResponse(code int32, service *protocol.PrincipalName) []byte {
	return s.errorResponseWithText(code, service, "")
}

func (s *Server) errorResponseWithData(code int32, service *protocol.PrincipalName, data []byte) []byte {
	return s.errorResponseWithTextAndData(code, service, data, "")
}

func (s *Server) errorResponseWithText(code int32, service *protocol.PrincipalName, text string) []byte {
	return s.errorResponseWithTextAndData(code, service, nil, text)
}

func (s *Server) errorResponseWithTextAndData(code int32, service *protocol.PrincipalName, data []byte, text string) []byte {
	now := s.now().UTC()
	if service == nil {
		service = &protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", s.Realm}}
	}
	reply := protocol.KRBError{
		PVNO: 5, MsgType: 30,
		STime: types.KerberosTime{Time: now, Present: true}, Susec: int32(now.Nanosecond() / 1000),
		ErrorCode: code, Realm: s.Realm, SName: *service, EData: append([]byte(nil), data...),
	}
	if text != "" {
		reply.EText = &text
	}
	return marshalDER(reply)
}

func (s *Server) authorizationError(client, service principal.Principal, asExchange bool, armor *fastContext) []byte {
	if s.Authorize == nil {
		return nil
	}
	if err := s.Authorize(client, service, asExchange); err != nil {
		serviceName := protocolPrincipal(service)
		code := int32(kdcErrPolicy)
		var kerberosError *krberr.KRBError
		if stderrors.As(err, &kerberosError) {
			code = int32(kerberosError.Code)
			if code < 0 || code > 128 {
				code = kdcErrGeneric
			}
		}
		if armor != nil {
			return s.fastErrorResponseWithText(code, serviceName, nil, armor.nonce, armor, err.Error())
		}
		return s.errorResponseWithText(code, serviceName, err.Error())
	}
	return nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) skew() time.Duration {
	skew := s.ClockSkew
	if skew < 0 {
		skew = -skew
	}
	if skew == 0 {
		skew = 5 * time.Minute
	}
	return skew
}

func (s *Server) withinSkew(value time.Time) bool {
	skew := s.skew()
	difference := value.Sub(s.now())
	if difference < 0 {
		difference = -difference
	}
	return difference <= skew
}

func (s *Server) replayed(realm string, name protocol.PrincipalName, authenticator protocol.Authenticator) bool {
	now := s.now()
	key := strings.Join(append([]string{realm, fmt.Sprint(name.NameType), fmt.Sprint(authenticator.Cusec), authenticator.Ctime.Time.UTC().Format(time.RFC3339Nano), hex.EncodeToString(authenticator.Checksum.Checksum)}, name.NameString...), "\x00")
	expires := now.Add(s.skew())
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if s.replays == nil {
		s.replays = make(map[string]time.Time)
	}
	for replayKey, expiry := range s.replays {
		if !expiry.After(now) {
			delete(s.replays, replayKey)
		}
	}
	if expiry, ok := s.replays[key]; ok && expiry.After(now) {
		return true
	}
	if len(s.replays) >= maxReplayEntries {
		var oldestKey string
		var oldest time.Time
		for replayKey, expiry := range s.replays {
			if oldestKey == "" || expiry.Before(oldest) {
				oldestKey, oldest = replayKey, expiry
			}
		}
		if oldestKey != "" {
			delete(s.replays, oldestKey)
		}
	}
	s.replays[key] = expires
	return false
}

func findPA(data protocol.MethodData, kind int32) *protocol.PAData {
	for index := range data {
		if data[index].PADataType == kind {
			return &data[index]
		}
	}
	return nil
}

func isSPAKESupport(pa *protocol.PAData) bool {
	if pa == nil || pa.PADataType != paSPAKE {
		return false
	}
	var msg protocol.PASPAKE
	return asn1.Unmarshal(pa.PADataValue, &msg) == nil && msg.Support != nil
}

func supportsSPAKEGroup(pa *protocol.PAData, group int32) bool {
	if !isSPAKESupport(pa) {
		return false
	}
	var msg protocol.PASPAKE
	if err := asn1.Unmarshal(pa.PADataValue, &msg); err != nil || msg.Support == nil {
		return false
	}
	for _, offered := range msg.Support.Groups {
		if offered == group {
			return true
		}
	}
	return false
}

func (s *Server) spakeGroups() []int32 {
	if len(s.SPAKEGroups) == 0 {
		return []int32{spake.GroupEdwards25519}
	}
	return append([]int32(nil), s.SPAKEGroups...)
}

func (s *Server) permitsSPAKEGroup(group int32) bool {
	for _, permitted := range s.spakeGroups() {
		if permitted == group {
			return true
		}
	}
	return false
}

func (s *Server) selectSPAKEGroup(pa *protocol.PAData) int32 {
	if !s.EnableSPAKE || !isSPAKESupport(pa) {
		return 0
	}
	var msg protocol.PASPAKE
	if err := asn1.Unmarshal(pa.PADataValue, &msg); err != nil || msg.Support == nil {
		return 0
	}
	for _, offered := range msg.Support.Groups {
		if s.permitsSPAKEGroup(offered) {
			if _, _, _, _, err := spake.GroupInfo(offered); err == nil {
				return offered
			}
		}
	}
	return 0
}

func (s *Server) spakeKey() ([]byte, error) {
	s.spakeCookieMu.Lock()
	defer s.spakeCookieMu.Unlock()
	if len(s.spakeCookieKey) == 0 {
		s.spakeCookieKey = make([]byte, 32)
		if _, err := io.ReadFull(random.Reader(), s.spakeCookieKey); err != nil {
			s.spakeCookieKey = nil
			return nil, err
		}
	}
	return append([]byte(nil), s.spakeCookieKey...), nil
}

func (s *Server) makeSPAKECookie(group int32, private, transcript []byte) ([]byte, error) {
	_, privateLen, _, _, err := spake.GroupInfo(group)
	if err != nil || len(private) != privateLen || len(transcript) == 0 {
		return nil, fmt.Errorf("invalid SPAKE cookie state")
	}
	data := make([]byte, 0, 2+2+8+4+4+privateLen+4+len(transcript))
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], 1)
	data = append(data, b2[:]...)
	binary.BigEndian.PutUint16(b2[:], 0)
	data = append(data, b2[:]...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(s.now().Unix()))
	data = append(data, b8[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(group))
	data = append(data, b4[:]...)
	binary.BigEndian.PutUint32(b4[:], uint32(len(private)))
	data = append(data, b4[:]...)
	data = append(data, private...)
	binary.BigEndian.PutUint32(b4[:], uint32(len(transcript)))
	data = append(data, b4[:]...)
	data = append(data, transcript...)
	key, err := s.spakeKey()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return append(data, mac.Sum(nil)...), nil
}

func (s *Server) parseSPAKECookie(pa *protocol.PAData) (int32, []byte, []byte, bool) {
	if pa == nil || len(pa.PADataValue) < 2+2+8+4+4+4+sha256.Size {
		return 0, nil, nil, false
	}
	data := pa.PADataValue
	macStart := len(data) - sha256.Size
	key, err := s.spakeKey()
	if err != nil {
		return 0, nil, nil, false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data[:macStart])
	if !hmac.Equal(mac.Sum(nil), data[macStart:]) {
		return 0, nil, nil, false
	}
	pos := 0
	version := binary.BigEndian.Uint16(data[pos:])
	pos += 2
	stage := binary.BigEndian.Uint16(data[pos:])
	pos += 2
	if version != 1 || stage != 0 || pos+8 > macStart {
		return 0, nil, nil, false
	}
	issuedAt := int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8
	if s.now().Unix() > issuedAt+int64(spakeCookieLifetime/time.Second) {
		return 0, nil, nil, false
	}
	group := int32(binary.BigEndian.Uint32(data[pos:]))
	pos += 4
	_, expectedPrivateLen, _, _, err := spake.GroupInfo(group)
	if err != nil || pos+4 > macStart {
		return 0, nil, nil, false
	}
	privateLen := int(binary.BigEndian.Uint32(data[pos:]))
	pos += 4
	if privateLen != expectedPrivateLen || pos+privateLen+4 > macStart {
		return 0, nil, nil, false
	}
	private := append([]byte(nil), data[pos:pos+privateLen]...)
	pos += privateLen
	transcriptLen := int(binary.BigEndian.Uint32(data[pos:]))
	pos += 4
	if transcriptLen == 0 || pos+transcriptLen != macStart {
		return 0, nil, nil, false
	}
	return group, private, append([]byte(nil), data[pos:pos+transcriptLen]...), true
}

func principalFromProtocol(value protocol.PrincipalName, realm string) principal.Principal {
	return principal.Principal{Realm: realm, NameType: principal.NameType(value.NameType), Components: append([]string(nil), value.NameString...)}
}

func anonymousPrincipal() principal.Principal {
	return principal.Principal{
		Realm: "WELLKNOWN:ANONYMOUS", NameType: principal.NTWellKnown,
		Components: []string{"WELLKNOWN", "ANONYMOUS"},
	}
}

func isAnonymousPrincipal(p principal.Principal) bool {
	a := anonymousPrincipal()
	if p.NameType != a.NameType || len(p.Components) != len(a.Components) {
		return false
	}
	for i := range a.Components {
		if p.Components[i] != a.Components[i] {
			return false
		}
	}
	return true
}

func (s *Server) rejectBadTransit() bool {
	if s == nil || !s.RejectBadTransitSet {
		return true
	}
	return s.RejectBadTransit
}

func (s *Server) restrictAnonymous(client, service principal.Principal) bool {
	if s == nil || !s.RestrictAnonymousToTGT || !isAnonymousPrincipal(client) {
		return false
	}
	return service.Realm != s.Realm ||
		service.NameType != principal.NTSrvInstance ||
		len(service.Components) != 2 ||
		service.Components[0] != "krbtgt" ||
		service.Components[1] != s.Realm
}

func (s *Server) referralAllowed(service principal.Principal, canonicalize bool,
	encTktInSKey bool) bool {
	if !canonicalize || encTktInSKey || len(service.Components) != 2 {
		return false
	}
	first := service.Components[0]
	if service.NameType == principal.NTUnknown && !listContains(s.HostBasedServices, first) &&
		!listContains(s.HostBasedServices, "*") {
		return false
	}
	if (service.NameType == principal.NTUnknown ||
		service.NameType == principal.NTSrvHst ||
		service.NameType == principal.NTSrvInstance) &&
		(listContains(s.NoHostReferral, first) || listContains(s.NoHostReferral, "*")) {
		return false
	}
	return service.NameType == principal.NTUnknown ||
		service.NameType == principal.NTSrvHst ||
		service.NameType == principal.NTSrvInstance
}

func listContains(values []string, item string) bool {
	for _, value := range values {
		if value == item {
			return true
		}
	}
	return false
}

func protocolPrincipal(value principal.Principal) *protocol.PrincipalName {
	return &protocol.PrincipalName{NameType: int32(value.NameType), NameString: append([]string(nil), value.Components...)}
}

func sameProtocolPrincipal(left, right protocol.PrincipalName) bool {
	if left.NameType != right.NameType || len(left.NameString) != len(right.NameString) {
		return false
	}
	for index := range left.NameString {
		if left.NameString[index] != right.NameString[index] {
			return false
		}
	}
	return true
}

// lookupAlias resolves an optional KDB alias and returns its canonical record
// name. Ordinary Store implementations need only implement Lookup.
func (s *Server) lookupAlias(name principal.Principal) (kdb.PrincipalRecord, bool, principal.Principal, error) {
	resolver, ok := s.DB.(kdb.AliasResolver)
	if !ok {
		return kdb.PrincipalRecord{}, false, name, nil
	}
	canonicalName, isAlias, err := resolver.ResolveAlias(name)
	if err != nil || !isAlias {
		return kdb.PrincipalRecord{}, false, name, err
	}
	if canonicalName.Realm == "" || len(canonicalName.Components) == 0 {
		return kdb.PrincipalRecord{}, false, name, fmt.Errorf("alias resolver returned invalid canonical principal")
	}
	record, found, err := s.DB.Lookup(canonicalName)
	if err != nil || !found {
		return kdb.PrincipalRecord{}, false, name, err
	}
	if record.Name.Realm != "" && len(record.Name.Components) > 0 {
		canonicalName = record.Name
	}
	return record, true, canonicalName, nil
}

func joinComponents(values []string) string {
	result := ""
	for _, value := range values {
		result += value
	}
	return result
}

func principalSalt(key kdb.Key, name principal.Principal) string {
	if key.Salt != "" {
		return key.Salt
	}
	return name.Realm + joinComponents(name.Components)
}

func stringPointer(value string) *string { return &value }
func int32Pointer(value int32) *int32    { return &value }

func mandatoryChecksumType(etype int32) int32 {
	switch etype {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256
	case crypto.EnctypeCamellia128:
		return crypto.ChecksumCMACCamellia128
	case crypto.EnctypeCamellia256:
		return crypto.ChecksumCMACCamellia256
	default:
		return 0
	}
}

func encryptWithKey(key kdb.Key, usage uint32, plaintext []byte) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		return nil, err
	}
	return etype.Encrypt(key.Key, usage, plaintext)
}

func marshalDER(value any) []byte {
	data, _ := asn1.Marshal(value)
	return data
}

func isClosedNetworkError(err error) bool {
	return err == net.ErrClosed || (err != nil && err.Error() == "use of closed network connection")
}

// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"context"
	stdcrypto "crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
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
	kdcErrPreauthFailed    = 24
	kdcErrPreauthRequired  = 25
	kdcErrMorePreauth      = 91
	kdcErrGeneric          = 60
	kdcErrBadOption        = 13
	kdcErrPolicy           = 12
	kdcErrServerNoMatch    = 26
	kdcErrCannotPostdate   = 10
	kdcErrClientRevoked    = 18
	kdcErrKeyExpired       = 23
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

// Server is a Kerberos KDC backed by a pluggable principal store.
type Server struct {
	Realm         string
	DB            kdb.Store
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
	// PKINITClientCAs trusts client certificates for PKINIT authentication.
	PKINITClientCAs *x509.CertPool
	// PKINITRequireFreshness requires RFC 8070 freshness tokens on signed
	// PKINIT requests. Clients which advertise freshness receive an opaque
	// token in PREAUTH_REQUIRED and must echo it in PKAuthenticator.
	PKINITRequireFreshness bool
	// Authorize optionally mirrors MIT's kdcpolicy plugin hook for authenticated
	// AS exchanges and validated TGS requests. A nil hook permits all requests.
	// Hook KRBError codes in the protocol range are returned unchanged; other
	// errors default to KDC_ERR_POLICY or KRB_ERR_GENERIC as appropriate.
	Authorize func(client, service principal.Principal, asExchange bool) error
	// OTPValidator enables RFC 6560 preauthentication for the named
	// principals. OTP is accepted only inside FAST.
	OTPValidator func(principal.Principal, string) error
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
			return s.errorResponse(kdcErrGeneric, nil)
		}
		return s.handleASReq(request, data)
	case 0x6c:
		var request protocol.TGSReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return s.errorResponse(kdcErrGeneric, nil)
		}
		return s.handleTGSReq(request, data)
	default:
		return s.errorResponse(kdcErrGeneric, nil)
	}
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
	errs := make(chan error, 2)
	go func() { errs <- s.serveUDP(udpConn) }()
	go func() { errs <- s.serveTCP(tcpListener) }()
	select {
	case <-ctx.Done():
		_ = udpConn.Close()
		_ = tcpListener.Close()
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
	response := s.dispatch(request, false)
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
	response := s.dispatch(request, true)
	if len(response) == 0 {
		return
	}
	_ = transport.WriteTCPFrame(conn, response)
}

func (s *Server) dispatch(request []byte, isTCP bool) []byte {
	cache := s.getLookaside()
	if cached, hit := cache.begin(request, s.now()); hit {
		if len(cached) == 0 {
			return nil
		}
		return s.limitDatagramReply(cached, isTCP)
	}
	response := s.HandleMessage(request)
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

func (s *Server) handleASReq(request protocol.ASReq, raw []byte) []byte {
	if request.PVNO != 5 || request.MsgType != 10 ||
		request.ReqBody.CName == nil || request.ReqBody.SName == nil ||
		request.ReqBody.Realm == "" || request.ReqBody.SName.NameString == nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	var armor *fastContext
	if findPA(request.PAData, fast.PAFXFast) != nil {
		var errCode int32
		request, armor, errCode = s.unwrapFASTASReq(request, raw)
		if errCode != 0 {
			if armor != nil {
				return s.fastErrorResponse(errCode, request.ReqBody.SName, nil, armor.nonce, armor)
			}
			return s.errorResponse(errCode, request.ReqBody.SName)
		}
	}
	anonymousRequest := request.ReqBody.KDCOptions&types.KDCRequestAnonymous != 0
	clientName := principalFromProtocol(*request.ReqBody.CName, request.ReqBody.Realm)
	requestClientName := clientName
	if anonymousRequest && !isAnonymousPrincipal(clientName) {
		return s.errorResponse(kdcErrBadOption, request.ReqBody.SName)
	}
	var clientRecord kdb.PrincipalRecord
	var ok bool
	var err error
	if anonymousRequest {
		clientName = anonymousPrincipal()
		clientRecord = kdb.PrincipalRecord{Name: clientName}
		ok = true
	} else {
		clientRecord, ok, err = s.DB.Lookup(clientName)
		if err != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
	}
	if !ok && request.ReqBody.KDCOptions&types.KDCCanonicalize != 0 {
		clientRecord, ok, clientName, err = s.lookupAlias(clientName)
		if err != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
	}
	if !ok {
		return s.errorResponse(kdcErrCPrincipal, request.ReqBody.SName)
	}
	if !anonymousRequest && s.lockedOut(clientName, &clientRecord) {
		return s.errorResponse(kdcErrClientRevoked, request.ReqBody.SName)
	}
	serviceName := principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	serviceRecord, ok, err := s.DB.Lookup(serviceName)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	if !ok {
		return s.errorResponse(kdcErrSPrincipal, request.ReqBody.SName)
	}
	timestampPA := findPA(request.PAData, paEncTimestamp)
	spakePA := findPA(request.PAData, paSPAKE)
	pkinitPA := findPA(request.PAData, protocol.PADataPKASReq)
	otpPA := findPA(request.PAData, otp.PADataRequest)
	otpEnabled := s.OTPValidator != nil
	var etypeID int32
	var clientKey, serviceKey kdb.Key
	if pkinitPA != nil || anonymousRequest || otpEnabled {
		etypeID, serviceKey, ok = selectPKINITServiceKey(request.ReqBody.EType, serviceRecord)
	} else {
		etypeID, clientKey, serviceKey, ok = s.selectASKeys(request.ReqBody.EType, clientRecord, serviceRecord)
		if !ok && s.PKINITCertificate != nil && s.PKINITSigner != nil && s.PKINITClientCAs != nil {
			etypeID, serviceKey, ok = selectPKINITServiceKey(request.ReqBody.EType, serviceRecord)
		}
	}
	if !ok {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	if anonymousRequest && pkinitPA == nil {
		if s.PKINITCertificate == nil || s.PKINITSigner == nil {
			return s.errorResponse(kdcErrBadOption, request.ReqBody.SName)
		}
		methodData := protocol.MethodData{{PADataType: protocol.PADataPKASReq}}
		if findPA(request.PAData, protocol.PADataASFreshness) != nil &&
			s.PKINITCertificate != nil && s.PKINITSigner != nil {
			if token, ok := s.makeFreshnessToken(request.ReqBody.EType); ok {
				methodData = append(methodData, protocol.PAData{
					PADataType: protocol.PADataASFreshness, PADataValue: token,
				})
			}
		}
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData), request.ReqBody.Nonce, armor)
		}
		return s.errorResponseWithData(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData))
	}
	if otpEnabled && !anonymousRequest && pkinitPA == nil && timestampPA == nil &&
		spakePA == nil && otpPA == nil && !s.DisablePreauth {
		if armor == nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		nonce, err := otp.NewNonce(s.now(), armor.etype.KeySize())
		if err != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
		tokenInfo := []otp.TokenInfo{{Length: int32Pointer(-1), Format: int32Pointer(-1), IterationCount: int32Pointer(-1)}}
		if s.OTPTokenInfo != nil {
			tokenInfo = s.OTPTokenInfo(clientName)
		}
		if len(tokenInfo) == 0 {
			tokenInfo = []otp.TokenInfo{{Length: int32Pointer(-1), Format: int32Pointer(-1), IterationCount: int32Pointer(-1)}}
		}
		methodData := protocol.MethodData{{PADataType: otp.PADataChallenge,
			PADataValue: marshalDER(otp.Challenge{Nonce: nonce, TokenInfo: tokenInfo})}}
		cookie := make([]byte, 16)
		if _, err := io.ReadFull(crypto.RandomSource, cookie); err != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
		methodData = append(methodData, protocol.PAData{
			PADataType: fast.PAFXCookie, PADataValue: cookie,
		})
		return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName,
			marshalDER(methodData), request.ReqBody.Nonce, armor)
	}
	if otpPA != nil {
		if armor == nil || s.OTPValidator == nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		otpRequest, err := otp.DecodeRequest(otpPA.PADataValue)
		if err != nil || otpRequest.EncData.EType != armor.etype.ID() {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		nonce, err := otp.DecryptNonce(armor.etype, armor.key, otpRequest.EncData)
		if err != nil || otp.ValidateNonce(nonce, armor.etype.KeySize(), s.now(), s.skew()) != nil {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		if err := s.OTPValidator(clientName, string(otpRequest.OTPValue)); err != nil {
			s.recordPreauthFailure(clientName, &clientRecord)
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		s.recordPreauthSuccess(clientName, &clientRecord)
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		replyKey := &kdb.Key{Enctype: armor.etype.ID(), Key: append([]byte(nil), armor.key...)}
		return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
			armor.etype.ID(), clientKey, serviceKey, armor, true, replyKey, nil, append([]string(nil), s.OTPIndicators...))
	}
	if otpEnabled && armor == nil && !anonymousRequest {
		return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
	}
	encryptedChallengePA := findPA(request.PAData, paEncryptedChallenge)
	if encryptedChallengePA != nil {
		if armor == nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		candidates := make([]kdb.Key, 0, len(clientRecord.Keys))
		seen := make(map[int32]bool, len(clientRecord.Keys))
		for _, requestedEType := range request.ReqBody.EType {
			if key, exists := clientRecord.Keys[requestedEType]; exists {
				key.Enctype = requestedEType
				candidates = append(candidates, key)
				seen[requestedEType] = true
			}
		}
		for enctype, key := range clientRecord.Keys {
			if seen[enctype] {
				continue
			}
			key.Enctype = enctype
			candidates = append(candidates, key)
		}
		var matchedKey kdb.Key
		var matchedKeyEType crypto.EType
		var timestamp time.Time
		for _, candidate := range candidates {
			candidateEType, candidateErr := crypto.NewRegistry().Get(candidate.Enctype)
			if candidateErr != nil {
				continue
			}
			candidateTimestamp, candidateErr := preauth.DecryptEncryptedChallengeWithKeyEType(
				armor.etype, armor.key, candidateEType, candidate.Key,
				encryptedChallengePA.PADataValue)
			if candidateErr == nil {
				matchedKey = candidate
				matchedKeyEType = candidateEType
				timestamp = candidateTimestamp
				break
			}
		}
		if matchedKey.Enctype == 0 {
			s.recordPreauthFailure(clientName, &clientRecord)
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		if !s.withinSkew(timestamp) {
			return s.fastErrorResponse(krbAPErrSkew, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		clientKey = matchedKey
		s.recordPreauthSuccess(clientName, &clientRecord)
		if s.passwordExpired(clientRecord) {
			return s.fastErrorResponse(kdcErrKeyExpired, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		replyPA, replyErr := preauth.BuildEncryptedChallengeReplyWithKeyEType(
			armor.etype, armor.key, matchedKeyEType, matchedKey.Key, s.now())
		if replyErr != nil {
			return s.fastErrorResponse(kdcErrGeneric, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
			etypeID, clientKey, serviceKey, armor, true, nil, protocol.MethodData{replyPA},
			configuredIndicator(s.EncryptedChallengeIndicator))
	}
	if !anonymousRequest && s.EnableSPAKE && spakePA == nil && timestampPA == nil &&
		pkinitPA == nil && !s.DisablePreauth {
		methodData := protocol.MethodData{
			{PADataType: paEncTimestamp},
			{PADataType: paSPAKE},
		}
		if clientKey.Enctype != 0 {
			methodData = append(methodData, protocol.PAData{PADataType: 19, PADataValue: marshalDER(protocol.ETypeInfo2{{
				EType: etypeID, Salt: stringPointer(principalSalt(clientKey, clientName)),
			}})})
		}
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData), request.ReqBody.Nonce, armor)
		}
		return s.errorResponseWithData(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData))
	}
	selectedSPAKEGroup := s.selectSPAKEGroup(spakePA)
	if !anonymousRequest && selectedSPAKEGroup != 0 &&
		timestampPA == nil && pkinitPA == nil && !s.DisablePreauth {
		methodData := protocol.MethodData{
			{PADataType: paSPAKE, PADataValue: marshalDER(protocol.PASPAKE{
				Support: &protocol.SPAKESupport{Groups: s.spakeGroups()},
			})},
		}
		if clientKey.Enctype != 0 {
			methodData = append(methodData, protocol.PAData{PADataType: 19, PADataValue: marshalDER(protocol.ETypeInfo2{{
				EType: etypeID, Salt: stringPointer(principalSalt(clientKey, clientName)),
			}})})
		}
		// The challenge's masked value is generated from w, not from zero;
		// derive it using the selected long-term key.
		etype, err := crypto.NewRegistry().Get(etypeID)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		w, err := spake.DeriveW(etype, clientKey.Key, selectedSPAKEGroup)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		private, public, err := spake.Keygen(selectedSPAKEGroup, w, true)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		challenge, err := spake.EncodeChallenge(selectedSPAKEGroup, public)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		methodData[0].PADataValue = challenge
		cookie, err := s.makeSPAKECookie(selectedSPAKEGroup, private,
			spake.TranscriptForGroup(selectedSPAKEGroup, nil, spakePA.PADataValue, challenge))
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		methodData = append(methodData, protocol.PAData{PADataType: paFXCookie, PADataValue: cookie})
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData), request.ReqBody.Nonce, armor)
		}
		return s.errorResponseWithData(kdcErrMorePreauth, request.ReqBody.SName, marshalDER(methodData))
	}
	if spakePA != nil {
		msg, err := spake.Decode(spakePA.PADataValue)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		// A support message with no permitted group is not an attempted
		// SPAKE response.  MIT ignores it and continues through the ordinary
		// encrypted-timestamp preauthentication path.
		if msg.Response == nil {
			spakePA = nil
		} else {
			cookiePA := findPA(request.PAData, paFXCookie)
			group, private, transcript, okCookie := s.parseSPAKECookie(cookiePA)
			if !okCookie || !s.permitsSPAKEGroup(group) {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			etype, err := crypto.NewRegistry().Get(etypeID)
			if err != nil {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			w, err := spake.DeriveW(etype, clientKey.Key, group)
			if err != nil {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			transcript = spake.TranscriptForGroup(group, transcript, msg.Response.PubKey, nil)
			result, err := spake.Result(group, w, private, msg.Response.PubKey, false)
			if err != nil {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			bodyDER, err := asn1.Marshal(request.ReqBody)
			if err != nil {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			k1, err := spake.DeriveKey(etype, clientKey.Key, w, result, transcript, bodyDER, group, 1)
			if err != nil {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			if msg.Response.Factor.EType != etypeID {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			factorPlain, err := etype.Decrypt(k1, spake.KeyUsage, msg.Response.Factor.Cipher)
			var factor protocol.SPAKESecondFactor
			if err != nil {
				s.recordPreauthFailure(clientName, &clientRecord)
				if armor != nil {
					return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName, nil, request.ReqBody.Nonce, armor)
				}
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			if asn1.Unmarshal(factorPlain, &factor) != nil || factor.Type != spake.FactorNone {
				s.recordPreauthFailure(clientName, &clientRecord)
				if armor != nil {
					return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName, nil, request.ReqBody.Nonce, armor)
				}
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			k0, err := spake.DeriveKey(etype, clientKey.Key, w, result, transcript, bodyDER, group, 0)
			if err != nil {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			s.recordPreauthSuccess(clientName, &clientRecord)
			if s.passwordExpired(clientRecord) {
				return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
			}
			if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
				return response
			}
			return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
				etypeID, clientKey, serviceKey, armor, true, &kdb.Key{Enctype: etypeID, Key: k0}, nil,
				append([]string(nil), s.SPAKEPreauthIndicators...))
		}
	}
	if pkinitPA != nil {
		if s.PKINITCertificate == nil || s.PKINITSigner == nil ||
			(!anonymousRequest && s.PKINITClientCAs == nil) {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		bodyDER, err := asn1.FieldContent(raw, protocol.TagASReq, 4)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		verified, err := pkinit.VerifyPAASReqForKDC(pkinitPA.PADataValue, bodyDER)
		if err != nil || verified.Authenticator.Nonce != request.ReqBody.Nonce ||
			verified.Authenticator.CTime.IsZero() || !s.withinSkew(verified.Authenticator.CTime) {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		if len(verified.Authenticator.FreshnessToken) > 0 {
			if !s.verifyFreshnessToken(verified.Authenticator.FreshnessToken) {
				return s.pkinitFreshnessError(request, armor,
					kdcErrPreauthExpired)
			}
		} else if s.PKINITRequireFreshness && !anonymousRequest {
			return s.pkinitFreshnessError(request, armor,
				kdcErrPreauthFailed)
		}
		if anonymousRequest {
			if verified.Signed {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
		} else {
			if !verified.Signed {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			if err := pkinit.ValidateClientCertificate(verified.Certificate, s.PKINITClientCAs,
				requestClientName.Realm, requestClientName.Components); err != nil {
				return s.errorResponse(kdcErrClientNotTrusted, request.ReqBody.SName)
			}
		}
		if s.passwordExpired(clientRecord) {
			return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
		}
		s.recordPreauthSuccess(clientName, &clientRecord)
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		selectedKDF := pkinit.PickKDFAlgorithm(verified.SupportedKDFs)
		requestDER, err := asn1.Marshal(request)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		kdfClientName := requestClientName
		if anonymousRequest {
			kdfClientName = anonymousPrincipal()
		}
		paRep, replyKey, err := pkinit.BuildPAASRepWithKDF(verified.PublicValue, etypeID,
			request.ReqBody.Nonce, s.PKINITCertificate, s.PKINITSigner, selectedKDF,
			kdfClientName, serviceName, requestDER)
		if err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		replyEncryptionKey := &kdb.Key{Enctype: etypeID, Key: replyKey}
		replyPAs := protocol.MethodData{paRep}
		return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
			etypeID, clientKey, serviceKey, armor, true, replyEncryptionKey, replyPAs,
			func() []string {
				if anonymousRequest {
					return nil
				}
				return append([]string(nil), s.PKINITIndicators...)
			}())
	}
	if timestampPA == nil {
		if s.DisablePreauth {
			if s.passwordExpired(clientRecord) {
				return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
			}
			if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
				return response
			}
			return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
				etypeID, clientKey, serviceKey, armor, false, nil, nil, nil)
		}
		var methodData protocol.MethodData
		// MIT does not advertise encrypted-timestamp inside FAST.  Offering
		// it before encrypted challenge causes the MIT client to select the
		// fallback factor and never exercise PA-ENCRYPTED-CHALLENGE.
		if armor == nil {
			methodData = append(methodData, protocol.PAData{
				PADataType: paEncTimestamp, PADataValue: []byte{},
			})
		}
		if clientKey.Enctype != 0 {
			methodData = append(methodData, protocol.PAData{
				PADataType: 19,
				PADataValue: marshalDER(protocol.ETypeInfo2{{
					EType: etypeID,
					Salt:  stringPointer(principalSalt(clientKey, clientName)),
				}}),
			})
		}
		if armor != nil && clientKey.Enctype != 0 {
			methodData = append(methodData, protocol.PAData{PADataType: paEncryptedChallenge})
		}
		if s.PKINITCertificate != nil && s.PKINITSigner != nil && s.PKINITClientCAs != nil {
			methodData = append(methodData, protocol.PAData{PADataType: protocol.PADataPKASReq})
		}
		if findPA(request.PAData, protocol.PADataASFreshness) != nil &&
			s.PKINITCertificate != nil && s.PKINITSigner != nil &&
			s.PKINITClientCAs != nil {
			if token, ok := s.makeFreshnessToken(request.ReqBody.EType); ok {
				methodData = append(methodData, protocol.PAData{
					PADataType: protocol.PADataASFreshness, PADataValue: token,
				})
			}
		}
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData), request.ReqBody.Nonce, armor)
		}
		return s.errorResponseWithData(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData))
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	timestampCipher := timestampPA.PADataValue
	var encrypted protocol.EncryptedData
	if err := asn1.Unmarshal(timestampPA.PADataValue, &encrypted); err == nil &&
		encrypted.EType == etypeID && len(encrypted.Cipher) > 0 {
		timestampCipher = encrypted.Cipher
	}
	timestampPlain, err := etype.Decrypt(clientKey.Key, 1, timestampCipher)
	if err != nil {
		s.recordPreauthFailure(clientName, &clientRecord)
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName, nil, request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
	}
	var timestamp preauth.EncTimestamp
	if err := asn1.Unmarshal(timestampPlain, &timestamp); err != nil ||
		!timestamp.PATimestamp.Present || !s.withinSkew(timestamp.PATimestamp.Time) {
		if armor != nil {
			return s.fastErrorResponse(krbAPErrSkew, request.ReqBody.SName, nil, request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(krbAPErrSkew, request.ReqBody.SName)
	}
	s.recordPreauthSuccess(clientName, &clientRecord)
	if !clientRecord.PasswordExpiration.IsZero() &&
		!s.now().Before(clientRecord.PasswordExpiration) {
		if armor != nil {
			return s.fastErrorResponse(kdcErrKeyExpired, request.ReqBody.SName, nil, request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
	}
	if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
		return response
	}
	return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
		etypeID, clientKey, serviceKey, armor, true, nil, nil, nil)
}

func (s *Server) unwrapFASTASReq(request protocol.ASReq, raw []byte) (protocol.ASReq, *fastContext, int32) {
	pa := findPA(request.PAData, fast.PAFXFast)
	if pa == nil {
		return request, nil, 0
	}
	var wrapper protocol.PAFXFastRequest
	if err := asn1.Unmarshal(pa.PADataValue, &wrapper); err != nil ||
		wrapper.ArmoredData.Armor == nil ||
		wrapper.ArmoredData.Armor.ArmorType != fast.ArmorTypeAPReq {
		return request, nil, kdcErrPreauthFailed
	}
	var apRequest protocol.APReq
	if err := asn1.Unmarshal(wrapper.ArmoredData.Armor.ArmorValue, &apRequest); err != nil ||
		apRequest.PVNO != 5 || apRequest.MsgType != 14 ||
		apRequest.Ticket.Realm != s.Realm ||
		len(apRequest.Ticket.SName.NameString) != 2 ||
		apRequest.Ticket.SName.NameString[0] != "krbtgt" ||
		apRequest.Ticket.SName.NameString[1] != s.Realm {
		return request, nil, kdcErrPreauthFailed
	}
	tgtName := principal.Principal{
		Realm: apRequest.Ticket.Realm, NameType: principal.NTSrvInstance,
		Components: apRequest.Ticket.SName.NameString,
	}
	tgtRecord, ok, err := s.DB.Lookup(tgtName)
	if err != nil || !ok {
		return request, nil, kdcErrPreauthFailed
	}
	ticketKey, ok := selectKVNO(tgtRecord, apRequest.Ticket.EncPart.EType, apRequest.Ticket.EncPart.KVNO)
	if !ok {
		return request, nil, kdcErrPreauthFailed
	}
	ticketEType, err := crypto.NewRegistry().Get(ticketKey.Enctype)
	if err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	ticketPlain, err := ticketEType.Decrypt(ticketKey.Key, 2, apRequest.Ticket.EncPart.Cipher)
	if err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	var ticketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(ticketPlain, &ticketPart); err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	if code, valid := s.ticketValidity(ticketPart); !valid {
		return request, nil, code
	}
	if apRequest.Authenticator.EType != ticketPart.Key.KeyType {
		return request, nil, kdcErrPreauthFailed
	}
	sessionEType, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
	if err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	authPlain, err := sessionEType.Decrypt(ticketPart.Key.KeyValue, 11, apRequest.Authenticator.Cipher)
	if err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	var authenticator protocol.Authenticator
	if err := asn1.Unmarshal(authPlain, &authenticator); err != nil ||
		authenticator.AuthenticatorVNO != 5 ||
		authenticator.CRealm != ticketPart.CRealm ||
		!sameProtocolPrincipal(authenticator.CName, ticketPart.CName) ||
		!authenticator.Ctime.Present ||
		!s.withinSkew(authenticator.Ctime.Time) ||
		authenticator.SubKey == nil ||
		authenticator.SubKey.KeyType != ticketPart.Key.KeyType {
		return request, nil, kdcErrPreauthFailed
	}
	if len(authenticator.SubKey.KeyValue) != sessionEType.KeySize() {
		return request, nil, kdcErrPreauthFailed
	}
	armorKey, err := crypto.CF2(sessionEType, authenticator.SubKey.KeyValue, ticketPart.Key.KeyValue,
		[]byte("subkeyarmor"), []byte("ticketarmor"))
	if err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	armor := &fastContext{etype: sessionEType, key: armorKey}
	body, err := asn1.FieldContent(raw, protocol.TagASReq, 4)
	if err != nil {
		return request, armor, kdcErrPreauthFailed
	}
	if wrapper.ArmoredData.EncFastReq.EType != sessionEType.ID() ||
		wrapper.ArmoredData.ReqChecksum.ChecksumType != fast.ChecksumType(sessionEType.ID()) ||
		wrapper.ArmoredData.ReqChecksum.Checksum == nil {
		return request, armor, krbAPErrBadIntegrity
	}
	plaintext, err := sessionEType.Decrypt(armorKey, fast.UsageReq, wrapper.ArmoredData.EncFastReq.Cipher)
	if err != nil {
		return request, armor, krbAPErrBadIntegrity
	}
	var fastRequest protocol.KrbFastReq
	if err := asn1.Unmarshal(plaintext, &fastRequest); err != nil {
		return request, armor, krbAPErrBadIntegrity
	}
	if err := sessionEType.VerifyChecksum(armorKey, fast.UsageReqChecksum, body, wrapper.ArmoredData.ReqChecksum.Checksum); err != nil {
		return request, armor, krbAPErrBadIntegrity
	}
	if cookie := findPA(fastRequest.PAData, fast.PAFXCookie); cookie != nil {
		copy := *cookie
		copy.PADataValue = append([]byte(nil), cookie.PADataValue...)
		armor.cookie = &copy
	}
	request.ReqBody = fastRequest.ReqBody
	request.PAData = fastRequest.PAData
	armor.nonce = fastRequest.ReqBody.Nonce
	return request, armor, 0
}

func (s *Server) pacPrivsvrKey() (kdb.Key, bool) {
	name := principal.Principal{
		Realm: s.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", s.Realm},
	}
	record, ok, err := s.DB.Lookup(name)
	if err != nil || !ok {
		return kdb.Key{}, false
	}
	enctypes := make([]int, 0, len(record.Keys))
	registry := crypto.NewRegistry()
	for enctype, key := range record.Keys {
		if key.KVNO != 0 && record.KVNO != 0 && key.KVNO != record.KVNO {
			continue
		}
		if _, err := registry.Get(enctype); err == nil {
			enctypes = append(enctypes, int(enctype))
		}
	}
	sort.Ints(enctypes)
	if len(enctypes) == 0 {
		return kdb.Key{}, false
	}
	key := record.Keys[int32(enctypes[0])]
	key.Enctype = int32(enctypes[0])
	return key, true
}

func (s *Server) issuePAC(ticketPart *protocol.EncTicketPart, client, service principal.Principal,
	headerKey, serviceKey kdb.Key, serviceTicket bool, replaceClient bool) error {
	return s.issuePACWithOptions(ticketPart, client, service, headerKey, serviceKey,
		serviceTicket, replaceClient, nil, nil, nil)
}

func (s *Server) issuePACWithOptions(ticketPart *protocol.EncTicketPart, client, service principal.Principal,
	headerKey, serviceKey kdb.Key, serviceTicket bool, replaceClient bool,
	replacedReplyKey *kdb.Key, delegationEvidence *principal.Principal,
	pacVerifyKey *kdb.Key) error {
	if !s.EnablePAC {
		return nil
	}
	privKey, ok := s.pacPrivsvrKey()
	if !ok {
		// AS TGTs use the same krbtgt key for both PAC signatures.
		if len(service.Components) == 2 && service.Components[0] == "krbtgt" {
			privKey = serviceKey
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("PAC: no usable krbtgt key for PAC signatures")
	}
	privEType, err := crypto.NewRegistry().Get(privKey.Enctype)
	if err != nil {
		return err
	}
	verifyKey := headerKey
	if pacVerifyKey != nil {
		verifyKey = *pacVerifyKey
	}
	headerEType, err := crypto.NewRegistry().Get(verifyKey.Enctype)
	if err != nil {
		return err
	}
	headerPACKey := pac.Key{EType: headerEType, Key: verifyKey.Key}
	serviceEType, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		return err
	}
	serverPACKey := pac.Key{EType: serviceEType, Key: serviceKey.Key}
	privPACKey := pac.Key{EType: privEType, Key: privKey.Key}
	p, err := pac.FromAuthorizationData(ticketPart.AuthorizationData)
	if err != nil {
		if !stderrors.Is(err, pac.ErrNotFound) {
			return err
		}
		p = pac.New()
	} else if err := p.Verify(headerPACKey, privPACKey); err != nil {
		return err
	}
	if replaceClient {
		if err := p.SetClientInfo(ticketPart.AuthTime.Time, client); err != nil {
			return err
		}
	}
	if len(p.Buffers) == 0 && s.GeneratePACIdentity != nil {
		identity, err := s.GeneratePACIdentity(client, service)
		if err != nil {
			return err
		}
		if identity != nil {
			if identity.LogonInfo != nil {
				logonInfo, err := identity.LogonInfo.MarshalBinary()
				if err != nil {
					return err
				}
				p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.LogonInfoBuffer, Data: logonInfo})
			}
			upn := pac.UPNDNSInfoData{
				UPN: identity.UPN, DNSDomainName: identity.DNSDomainName,
				SAMName: identity.SAMName, Flags: identity.Flags,
			}
			if identity.Flags&pac.UPNDNSInfoHasSAMNameAndSID != 0 {
				sid := identity.SID
				upn.SID = &sid
			}
			data, err := upn.MarshalBinary()
			if err != nil {
				return err
			}
			p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.UPNDNSInfo, Data: data})
		}
	} else if len(p.Buffers) == 0 && s.GeneratePAC != nil {
		logonInfo, err := s.GeneratePAC(client, service)
		if err != nil {
			return err
		}
		p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.LogonInfoBuffer, Data: logonInfo})
	} else if len(p.Buffers) == 0 {
		p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.LogonInfoBuffer})
	}
	if replacedReplyKey != nil && s.GeneratePACCredentials != nil {
		plaintext, enctype, err := s.GeneratePACCredentials(client, service, *replacedReplyKey)
		if err != nil {
			return err
		}
		if enctype != replacedReplyKey.Enctype {
			return fmt.Errorf("PAC: credentials enctype %d does not match reply key enctype %d",
				enctype, replacedReplyKey.Enctype)
		}
		credentialEType, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return err
		}
		credentials, err := pac.EncryptCredentialInfo(credentialEType,
			replacedReplyKey.Key, plaintext)
		if err != nil {
			return err
		}
		data, err := credentials.MarshalBinary()
		if err != nil {
			return err
		}
		p.SetBuffer(pac.CredentialInfoBuffer, data)
	}
	if delegationEvidence != nil {
		var info pac.DelegationInfo
		if data, ok := p.Buffer(pac.DelegationInfoBuffer); ok {
			info, err = pac.ParseDelegationInfo(data)
			if err != nil {
				return err
			}
		}
		info.ProxyTarget = strings.Join(service.Components, "/")
		info.TransitedServices = append(info.TransitedServices, delegationEvidence.String())
		data, err := info.MarshalBinary()
		if err != nil {
			return err
		}
		p.SetBuffer(pac.DelegationInfoBuffer, data)
	}
	var dummyTicket []byte
	if serviceTicket {
		originalAuthData := ticketPart.AuthorizationData
		dummyAuthData, err := pac.AddDummyAuthorizationData(originalAuthData)
		if err != nil {
			return err
		}
		ticketPart.AuthorizationData = dummyAuthData
		dummyTicket = marshalDER(*ticketPart)
		ticketPart.AuthorizationData = originalAuthData
	}
	var encoded []byte
	if dummyTicket != nil {
		encoded, err = p.SignWithTicket(ticketPart.AuthTime.Time, &client,
			serverPACKey, privPACKey, dummyTicket)
	} else {
		encoded, err = p.Sign(ticketPart.AuthTime.Time, &client,
			serverPACKey, privPACKey, serviceTicket)
	}
	if err != nil {
		return err
	}
	authdata, err := pac.AddAuthorizationData(ticketPart.AuthorizationData, encoded)
	if err != nil {
		return err
	}
	ticketPart.AuthorizationData = authdata
	return nil
}

func stripCAMMAC(data protocol.AuthorizationData) (protocol.AuthorizationData, error) {
	out := make(protocol.AuthorizationData, 0, len(data))
	for _, outer := range data {
		if outer.ADType != protocol.ADIfRelevant {
			out = append(out, outer)
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(outer.ADData, &inner); err != nil {
			return nil, fmt.Errorf("CAMMAC IF-RELEVANT: %w", err)
		}
		filtered := make(protocol.AuthorizationData, 0, len(inner))
		for _, entry := range inner {
			if entry.ADType != protocol.ADCAMMAC {
				filtered = append(filtered, entry)
			}
		}
		if len(filtered) == len(inner) {
			out = append(out, outer)
			continue
		}
		if len(filtered) != 0 {
			encoded, err := asn1.Marshal(filtered)
			if err != nil {
				return nil, fmt.Errorf("CAMMAC IF-RELEVANT: %w", err)
			}
			out = append(out, protocol.AuthorizationDataEntry{
				ADType: protocol.ADIfRelevant, ADData: encoded,
			})
		}
	}
	return out, nil
}

func (s *Server) issueCAMMAC(ticketPart *protocol.EncTicketPart, serviceKey kdb.Key,
	verifiedElements protocol.AuthorizationData, assertedIndicators []string) error {
	var elements protocol.AuthorizationData
	var err error
	if len(assertedIndicators) > 0 {
		indicators := make([]types.UTF8String, len(assertedIndicators))
		for i, indicator := range assertedIndicators {
			indicators[i] = types.UTF8String(indicator)
		}
		encodedIndicators, marshalErr := asn1.Marshal(indicators)
		if marshalErr != nil {
			return fmt.Errorf("CAMMAC auth indicators: %w", marshalErr)
		}
		elements = protocol.AuthorizationData{{
			ADType: protocol.ADAuthIndicator, ADData: encodedIndicators,
		}}
	} else if verifiedElements != nil {
		elements = verifiedElements
	} else {
		elements, err = cammac.ProtectedElements(ticketPart.AuthorizationData)
		if err != nil && !stderrors.Is(err, cammac.ErrNotFound) {
			return err
		}
		if stderrors.Is(err, cammac.ErrNotFound) {
			return nil
		}
	}
	kdcKey, ok := s.freshnessKey([]int32{serviceKey.Enctype})
	if !ok {
		return fmt.Errorf("CAMMAC: no usable local krbtgt key")
	}
	base, err := stripCAMMAC(ticketPart.AuthorizationData)
	if err != nil {
		return err
	}
	ticketPart.AuthorizationData = base
	wrapped, err := cammac.Marshal(elements, *ticketPart,
		protocol.EncryptionKey{KeyType: kdcKey.Enctype, KeyValue: kdcKey.Key},
		protocol.EncryptionKey{KeyType: serviceKey.Enctype, KeyValue: serviceKey.Key},
		kdcKey.KVNO)
	if err != nil {
		return err
	}
	ticketPart.AuthorizationData = append(ticketPart.AuthorizationData, wrapped...)
	return nil
}

func (s *Server) buildASRep(request protocol.ASReq, clientName principal.Principal, clientRecord kdb.PrincipalRecord, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, clientKey, serviceKey kdb.Key, armor *fastContext, preauthenticated bool, replyEncryptionKey *kdb.Key, replyPAs protocol.MethodData, assertedIndicators []string) []byte {
	if response := s.requireAuthError(serviceRecord, assertedIndicators, armor, request.ReqBody.SName); response != nil {
		return response
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	sessionValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, sessionValue); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	now := s.now().UTC().Truncate(time.Second)
	authTime := types.KerberosTime{Time: now, Present: true}
	startTime := authTime
	flags := types.TicketInitial
	if preauthenticated {
		flags |= types.TicketPreAuthent
	}
	if request.ReqBody.KDCOptions&types.KDCRequestAnonymous != 0 {
		flags |= types.TicketAnonymous
	}
	if request.ReqBody.KDCOptions&types.KDCForwardable != 0 {
		flags |= types.TicketForwardable
	}
	if request.ReqBody.KDCOptions&types.KDCProxiable != 0 {
		flags |= types.TicketProxiable
	}
	s.applyFlagPolicy(&flags)
	if request.ReqBody.KDCOptions&types.KDCAllowPostdate != 0 {
		flags |= types.TicketMayPostdate
	}
	if request.ReqBody.KDCOptions&types.KDCPostdated != 0 {
		if request.ReqBody.From == nil || !request.ReqBody.From.Present ||
			!request.ReqBody.From.Time.After(now) ||
			(request.ReqBody.Till.Present && !request.ReqBody.Till.Time.After(request.ReqBody.From.Time)) ||
			request.ReqBody.KDCOptions&types.KDCAllowPostdate == 0 {
			return s.errorResponse(kdcErrCannotPostdate, request.ReqBody.SName)
		}
		startTime = *request.ReqBody.From
		flags |= types.TicketPostdated | types.TicketInvalid
	}
	endTime := s.ticketEndFrom(request.ReqBody.Till, startTime.Time)
	renewTill := s.renewTill(request.ReqBody.KDCOptions, request.ReqBody.RTime, request.ReqBody.Till, startTime.Time, endTime.Time)
	if s.Policy != nil && !s.Policy.AllowRenewable {
		renewTill = nil
	}
	if renewTill != nil {
		flags |= types.TicketRenewable
	}
	var contributionKey []byte
	if request.ReqBody.KDCOptions&types.KDCRequestAnonymous != 0 &&
		replyEncryptionKey != nil {
		contributionKey = append([]byte(nil), sessionValue...)
		sessionValue, err = crypto.CF2(etype, contributionKey, replyEncryptionKey.Key,
			[]byte("PKINIT"), []byte("KEYEXCHANGE"))
		if err != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
	}
	ticketPart := protocol.EncTicketPart{
		Flags:    flags,
		Key:      protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		CRealm:   clientName.Realm,
		CName:    protocol.PrincipalName{NameType: int32(clientName.NameType), NameString: clientName.Components},
		AuthTime: authTime, StartTime: &startTime, EndTime: endTime, RenewTill: renewTill,
	}
	if err := s.issueCAMMAC(&ticketPart, serviceKey, nil, assertedIndicators); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	if err := s.issuePACWithOptions(&ticketPart, clientName, serviceName, serviceKey, serviceKey, false, false,
		replyEncryptionKey, nil, nil); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	ticketPlain := marshalDER(ticketPart)
	ticketCipher, err := encryptWithKey(serviceKey, 2, ticketPlain)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	ticketKVNO := serviceKey.KVNO
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: request.ReqBody.Realm,
		SName:   *request.ReqBody.SName,
		EncPart: protocol.EncryptedData{EType: etypeID, KVNO: &ticketKVNO, Cipher: ticketCipher},
	}
	if request.ReqBody.KDCOptions&types.KDCRequestAnonymous != 0 &&
		replyEncryptionKey != nil {
		encodedKey := marshalDER(protocol.EncryptionKey{
			KeyType: etypeID, KeyValue: contributionKey,
		})
		cipher, encryptErr := etype.Encrypt(replyEncryptionKey.Key, keyUsagePAPKINITKX, encodedKey)
		if encryptErr != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
		replyPAs = append(replyPAs, protocol.PAData{
			PADataType: 147,
			PADataValue: marshalDER(protocol.EncryptedData{
				EType: etypeID, Cipher: cipher,
			}),
		})
	}
	lastReq := protocol.LastReq{{LRType: 0, LRValue: types.KerberosTime{Time: now, Present: true}}}
	part := protocol.EncASRepPart{
		Key:     protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		LastReq: lastReq, Nonce: request.ReqBody.Nonce, Flags: flags,
		AuthTime: authTime, StartTime: &startTime, EndTime: endTime, RenewTill: renewTill,
		SRealm: request.ReqBody.Realm, SName: *request.ReqBody.SName,
	}
	replyPlain := marshalDER(part)
	replyKey := clientKey
	if replyEncryptionKey != nil {
		replyKey = *replyEncryptionKey
		replyKey.Enctype = etypeID
	}
	replyCipher, err := encryptWithKey(replyKey, 3, replyPlain)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	reply := protocol.ASRep{
		PVNO: 5, MsgType: 11,
		CRealm:  clientName.Realm,
		CName:   *protocolPrincipal(clientName),
		Ticket:  ticket,
		EncPart: protocol.EncryptedData{EType: etypeID, Cipher: replyCipher},
	}
	if len(replyPAs) > 0 {
		reply.PAData = replyPAs
	}
	if armor == nil {
		return marshalDER(reply)
	}
	return s.wrapFASTASRep(reply, replyKey, armor, replyPAs)
}

func (s *Server) wrapFASTASRep(reply protocol.ASRep, clientKey kdb.Key, armor *fastContext, replyPAs protocol.MethodData) []byte {
	strengthenValue := make([]byte, armor.etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, strengthenValue); err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyEType, err := crypto.NewRegistry().Get(reply.EncPart.EType)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyKey, err := crypto.CF2WithKeyEType(armor.etype, strengthenValue,
		replyEType, clientKey.Key,
		[]byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyPlain, err := replyEType.Decrypt(clientKey.Key, 3, reply.EncPart.Cipher)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyCipher, err := armor.etype.Encrypt(replyKey, 3, replyPlain)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	reply.EncPart = protocol.EncryptedData{EType: armor.etype.ID(), Cipher: replyCipher}
	ticketDER := marshalDER(reply.Ticket)
	ticketChecksum, err := armor.etype.Checksum(armor.key, fast.UsageFinished, ticketDER)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	now := s.now().UTC()
	fastResponse := protocol.KrbFastResponse{
		StrengthenKey: &protocol.EncryptionKey{KeyType: armor.etype.ID(), KeyValue: strengthenValue},
		Finished: &protocol.KrbFastFinished{
			Timestamp: types.KerberosTime{Time: now, Present: true},
			Usec:      int32(now.Nanosecond() / 1000),
			CRealm:    reply.CRealm, CName: reply.CName,
			TicketChecksum: protocol.Checksum{
				ChecksumType: fast.ChecksumType(armor.etype.ID()),
				Checksum:     ticketChecksum,
			},
		},
		Nonce: armor.nonce,
	}
	if armor.cookie != nil {
		fastResponse.PAData = protocol.MethodData{*armor.cookie}
	}
	if len(replyPAs) > 0 {
		fastResponse.PAData = append(fastResponse.PAData, replyPAs...)
	}
	responseCipher, err := armor.etype.Encrypt(armor.key, fast.UsageRep, marshalDER(fastResponse))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	reply.PAData = protocol.MethodData{{
		PADataType: fast.PAFXFast,
		PADataValue: marshalDER(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{
			EncFastRep: protocol.EncryptedData{EType: armor.etype.ID(), Cipher: responseCipher},
		}}),
	}}
	return marshalDER(reply)
}

func (s *Server) wrapFASTTGSRep(reply protocol.TGSRep, replyKey protocol.EncryptionKey, replyUsage uint32, armor *fastContext) []byte {
	strengthenValue := make([]byte, armor.etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, strengthenValue); err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyEType, err := crypto.NewRegistry().Get(reply.EncPart.EType)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	effectiveKey, err := crypto.CF2WithKeyEType(armor.etype, strengthenValue,
		replyEType, replyKey.KeyValue,
		[]byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyPlain, err := replyEType.Decrypt(replyKey.KeyValue, replyUsage, reply.EncPart.Cipher)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	replyCipher, err := armor.etype.Encrypt(effectiveKey, replyUsage, replyPlain)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	reply.EncPart = protocol.EncryptedData{EType: armor.etype.ID(), Cipher: replyCipher}
	ticketChecksum, err := armor.etype.Checksum(armor.key, fast.UsageFinished, marshalDER(reply.Ticket))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	now := s.now().UTC()
	fastResponse := protocol.KrbFastResponse{
		StrengthenKey: &protocol.EncryptionKey{KeyType: armor.etype.ID(), KeyValue: strengthenValue},
		Finished: &protocol.KrbFastFinished{
			Timestamp: types.KerberosTime{Time: now, Present: true},
			Usec:      int32(now.Nanosecond() / 1000),
			CRealm:    reply.CRealm,
			CName:     reply.CName,
			TicketChecksum: protocol.Checksum{
				ChecksumType: fast.ChecksumType(armor.etype.ID()),
				Checksum:     ticketChecksum,
			},
		},
		Nonce: armor.nonce,
	}
	if armor.cookie != nil {
		fastResponse.PAData = protocol.MethodData{*armor.cookie}
	}
	fastResponse.PAData = append(fastResponse.PAData, reply.PAData...)
	responseCipher, err := armor.etype.Encrypt(armor.key, fast.UsageRep, marshalDER(fastResponse))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, &reply.Ticket.SName)
	}
	reply.PAData = protocol.MethodData{{
		PADataType: fast.PAFXFast,
		PADataValue: marshalDER(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{
			EncFastRep: protocol.EncryptedData{EType: armor.etype.ID(), Cipher: responseCipher},
		}}),
	}}
	return marshalDER(reply)
}

func (s *Server) fastErrorResponse(code int32, service *protocol.PrincipalName, data []byte, nonce uint32, armor *fastContext) []byte {
	return s.fastErrorResponseWithText(code, service, data, nonce, armor, "")
}

func (s *Server) fastErrorResponseWithText(code int32, service *protocol.PrincipalName, data []byte, nonce uint32, armor *fastContext, text string) []byte {
	var inner protocol.MethodData
	if armor.cookie != nil {
		inner = append(inner, *armor.cookie)
	} else {
		// MIT's FAST error processing only retries when the protected response
		// carries a PA-FX-COOKIE.  A trivial cookie is sufficient when there is
		// no server-side preauthentication state to preserve.
		inner = append(inner, protocol.PAData{
			PADataType: fast.PAFXCookie, PADataValue: []byte("MIT"),
		})
	}
	if len(data) > 0 {
		var errorData protocol.MethodData
		if asn1.Unmarshal(data, &errorData) == nil {
			inner = append(inner, errorData...)
		}
	}
	inner = append(inner, protocol.PAData{
		PADataType:  fast.PAFXError,
		PADataValue: s.errorResponseWithText(code, service, text),
	})
	fastResponse := protocol.KrbFastResponse{PAData: inner, Nonce: nonce}
	responseCipher, err := armor.etype.Encrypt(armor.key, fast.UsageRep, marshalDER(fastResponse))
	if err != nil {
		return s.errorResponseWithText(code, service, text)
	}
	outer := protocol.MethodData{{
		PADataType: fast.PAFXFast,
		PADataValue: marshalDER(protocol.PAFXFastReply{ArmoredData: protocol.KrbFastArmoredRep{
			EncFastRep: protocol.EncryptedData{EType: armor.etype.ID(), Cipher: responseCipher},
		}}),
	}}
	return s.errorResponseWithData(code, service, marshalDER(outer))
}

func (s *Server) tgsErrorResponse(armor *fastContext, code int32, service *protocol.PrincipalName) []byte {
	if armor == nil {
		return s.errorResponse(code, service)
	}
	return s.fastErrorResponse(code, service, nil, armor.nonce, armor)
}

func (s *Server) handleTGSReq(request protocol.TGSReq, raw []byte) []byte {
	if request.PVNO != 5 || request.MsgType != 12 || len(request.PAData) == 0 ||
		request.ReqBody.SName == nil || request.ReqBody.Realm == "" {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	pa := findPA(request.PAData, paTGSReq)
	if pa == nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	var apRequest protocol.APReq
	if err := asn1.Unmarshal(pa.PADataValue, &apRequest); err != nil ||
		apRequest.PVNO != 5 || apRequest.MsgType != 14 {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	tgtName := principal.Principal{
		Realm: apRequest.Ticket.Realm, NameType: principal.NTSrvInstance,
		Components: apRequest.Ticket.SName.NameString,
	}
	tgtRecord, ok, err := s.DB.Lookup(tgtName)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	if !ok {
		return s.errorResponse(kdcErrSPrincipal, request.ReqBody.SName)
	}
	ticketKey, ok := selectKVNO(tgtRecord, apRequest.Ticket.EncPart.EType, apRequest.Ticket.EncPart.KVNO)
	if !ok {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	ticketEType, err := crypto.NewRegistry().Get(ticketKey.Enctype)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	ticketPlain, err := ticketEType.Decrypt(ticketKey.Key, 2, apRequest.Ticket.EncPart.Cipher)
	if err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	var ticketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(ticketPlain, &ticketPart); err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	sessionEType, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	authPlain, err := sessionEType.Decrypt(ticketPart.Key.KeyValue, 7, apRequest.Authenticator.Cipher)
	if err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	var authenticator protocol.Authenticator
	if err := asn1.Unmarshal(authPlain, &authenticator); err != nil ||
		authenticator.AuthenticatorVNO != 5 ||
		authenticator.CRealm != ticketPart.CRealm ||
		!sameProtocolPrincipal(authenticator.CName, ticketPart.CName) {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	if !s.withinSkew(authenticator.Ctime.Time) {
		return s.errorResponse(krbAPErrSkew, request.ReqBody.SName)
	}
	if authenticator.Checksum == nil ||
		authenticator.Checksum.ChecksumType != mandatoryChecksumType(ticketPart.Key.KeyType) {
		return s.errorResponse(krbAPErrInKeyUsage, request.ReqBody.SName)
	}
	body, err := asn1.FieldContent(raw, protocol.TagTGSReq, 4)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	if err := sessionEType.VerifyChecksum(ticketPart.Key.KeyValue, 6, body, authenticator.Checksum.Checksum); err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	var armor *fastContext
	if findPA(request.PAData, fast.PAFXFast) != nil {
		var errCode int32
		request, armor, errCode = s.unwrapFASTTGSReq(request, pa.PADataValue, ticketPart, authenticator)
		if errCode != 0 {
			if armor != nil {
				return s.fastErrorResponse(errCode, request.ReqBody.SName, nil, armor.nonce, armor)
			}
			return s.errorResponse(errCode, request.ReqBody.SName)
		}
	}
	requestedServiceName := principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	if err := cammac.VerifyKDC(ticketPart.AuthorizationData, ticketPart,
		protocol.EncryptionKey{KeyType: ticketKey.Enctype, KeyValue: ticketKey.Key}); err != nil &&
		!stderrors.Is(err, cammac.ErrNotFound) {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	var verifiedHeaderCAMMACElements protocol.AuthorizationData
	if err := cammac.VerifyKDC(ticketPart.AuthorizationData, ticketPart,
		protocol.EncryptionKey{KeyType: ticketKey.Enctype, KeyValue: ticketKey.Key}); err == nil {
		verifiedHeaderCAMMACElements, err = cammac.ProtectedElements(ticketPart.AuthorizationData)
		if err != nil {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		}
	}
	options := request.ReqBody.KDCOptions
	if options&types.KDCEncTktInSkey != 0 {
		if len(request.ReqBody.AdditionalTickets) != 1 ||
			options&(types.KDCRenew|types.KDCValidate|types.KDCForwarded|types.KDCProxy|types.KDCCNameInAddlTkt) != 0 ||
			requestedServiceName.Realm != s.Realm {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
	}
	if options&types.KDCRenew != 0 {
		if code, ok := s.ticketValidity(ticketPart); !ok {
			return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
		}
		if ticketPart.Flags&types.TicketRenewable == 0 {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		if ticketPart.RenewTill == nil || s.now().After(ticketPart.RenewTill.Time) {
			return s.tgsErrorResponse(armor, krbAPErrTktExpired, request.ReqBody.SName)
		}
	} else if options&types.KDCValidate != 0 {
		if ticketPart.Flags&types.TicketInvalid == 0 {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		if ticketPart.StartTime != nil && ticketPart.StartTime.Present && s.now().Before(ticketPart.StartTime.Time) {
			return s.tgsErrorResponse(armor, krbAPErrTktNYV, request.ReqBody.SName)
		}
		if code, ok := s.ticketValidityWithInvalid(ticketPart); !ok {
			return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
		}
	} else if code, ok := s.ticketValidity(ticketPart); !ok {
		return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
	}
	ticketClient := principalFromProtocol(ticketPart.CName, ticketPart.CRealm)
	if response := s.authorizationError(ticketClient, requestedServiceName, false, armor); response != nil {
		return response
	}
	if apRequest.Ticket.Realm != s.Realm {
		if (ticketPart.Transited.TrType == 0 && len(ticketPart.Transited.Contents) != 0) ||
			(ticketPart.Transited.TrType != 0 && ticketPart.Transited.TrType != domainX500Compress) {
			return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
		}
		contents, err := appendTransited(ticketPart.Transited.Contents, apRequest.Ticket.Realm)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		ticketPart.Transited = protocol.TransitedEncoding{
			TrType: domainX500Compress, Contents: contents,
		}
	}
	if s.replayed(ticketPart.CRealm, ticketPart.CName, authenticator) {
		return s.tgsErrorResponse(armor, krbAPErrRepeat, request.ReqBody.SName)
	}
	if options&types.KDCPostdated != 0 && options&types.KDCAllowPostdate == 0 {
		return s.tgsErrorResponse(armor, kdcErrCannotPostdate, request.ReqBody.SName)
	}
	if options&(types.KDCAllowPostdate|types.KDCPostdated) != 0 &&
		ticketPart.Flags&types.TicketMayPostdate == 0 {
		return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
	}
	serviceName := requestedServiceName
	if options&(types.KDCRenew|types.KDCValidate) != 0 {
		serviceName = principalFromProtocol(apRequest.Ticket.SName, apRequest.Ticket.Realm)
	} else if serviceName.Realm != s.Realm {
		serviceName = principal.Principal{
			Realm: s.Realm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", request.ReqBody.Realm},
		}
	}
	serviceRecord, ok, err := s.DB.Lookup(serviceName)
	if err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	if !ok && options&(types.KDCRenew|types.KDCValidate) == 0 {
		var canonicalName principal.Principal
		serviceRecord, ok, canonicalName, err = s.lookupAlias(serviceName)
		if err != nil {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		}
		if ok && options&types.KDCCanonicalize != 0 {
			serviceName = canonicalName
		}
	}
	if !ok {
		return s.tgsErrorResponse(armor, kdcErrSPrincipal, request.ReqBody.SName)
	}
	requester := principalFromProtocol(ticketPart.CName, ticketPart.CRealm)
	var s4uUser *protocol.S4UUserID
	var s4uReplyPA *protocol.PAData
	if pa130 := findPA(request.PAData, protocol.PADataS4UX509User); pa130 != nil {
		var value protocol.PAS4UX509User
		if err := asn1.Unmarshal(pa130.PADataValue, &value); err != nil ||
			value.UserID.CName == nil || value.UserID.CRealm == "" ||
			len(value.UserID.CName.NameString) == 0 ||
			value.UserID.Nonce != request.ReqBody.Nonce {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		userIDDER, err := asn1.FieldContent(pa130.PADataValue, 0)
		if err != nil {
			userIDDER = marshalDER(value.UserID)
		}
		s4uKey := ticketPart.Key
		if authenticator.SubKey != nil {
			s4uKey = *authenticator.SubKey
		}
		if !verifyS4UChecksum(s4uKey.KeyValue, value.Checksum.ChecksumType, 26, userIDDER, value.Checksum.Checksum) {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		id := value.UserID
		s4uUser = &id
		checksum, err := makeS4UChecksum(s4uKey.KeyValue, value.Checksum.ChecksumType, 27, userIDDER)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		replyValue := protocol.PAS4UX509User{
			UserID: id,
			Checksum: protocol.Checksum{
				ChecksumType: value.Checksum.ChecksumType,
				Checksum:     checksum,
			},
		}
		s4uReplyPA = &protocol.PAData{
			PADataType:  protocol.PADataS4UX509User,
			PADataValue: marshalDER(replyValue),
		}
	} else if pa129 := findPA(request.PAData, protocol.PADataForUser); pa129 != nil {
		var value protocol.PAForUser
		if err := asn1.Unmarshal(pa129.PADataValue, &value); err != nil ||
			value.UserRealm == "" || len(value.UserName.NameString) == 0 ||
			value.AuthPackage != "Kerberos" {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		checksumInput := make([]byte, 4, 4+len(value.UserRealm)+len(value.AuthPackage))
		binary.LittleEndian.PutUint32(checksumInput, uint32(value.UserName.NameType))
		for _, component := range value.UserName.NameString {
			checksumInput = append(checksumInput, component...)
		}
		checksumInput = append(checksumInput, value.UserRealm...)
		checksumInput = append(checksumInput, value.AuthPackage...)
		etype, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
		if err != nil || !verifyPAForUserChecksumForEType(etype, ticketPart.Key.KeyValue,
			value.Checksum.ChecksumType, checksumInput, value.Checksum.Checksum) {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		id := protocol.S4UUserID{
			CName: &value.UserName, CRealm: value.UserRealm,
		}
		s4uUser = &id
	}
	var issuedClient *principal.Principal
	var delegationEvidence *principal.Principal
	var pacVerifyKey *kdb.Key
	var u2uTicketKey *kdb.Key
	verifiedCAMMACElements := verifiedHeaderCAMMACElements
	if s4uUser != nil {
		if serviceName.String() != requester.String() || options&types.KDCCNameInAddlTkt != 0 {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		user := principalFromProtocol(*s4uUser.CName, s4uUser.CRealm)
		if user.Realm != s.Realm {
			return s.tgsErrorResponse(armor, kdcErrCPrincipal, request.ReqBody.SName)
		}
		record, exists, err := s.DB.Lookup(user)
		if err != nil {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		}
		if !exists || len(record.Name.Components) == 0 {
			return s.tgsErrorResponse(armor, kdcErrCPrincipal, request.ReqBody.SName)
		}
		issuedClient = &user
		if s.CheckAllowedToDelegate == nil {
			ticketPart.Flags &^= types.TicketForwardable
		} else if err := s.CheckAllowedToDelegate(nil, requester, nil); err != nil {
			ticketPart.Flags &^= types.TicketForwardable
		}
	}
	if options&types.KDCCNameInAddlTkt != 0 {
		if s.CheckAllowedToDelegate == nil {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		if len(request.ReqBody.AdditionalTickets) != 1 ||
			options&(types.KDCRenew|types.KDCValidate|types.KDCForwarded|types.KDCProxy|types.KDCEncTktInSkey) != 0 {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		if len(serviceName.Components) > 0 && serviceName.Components[0] == "krbtgt" {
			return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
		}
		evidence := request.ReqBody.AdditionalTickets[0]
		requesterRecord, exists, err := s.DB.Lookup(requester)
		if err != nil || !exists {
			return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
		}
		evidenceKey, ok := selectKVNO(requesterRecord, evidence.EncPart.EType, evidence.EncPart.KVNO)
		if !ok {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		evidenceEType, err := crypto.NewRegistry().Get(evidenceKey.Enctype)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		evidencePlain, err := evidenceEType.Decrypt(evidenceKey.Key, 2, evidence.EncPart.Cipher)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		var evidencePart protocol.EncTicketPart
		if err := asn1.Unmarshal(evidencePlain, &evidencePart); err != nil ||
			evidence.Realm != requester.Realm ||
			!sameProtocolPrincipal(evidence.SName, *protocolPrincipal(requester)) ||
			evidencePart.Flags&types.TicketForwardable == 0 {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		if code, valid := s.ticketValidity(evidencePart); !valid {
			return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
		}
		evidenceKDCKey := protocol.EncryptionKey{}
		if key, ok := s.freshnessKey([]int32{evidence.EncPart.EType}); ok {
			evidenceKDCKey = protocol.EncryptionKey{KeyType: key.Enctype, KeyValue: key.Key}
		}
		if verifyErr := cammac.VerifyKDC(evidencePart.AuthorizationData,
			evidencePart, evidenceKDCKey); verifyErr != nil && !stderrors.Is(verifyErr, cammac.ErrNotFound) {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		} else if verifyErr == nil {
			verifiedCAMMACElements, err = cammac.ProtectedElements(evidencePart.AuthorizationData)
			if err != nil {
				return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
			}
		}
		client := principalFromProtocol(evidencePart.CName, evidencePart.CRealm)
		if err := s.CheckAllowedToDelegate(&client, requester, &serviceName); err != nil {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		issuedClient = &client
		evidenceServer := principalFromProtocol(evidence.SName, evidence.Realm)
		delegationEvidence = &evidenceServer
		pacVerifyKey = &evidenceKey
		ticketPart.Flags = evidencePart.Flags
		if len(evidencePart.AuthorizationData) > 0 {
			ticketPart.AuthorizationData = evidencePart.AuthorizationData
		}
	}
	if options&types.KDCEncTktInSkey != 0 {
		second := request.ReqBody.AdditionalTickets[0]
		if second.Realm != s.Realm ||
			second.SName.NameType != int32(principal.NTSrvInstance) ||
			len(second.SName.NameString) != 2 ||
			second.SName.NameString[0] != "krbtgt" ||
			second.SName.NameString[1] != s.Realm {
			return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
		}
		localTGT := principal.Principal{
			Realm: s.Realm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", s.Realm},
		}
		localTGTRecord, exists, err := s.DB.Lookup(localTGT)
		if err != nil || !exists {
			return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
		}
		secondKey, ok := selectKVNO(localTGTRecord, second.EncPart.EType, second.EncPart.KVNO)
		if !ok {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		secondEType, err := crypto.NewRegistry().Get(secondKey.Enctype)
		if err != nil {
			return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
		}
		secondPlain, err := secondEType.Decrypt(secondKey.Key, 2, second.EncPart.Cipher)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		var secondPart protocol.EncTicketPart
		if err := asn1.Unmarshal(secondPlain, &secondPart); err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		if code, valid := s.ticketValidity(secondPart); !valid {
			return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
		}
		secondClient := principalFromProtocol(secondPart.CName, secondPart.CRealm)
		secondRecord, secondFound, err := s.DB.Lookup(secondClient)
		if err != nil {
			return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
		}
		if !secondFound {
			secondRecord, secondFound, _, err = s.lookupAlias(secondClient)
			if err != nil {
				return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
			}
		}
		if !secondFound || !samePrincipalIdentity(secondRecord.Name, serviceRecord.Name) {
			return s.tgsErrorResponse(armor, kdcErrServerNoMatch, request.ReqBody.SName)
		}
		if _, err := crypto.NewRegistry().Get(secondPart.Key.KeyType); err != nil ||
			len(secondPart.Key.KeyValue) == 0 {
			return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
		}
		u2uTicketKey = &kdb.Key{
			Enctype: secondPart.Key.KeyType,
			Key:     append([]byte(nil), secondPart.Key.KeyValue...),
		}
	}
	if options&types.KDCForwarded != 0 {
		if len(serviceName.Components) != 2 || serviceName.Components[0] != "krbtgt" ||
			serviceName.Components[1] != request.ReqBody.Realm ||
			ticketPart.Flags&types.TicketForwardable == 0 {
			return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
		}
		ticketPart.Flags |= types.TicketForwarded
	}
	etypeID, serviceKey, ok := selectServiceKey(request.ReqBody.EType, serviceRecord)
	if options&types.KDCEncTktInSkey != 0 {
		for _, requestedEType := range request.ReqBody.EType {
			if requestedEType == u2uTicketKey.Enctype {
				etypeID = u2uTicketKey.Enctype
				break
			}
		}
		if !ok && s.EnablePAC {
			return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
		}
	} else if !ok {
		return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
	}
	replyKey := ticketPart.Key
	replyUsage := uint32(8)
	if authenticator.SubKey != nil {
		replyKey = *authenticator.SubKey
		replyUsage = 9
	}
	return s.buildTGSRep(request, ticketPart, apRequest.Ticket, ticketKey, serviceName, serviceRecord, etypeID, serviceKey, replyKey, replyUsage, armor, issuedClient, s4uReplyPA, delegationEvidence, verifiedCAMMACElements, pacVerifyKey, u2uTicketKey)
}

func samePrincipalIdentity(left, right principal.Principal) bool {
	if left.Realm != right.Realm || left.NameType != right.NameType ||
		len(left.Components) != len(right.Components) {
		return false
	}
	for i := range left.Components {
		if left.Components[i] != right.Components[i] {
			return false
		}
	}
	return true
}

func verifyPAForUserChecksum(key []byte, usage uint32, data, expected []byte) bool {
	if len(expected) != md5.Size || len(key) == 0 {
		return false
	}
	var usageBytes [4]byte
	binary.LittleEndian.PutUint32(usageBytes[:], usage)
	hashInput := append(append([]byte(nil), usageBytes[:]...), data...)
	digest := md5.Sum(hashInput)
	signingKey := hmac.New(md5.New, key)
	_, _ = signingKey.Write([]byte("signaturekey\x00"))
	mac := hmac.New(md5.New, signingKey.Sum(nil))
	_, _ = mac.Write(digest[:])
	return hmac.Equal(mac.Sum(nil), expected)
}

func verifyPAForUserChecksumForEType(etype crypto.EType, key []byte, checksumType int32, data, expected []byte) bool {
	if checksumType == -138 {
		return verifyPAForUserChecksum(key, 17, data, expected)
	}
	return etype != nil && verifyS4UChecksum(key, checksumType, 17, data, expected)
}

// verifyS4UChecksum verifies one of the keyed checksum types supported by the
// AES session-key enctypes.  PA-FOR-USER additionally accepts the legacy
// RFC 4757 checksum above; callers choose the usage appropriate to the
// padata being processed.
func verifyS4UChecksum(key []byte, checksumType int32, usage uint32, data, expected []byte) bool {
	if checksumType == -138 {
		return usage == 17 && verifyPAForUserChecksum(key, usage, data, expected)
	}
	etypeID := int32(0)
	switch checksumType {
	case crypto.ChecksumHMACSHA196AES128:
		etypeID = crypto.EnctypeAES128SHA1
	case crypto.ChecksumHMACSHA196AES256:
		etypeID = crypto.EnctypeAES256SHA1
	case crypto.ChecksumHMACSHA256128AES128:
		etypeID = crypto.EnctypeAES128SHA256
	case crypto.ChecksumHMACSHA384192AES256:
		etypeID = crypto.EnctypeAES256SHA384
	default:
		return false
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	return err == nil && etype.VerifyChecksum(key, usage, data, expected) == nil
}

func makeS4UChecksum(key []byte, checksumType int32, usage uint32, data []byte) ([]byte, error) {
	if checksumType == -138 {
		return nil, fmt.Errorf("unsupported S4U checksum type %d", checksumType)
	}
	var etypeID int32
	switch checksumType {
	case crypto.ChecksumHMACSHA196AES128:
		etypeID = crypto.EnctypeAES128SHA1
	case crypto.ChecksumHMACSHA196AES256:
		etypeID = crypto.EnctypeAES256SHA1
	case crypto.ChecksumHMACSHA256128AES128:
		etypeID = crypto.EnctypeAES128SHA256
	case crypto.ChecksumHMACSHA384192AES256:
		etypeID = crypto.EnctypeAES256SHA384
	default:
		return nil, fmt.Errorf("unsupported S4U checksum type %d", checksumType)
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return nil, err
	}
	return etype.Checksum(key, usage, data)
}

func (s *Server) unwrapFASTTGSReq(request protocol.TGSReq, checksummedData []byte, ticketPart protocol.EncTicketPart, authenticator protocol.Authenticator) (protocol.TGSReq, *fastContext, int32) {
	pa := findPA(request.PAData, fast.PAFXFast)
	if pa == nil {
		return request, nil, 0
	}
	var wrapper protocol.PAFXFastRequest
	if err := asn1.Unmarshal(pa.PADataValue, &wrapper); err != nil ||
		wrapper.ArmoredData.Armor != nil {
		return request, nil, kdcErrPreauthFailed
	}
	if authenticator.SubKey == nil || authenticator.SubKey.KeyType != ticketPart.Key.KeyType {
		return request, nil, kdcErrPreauthFailed
	}
	sessionEType, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
	if err != nil || len(authenticator.SubKey.KeyValue) != sessionEType.KeySize() {
		return request, nil, kdcErrPreauthFailed
	}
	armorKey, err := crypto.CF2(sessionEType, authenticator.SubKey.KeyValue, ticketPart.Key.KeyValue,
		[]byte("subkeyarmor"), []byte("ticketarmor"))
	if err != nil {
		return request, nil, kdcErrPreauthFailed
	}
	armor := &fastContext{etype: sessionEType, key: armorKey}
	if wrapper.ArmoredData.EncFastReq.EType != sessionEType.ID() ||
		wrapper.ArmoredData.ReqChecksum.ChecksumType != fast.ChecksumType(sessionEType.ID()) ||
		wrapper.ArmoredData.ReqChecksum.Checksum == nil {
		return request, armor, krbAPErrBadIntegrity
	}
	plaintext, err := sessionEType.Decrypt(armorKey, fast.UsageReq, wrapper.ArmoredData.EncFastReq.Cipher)
	if err != nil {
		return request, armor, krbAPErrBadIntegrity
	}
	var fastRequest protocol.KrbFastReq
	if err := asn1.Unmarshal(plaintext, &fastRequest); err != nil {
		return request, armor, krbAPErrBadIntegrity
	}
	if err := sessionEType.VerifyChecksum(armorKey, fast.UsageReqChecksum, checksummedData,
		wrapper.ArmoredData.ReqChecksum.Checksum); err != nil {
		return request, armor, krbAPErrBadIntegrity
	}
	if cookie := findPA(fastRequest.PAData, fast.PAFXCookie); cookie != nil {
		copy := *cookie
		copy.PADataValue = append([]byte(nil), cookie.PADataValue...)
		armor.cookie = &copy
	}
	request.ReqBody = fastRequest.ReqBody
	request.PAData = fastRequest.PAData
	armor.nonce = fastRequest.ReqBody.Nonce
	return request, armor, 0
}

func (s *Server) buildTGSRep(request protocol.TGSReq, ticketPart protocol.EncTicketPart, headerTicket protocol.Ticket, headerKey kdb.Key, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, serviceKey kdb.Key, replyKey protocol.EncryptionKey, replyUsage uint32, armor *fastContext, issuedClient *principal.Principal, replyPA *protocol.PAData, delegationEvidence *principal.Principal, verifiedCAMMACElements protocol.AuthorizationData, pacVerifyKey *kdb.Key, u2uTicketKey *kdb.Key) []byte {
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
	}
	sessionValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, sessionValue); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	now := s.now().UTC().Truncate(time.Second)
	authTime := ticketPart.AuthTime
	if !authTime.Present {
		authTime = types.KerberosTime{Time: now, Present: true}
	}
	flags := ticketPart.Flags
	startTime := ticketPart.StartTime
	endTime := ticketPart.EndTime
	renewTill := ticketPart.RenewTill
	if request.ReqBody.KDCOptions&types.KDCValidate != 0 {
		flags &^= types.TicketInvalid
	} else if request.ReqBody.KDCOptions&types.KDCRenew != 0 {
		start := authTime.Time
		if startTime != nil && startTime.Present {
			start = startTime.Time
		}
		lifetime := ticketPart.EndTime.Time.Sub(start)
		end := now.Add(lifetime)
		if renewTill != nil && end.After(renewTill.Time) {
			end = renewTill.Time
		}
		startTime = &types.KerberosTime{Time: now, Present: true}
		endTime = types.KerberosTime{Time: end.Truncate(time.Second), Present: true}
	} else {
		start := now
		flags &^= types.TicketRenewable
		if request.ReqBody.KDCOptions&types.KDCPostdated != 0 {
			if request.ReqBody.From == nil || !request.ReqBody.From.Present ||
				!request.ReqBody.From.Time.After(now) ||
				(request.ReqBody.Till.Present && !request.ReqBody.Till.Time.After(request.ReqBody.From.Time)) {
				return s.tgsErrorResponse(armor, kdcErrCannotPostdate, request.ReqBody.SName)
			}
			startTime = request.ReqBody.From
			start = startTime.Time
			flags |= types.TicketPostdated | types.TicketInvalid
		} else {
			startTime = nil
		}
		endTime = s.ticketEndFrom(request.ReqBody.Till, start)
		renewTill = s.renewTill(request.ReqBody.KDCOptions, request.ReqBody.RTime, request.ReqBody.Till, start, endTime.Time)
		if request.ReqBody.KDCOptions&(types.KDCRenewable|types.KDCRenewableOK) != 0 {
			if ticketPart.RenewTill == nil {
				renewTill = nil
			} else if renewTill != nil && renewTill.Time.After(ticketPart.RenewTill.Time) {
				renewTill = ticketPart.RenewTill
			}
		}
		if renewTill != nil {
			flags |= types.TicketRenewable
		}
	}
	if s.Policy != nil && !s.Policy.AllowRenewable {
		renewTill = nil
	}
	s.applyFlagPolicy(&flags)
	addresses := append(protocol.HostAddresses(nil), ticketPart.CAddr...)
	if request.ReqBody.KDCOptions&(types.KDCForwarded|types.KDCProxy) != 0 {
		addresses = append(protocol.HostAddresses(nil), request.ReqBody.Addresses...)
	}
	ticketPart = protocol.EncTicketPart{
		Flags:  flags,
		Key:    protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		CRealm: ticketPart.CRealm, CName: ticketPart.CName,
		Transited: ticketPart.Transited,
		AuthTime:  authTime, StartTime: startTime, EndTime: endTime, RenewTill: renewTill,
		CAddr: addresses, AuthorizationData: ticketPart.AuthorizationData,
	}
	if issuedClient != nil {
		ticketPart.CRealm = issuedClient.Realm
		ticketPart.CName = *protocolPrincipal(*issuedClient)
	}
	crossRealmTGT := len(serviceName.Components) == 2 &&
		serviceName.Components[0] == "krbtgt" && serviceName.Components[1] != s.Realm
	if crossRealmTGT {
		delegationEvidence = nil
	}
	if ticketPart.CRealm != s.Realm || crossRealmTGT {
		ticketPart.Transited.TrType = 1
	}
	if !crossRealmTGT && len(ticketPart.Transited.Contents) > 0 {
		if !transitedPermitted(ticketPart.Transited.Contents, ticketPart.CRealm,
			serviceName.Realm, s.Capaths) {
			return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
		}
		flags |= types.TicketTransited
	}
	ticketPart.Flags = flags
	ticketEncryptionKey := serviceKey
	ticketKVNO := serviceKey.KVNO
	var ticketKVNOPtr = &ticketKVNO
	if u2uTicketKey != nil {
		ticketEncryptionKey = *u2uTicketKey
		ticketKVNO = 0
		// MIT's optional-zero KVNO encoder omits a zero value on U2U tickets.
		ticketKVNOPtr = nil
	}
	if findPA(request.PAData, protocol.PADataForUser) == nil {
		authIndicators, err := authIndicatorsFromElements(verifiedCAMMACElements)
		if err != nil {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		}
		if response := s.requireAuthError(serviceRecord, authIndicators,
			armor, request.ReqBody.SName); response != nil {
			return response
		}
	}
	if err := s.issueCAMMAC(&ticketPart, ticketEncryptionKey, verifiedCAMMACElements, nil); err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	if err := s.issuePACWithOptions(&ticketPart, principalFromProtocol(ticketPart.CName, ticketPart.CRealm),
		serviceName, headerKey, serviceKey, !(len(serviceName.Components) == 2 && serviceName.Components[0] == "krbtgt"),
		issuedClient != nil, nil, delegationEvidence, pacVerifyKey); err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	ticketCipher, err := encryptWithKey(ticketEncryptionKey, 2, marshalDER(ticketPart))
	if err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: serviceName.Realm, SName: *protocolPrincipal(serviceName),
		EncPart: protocol.EncryptedData{EType: ticketEncryptionKey.Enctype, KVNO: ticketKVNOPtr, Cipher: ticketCipher},
	}
	if request.ReqBody.KDCOptions&(types.KDCRenew|types.KDCValidate) != 0 {
		ticket.SName = headerTicket.SName
		ticket.Realm = headerTicket.Realm
	}
	part := protocol.EncTGSRepPart{
		Key:     protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		LastReq: protocol.LastReq{{LRType: 0, LRValue: types.KerberosTime{Time: now, Present: true}}},
		Nonce:   request.ReqBody.Nonce, Flags: flags, AuthTime: authTime, StartTime: startTime,
		EndTime: endTime, SRealm: serviceName.Realm, SName: *protocolPrincipal(serviceName),
		RenewTill: renewTill,
	}
	if request.ReqBody.KDCOptions&(types.KDCRenew|types.KDCValidate) != 0 {
		part.SRealm = headerTicket.Realm
		part.SName = headerTicket.SName
	}
	replyCipher, err := encryptWithKey(kdb.Key{Enctype: replyKey.KeyType, KVNO: 0, Key: replyKey.KeyValue}, replyUsage, marshalDER(part))
	if err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	reply := protocol.TGSRep{
		PVNO: 5, MsgType: 13, CRealm: ticketPart.CRealm, CName: ticketPart.CName,
		Ticket:  ticket,
		EncPart: protocol.EncryptedData{EType: replyKey.KeyType, Cipher: replyCipher},
	}
	if replyPA != nil {
		reply.PAData = protocol.MethodData{*replyPA}
	}
	if armor != nil {
		return s.wrapFASTTGSRep(reply, replyKey, replyUsage, armor)
	}
	return marshalDER(reply)
}

func (s *Server) selectASKeys(enctypes []int32, client, service kdb.PrincipalRecord) (int32, kdb.Key, kdb.Key, bool) {
	for _, enctype := range enctypes {
		clientKey, clientOK := client.Keys[enctype]
		serviceKey, serviceOK := service.Keys[enctype]
		if clientOK && serviceOK {
			clientKey.Enctype = enctype
			serviceKey.Enctype = enctype
			return enctype, clientKey, serviceKey, true
		}
	}
	return 0, kdb.Key{}, kdb.Key{}, false
}

func selectPKINITServiceKey(enctypes []int32, service kdb.PrincipalRecord) (int32, kdb.Key, bool) {
	registry := crypto.NewRegistry()
	for _, enctype := range enctypes {
		if _, err := registry.Get(enctype); err != nil {
			continue
		}
		if key, ok := service.Keys[enctype]; ok {
			key.Enctype = enctype
			return enctype, key, true
		}
	}
	return 0, kdb.Key{}, false
}

const freshnessKeyUsage uint32 = 514

func (s *Server) freshnessKey(enctypes []int32) (kdb.Key, bool) {
	name := principal.Principal{
		Realm: s.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", s.Realm},
	}
	record, ok, err := s.DB.Lookup(name)
	if err != nil || !ok {
		return kdb.Key{}, false
	}
	for _, enctype := range enctypes {
		if key, ok := record.Keys[enctype]; ok {
			if _, err := crypto.NewRegistry().Get(enctype); err != nil {
				continue
			}
			key.Enctype = enctype
			return key, true
		}
	}
	for enctype, key := range record.Keys {
		if _, err := crypto.NewRegistry().Get(enctype); err == nil {
			key.Enctype = enctype
			return key, true
		}
	}
	return kdb.Key{}, false
}

func (s *Server) makeFreshnessToken(enctypes []int32) ([]byte, bool) {
	key, ok := s.freshnessKey(enctypes)
	if !ok {
		return nil, false
	}
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		return nil, false
	}
	now := uint32(s.now().Unix())
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], now)
	checksum, err := etype.Checksum(key.Key, freshnessKeyUsage, timestamp[:])
	if err != nil {
		return nil, false
	}
	token := make([]byte, 8+len(checksum))
	binary.BigEndian.PutUint32(token, now)
	binary.BigEndian.PutUint32(token[4:], key.KVNO)
	copy(token[8:], checksum)
	return token, true
}

func (s *Server) verifyFreshnessToken(token []byte) bool {
	if len(token) <= 8 {
		return false
	}
	timestamp := binary.BigEndian.Uint32(token)
	tokenKVNO := binary.BigEndian.Uint32(token[4:])
	now := uint32(s.now().Unix())
	if now > timestamp && now-timestamp > 10*60 {
		return false
	}
	name := principal.Principal{
		Realm: s.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", s.Realm},
	}
	record, ok, err := s.DB.Lookup(name)
	if err != nil || !ok {
		return false
	}
	for enctype, key := range record.Keys {
		if key.KVNO != tokenKVNO {
			continue
		}
		etype, err := crypto.NewRegistry().Get(enctype)
		if err == nil && etype.VerifyChecksum(key.Key, freshnessKeyUsage,
			token[:4], token[8:]) == nil {
			return true
		}
	}
	return false
}

func (s *Server) pkinitFreshnessError(request protocol.ASReq,
	armor *fastContext, code int32) []byte {
	token, ok := s.makeFreshnessToken(request.ReqBody.EType)
	if !ok {
		if armor != nil {
			return s.fastErrorResponse(code, request.ReqBody.SName, nil,
				request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(code, request.ReqBody.SName)
	}
	data := marshalDER(protocol.MethodData{
		{PADataType: protocol.PADataPKASReq},
		{PADataType: protocol.PADataASFreshness, PADataValue: token},
	})
	if armor != nil {
		return s.fastErrorResponse(code, request.ReqBody.SName, data,
			request.ReqBody.Nonce, armor)
	}
	return s.errorResponseWithData(code, request.ReqBody.SName, data)
}

func selectServiceKey(enctypes []int32, service kdb.PrincipalRecord) (int32, kdb.Key, bool) {
	for _, enctype := range enctypes {
		if key, ok := service.Keys[enctype]; ok {
			key.Enctype = enctype
			return enctype, key, true
		}
	}
	return 0, kdb.Key{}, false
}

func selectKVNO(record kdb.PrincipalRecord, enctype int32, kvno *uint32) (kdb.Key, bool) {
	key, ok := record.Keys[enctype]
	if !ok || (kvno != nil && key.KVNO != *kvno) {
		return kdb.Key{}, false
	}
	key.Enctype = enctype
	return key, true
}

func (s *Server) errorResponse(code int32, service *protocol.PrincipalName) []byte {
	return s.errorResponseWithText(code, service, "")
}

func authIndicatorsFromElements(elements protocol.AuthorizationData) ([]string, error) {
	var indicators []string
	for _, element := range elements {
		if element.ADType != protocol.ADAuthIndicator {
			continue
		}
		var values []types.UTF8String
		if err := asn1.Unmarshal(element.ADData, &values); err != nil {
			return nil, fmt.Errorf("auth indicators: %w", err)
		}
		for _, value := range values {
			indicators = append(indicators, string(value))
		}
	}
	return indicators, nil
}

func configuredIndicator(indicator string) []string {
	if indicator == "" {
		return nil
	}
	return []string{indicator}
}

func (s *Server) requireAuthError(record kdb.PrincipalRecord, indicators []string,
	armor *fastContext, service *protocol.PrincipalName) []byte {
	required := strings.TrimSpace(record.Strings["require_auth"])
	if required == "" {
		return nil
	}
	present := make(map[string]struct{}, len(indicators))
	for _, indicator := range indicators {
		present[indicator] = struct{}{}
	}
	for _, indicator := range strings.Fields(required) {
		if _, ok := present[indicator]; ok {
			return nil
		}
	}
	text := "Required auth indicators not present in ticket: " + required
	if armor != nil {
		return s.fastErrorResponseWithText(kdcErrPolicy, service, nil,
			armor.nonce, armor, text)
	}
	return s.errorResponseWithText(kdcErrPolicy, service, text)
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
		var kerberosError *krberrors.KRBError
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

func (s *Server) passwordPolicy(record kdb.PrincipalRecord) (kdb.PolicyRecord, bool) {
	if record.Policy == "" {
		return kdb.PolicyRecord{}, false
	}
	resolver, ok := s.DB.(kdb.PolicyResolver)
	if !ok {
		return kdb.PolicyRecord{}, false
	}
	policy, err := resolver.GetPolicy(record.Policy)
	if err != nil {
		return kdb.PolicyRecord{}, false
	}
	return policy, true
}

func (s *Server) persistLockout(name principal.Principal, record kdb.PrincipalRecord) {
	updater, ok := s.DB.(kdb.LockoutUpdater)
	if !ok {
		return
	}
	_ = updater.UpdateLockout(name, record.FailAuthCount, record.LastFailed, record.LastSuccess)
}

func (s *Server) lockedOut(name principal.Principal, record *kdb.PrincipalRecord) bool {
	policy, ok := s.passwordPolicy(*record)
	if !ok {
		return false
	}
	now := s.now()
	if policy.FailureCountInterval > 0 && !record.LastFailed.IsZero() &&
		!now.Before(record.LastFailed.Add(time.Duration(policy.FailureCountInterval)*time.Second)) {
		record.FailAuthCount = 0
		if recorder, ok := s.DB.(kdb.LockoutRecorder); ok {
			_ = recorder.ResetAuthFailures(name, record.LastFailed)
		} else {
			s.persistLockout(name, *record)
		}
	}
	if policy.MaxFailure == 0 || record.FailAuthCount < policy.MaxFailure {
		return false
	}
	if policy.LockoutDuration == 0 {
		return true
	}
	return now.Before(record.LastFailed.Add(time.Duration(policy.LockoutDuration) * time.Second))
}

func (s *Server) recordPreauthFailure(name principal.Principal, record *kdb.PrincipalRecord) {
	policy, ok := s.passwordPolicy(*record)
	now := s.now()
	interval := time.Duration(0)
	if ok && policy.FailureCountInterval > 0 {
		interval = time.Duration(policy.FailureCountInterval) * time.Second
	}
	if recorder, recorderOK := s.DB.(kdb.LockoutRecorder); recorderOK {
		count, err := recorder.RecordAuthFailure(name, now, interval)
		if err == nil {
			record.FailAuthCount = count
			record.LastFailed = now
			return
		}
	}
	if interval > 0 && !record.LastFailed.IsZero() &&
		!now.Before(record.LastFailed.Add(interval)) {
		record.FailAuthCount = 0
	}
	record.FailAuthCount++
	record.LastFailed = now
	s.persistLockout(name, *record)
}

func (s *Server) recordPreauthSuccess(name principal.Principal, record *kdb.PrincipalRecord) {
	now := s.now()
	if recorder, ok := s.DB.(kdb.LockoutRecorder); ok {
		if err := recorder.RecordAuthSuccess(name, now); err == nil {
			record.FailAuthCount = 0
			record.LastSuccess = now
			return
		}
	}
	record.FailAuthCount = 0
	record.LastSuccess = now
	s.persistLockout(name, *record)
}

func (s *Server) passwordExpired(record kdb.PrincipalRecord) bool {
	return !record.PasswordExpiration.IsZero() && !s.now().Before(record.PasswordExpiration)
}

// ticketValidity reports whether a presented ticket is usable now, returning
// the KRB_ERROR code to send when it is not.
func (s *Server) ticketValidity(ticket protocol.EncTicketPart) (int32, bool) {
	return s.ticketValidityWithInvalidMode(ticket, false)
}

func (s *Server) ticketValidityWithInvalid(ticket protocol.EncTicketPart) (int32, bool) {
	return s.ticketValidityWithInvalidMode(ticket, true)
}

func (s *Server) ticketValidityWithInvalidMode(ticket protocol.EncTicketPart, allowInvalid bool) (int32, bool) {
	now := s.now()
	if !allowInvalid && ticket.Flags&types.TicketInvalid != 0 {
		return krbAPErrTktNYV, false
	}
	if ticket.StartTime != nil && ticket.StartTime.Present && now.Add(s.skew()).Before(ticket.StartTime.Time) {
		return krbAPErrTktNYV, false
	}
	if ticket.EndTime.Present && now.Add(-s.skew()).After(ticket.EndTime.Time) {
		return krbAPErrTktExpired, false
	}
	return 0, true
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

func (s *Server) ticketEndFrom(till types.KerberosTime, start time.Time) types.KerberosTime {
	maxLife := s.MaxTicketLife
	if maxLife <= 0 {
		maxLife = 10 * time.Hour
	}
	end := start.Add(maxLife)
	if !ticketTillSet(till) {
		if s.DefaultTicketLife > 0 && s.DefaultTicketLife < maxLife {
			end = start.Add(s.DefaultTicketLife)
		}
	} else if till.Time.Before(end) {
		end = till.Time
	}
	if end.Before(start) {
		end = start
	}
	return types.KerberosTime{Time: end.Truncate(time.Second), Present: true}
}

func (s *Server) renewTill(options types.KDCOptions, requested *types.KerberosTime, till types.KerberosTime, start, end time.Time) *types.KerberosTime {
	renewable := options&types.KDCRenewable != 0
	hasTill := ticketTillSet(till)
	hasRequested := requested != nil && ticketTillSet(*requested)
	if !renewable && (options&types.KDCRenewableOK == 0 || (hasTill && !till.Time.After(end))) {
		return nil
	}
	target := start.Add(s.MaxRenewableLife)
	if renewable {
		switch {
		case hasRequested:
			target = requested.Time
		case s.DefaultRenewableLife > 0:
			target = start.Add(s.DefaultRenewableLife)
		case hasTill:
			target = till.Time
		}
	} else if hasTill {
		target = till.Time
	} else if s.DefaultRenewableLife > 0 {
		target = start.Add(s.DefaultRenewableLife)
	}
	if !target.After(end) && !renewable {
		return nil
	}
	if s.MaxRenewableLife <= 0 {
		return nil
	}
	capTime := start.Add(s.MaxRenewableLife)
	if target.After(capTime) {
		target = capTime
	}
	if !target.After(end) && !renewable {
		return nil
	}
	if !target.After(start) {
		return nil
	}
	result := types.KerberosTime{Time: target.Truncate(time.Second), Present: true}
	return &result
}

func ticketTillSet(till types.KerberosTime) bool {
	return till.Present && !till.Time.Equal(time.Unix(0, 0).UTC())
}

func (s *Server) applyFlagPolicy(flags *types.TicketFlags) {
	if s.Policy == nil {
		return
	}
	if !s.Policy.AllowForwardable {
		*flags &^= types.TicketForwardable
	}
	if !s.Policy.AllowProxiable {
		*flags &^= types.TicketProxiable
	}
	if !s.Policy.AllowRenewable {
		*flags &^= types.TicketRenewable
	}
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
		if _, err := io.ReadFull(crypto.RandomSource, s.spakeCookieKey); err != nil {
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

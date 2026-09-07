package client

import (
	"context"
	stdcrypto "crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/trace"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

var errUnexpectedReferral = errors.New("unexpected referral TGT")

// Client performs Kerberos client exchanges.
type Client struct {
	Config *config.Config
	Dialer transport.Dialer
	// KKDCP optionally configures HTTPS KDC Proxy requests. When nil, an
	// internal client uses HTTPAnchors and Dialer for HTTPS endpoints.
	KKDCP *kkdcp.Client
	// HTTPAnchors supplies CA roots for HTTPS KDC Proxy endpoints.
	HTTPAnchors *x509.CertPool
	Now         func() time.Time
	Exchange    func(ctx context.Context, realm string, payload []byte) ([]byte, error)
	// SPAKEGroups controls the PA-SPAKE groups offered by ASExchange. When
	// empty, only MIT's default edwards25519 group is offered.
	SPAKEGroups []int32
	// Canonicalize requests KDC canonicalization and permits the KDC to
	// return a canonical client principal in an AS-REP.
	Canonicalize bool
	// PreauthModules contains compile-time registered client preauthentication
	// modules. Built-in mechanisms retain precedence for their PA types.
	PreauthModules []preauth.ClientPreauthModule
	// Trace receives MIT-style diagnostic messages. When nil, KRB5_TRACE is
	// consulted lazily.
	// Set Trace before first use; it must not be replaced while exchanges are in flight.
	Trace     trace.Callback
	traceOnce *sync.Once
	envTrace  trace.Callback
}

// Credentials contains the initial credentials returned by an AS exchange.
type Credentials struct {
	Client principal.Principal
	Server principal.Principal
	Key    protocol.EncryptionKey
	Flags  types.TicketFlags
	// IsSKey reports that the ticket is encrypted in the second ticket's
	// session key, as used by user-to-user authentication.
	IsSKey       bool
	SecondTicket []byte
	AuthTime     types.KerberosTime
	StartTime    *types.KerberosTime
	EndTime      types.KerberosTime
	RenewTill    *types.KerberosTime
	Ticket       []byte
}

// OTPProvider supplies the token value and optional PIN for an OTP challenge.
// The challenge contains the token metadata selected by the KDC.
type OTPProvider func(otp.Challenge) (value string, pin string, err error)

// ToCCacheCredential converts credentials to a FILE ccache credential.
func (c Credentials) ToCCacheCredential() ccache.Credential {
	return ccache.Credential{
		Client:       c.Client,
		Server:       c.Server,
		Enctype:      c.Key.KeyType,
		Key:          append([]byte(nil), c.Key.KeyValue...),
		TicketFlags:  uint32(c.Flags),
		IsSKey:       c.IsSKey,
		AuthTime:     unixTime(c.AuthTime),
		StartTime:    unixOptional(c.StartTime),
		EndTime:      unixTime(c.EndTime),
		RenewTill:    unixOptional(c.RenewTill),
		Ticket:       append([]byte(nil), c.Ticket...),
		SecondTicket: append([]byte(nil), c.SecondTicket...),
	}
}

func (c *Client) exchangePayload(ctx context.Context, realm string, request any, label string) ([]byte, error) {
	payload, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return c.exchangeRawPayload(ctx, realm, payload, label)
}

// ExchangeRaw forwards an already encoded Kerberos request to the configured
// KDC. It is used by protocol adapters such as IAKERB which carry KDC
// messages inside another exchange.
func (c *Client) ExchangeRaw(ctx context.Context, realm string, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("KDC exchange: empty request")
	}
	return c.exchangeRawPayload(ctx, realm, payload, "KDC exchange request")
}

func (c *Client) exchangeRawPayload(ctx context.Context, realm string, payload []byte, label string) ([]byte, error) {
	c.tracef("Sending request (%d bytes) to %s", len(payload), realm)
	if c.Exchange != nil {
		response, err := c.Exchange(ctx, realm, payload)
		if err != nil {
			c.tracef("KDC exchange error: %v", err)
			return nil, fmt.Errorf("%s transport: %w", label, err)
		}
		c.tracef("Received answer (%d bytes) from %s", len(response), realm)
		return response, nil
	}
	if c.Config == nil {
		return nil, fmt.Errorf("%s: no configuration or exchange function", label)
	}
	c.tracef("Resolving hostname %s", realm)
	endpoint, ok := configuredKDC(c.Config, realm)
	if !ok {
		return nil, fmt.Errorf("%s: no KDC configured for realm %q", label, realm)
	}
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		c.tracef("Sending HTTPS request to %s", endpoint)
		response, err := c.kkdcpClient().Exchange(ctx, endpoint, realm, payload)
		if err != nil {
			c.tracef("KDC exchange error: %v", err)
			return nil, err
		}
		c.tracef("Received answer (%d bytes) from %s", len(response), endpoint)
		return response, nil
	}
	address, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("TGS exchange KDC address: %w", err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("TGS exchange UDP socket: %w", err)
	}
	defer conn.Close()
	exchange := transport.Exchange{
		Dialer: c.Dialer, Timeout: c.requestTimeout(realm), UDPPreferenceLimit: 1,
	}
	if c.Config.UDPPreferenceLimit > 0 {
		exchange.UDPPreferenceLimit = c.Config.UDPPreferenceLimit
	}
	response, err := exchange.Request(ctx, conn, address, payload)
	if err != nil {
		c.tracef("KDC exchange error: %v", err)
		return nil, err
	}
	c.tracef("Received answer (%d bytes) from %s", len(response), trace.RemoteAddress("udp", address))
	return response, nil
}

func (c *Client) tracef(format string, args ...any) {
	if c == nil {
		return
	}
	callback := c.Trace
	if callback == nil {
		clientTraceMu.Lock()
		if c.traceOnce == nil {
			c.traceOnce = &sync.Once{}
		}
		once := c.traceOnce
		clientTraceMu.Unlock()
		once.Do(func() {
			c.envTrace, _ = trace.FromEnv()
		})
		callback = c.envTrace
	}
	if callback != nil {
		callback(fmt.Sprintf(format, args...))
	}
}

var clientTraceMu sync.Mutex

func (c *Client) ticketLifetime() time.Duration {
	if c.Config != nil && c.Config.TicketLifetime > 0 {
		return c.Config.TicketLifetime
	}
	return 10 * time.Hour
}

func (c *Client) canonicalizeEnabled() bool {
	return c.Canonicalize || (c.Config != nil && c.Config.Canonicalize)
}

var defaultRequestEnctypes = []int32{
	crypto.EnctypeAES256SHA1,
	crypto.EnctypeAES128SHA1,
	crypto.EnctypeAES256SHA384,
	crypto.EnctypeAES128SHA256,
	crypto.EnctypeCamellia128,
	crypto.EnctypeCamellia256,
}

func (c *Client) asRequestEnctypes() []int32 {
	var candidates []int32
	if c.Config != nil && len(c.Config.DefaultTKTEnctypes) > 0 {
		candidates = c.Config.DefaultTKTEnctypes
	} else if c.Config != nil && len(c.Config.PermittedEnctypes) > 0 {
		candidates = c.Config.PermittedEnctypes
	} else {
		candidates = defaultRequestEnctypes
	}
	return c.supportedRequestEnctypes(candidates)
}

// RequestEnctypes returns the client's ordered AS request enctype list.
func (c *Client) RequestEnctypes() []int32 {
	return append([]int32(nil), c.asRequestEnctypes()...)
}

func (c *Client) tgsRequestEnctypes() []int32 {
	var candidates []int32
	if c.Config != nil && len(c.Config.DefaultTGSEnctypes) > 0 {
		candidates = c.Config.DefaultTGSEnctypes
	} else if c.Config != nil && len(c.Config.PermittedEnctypes) > 0 {
		candidates = c.Config.PermittedEnctypes
	} else {
		candidates = defaultRequestEnctypes
	}
	return c.supportedRequestEnctypes(candidates)
}

func (c *Client) supportedRequestEnctypes(candidates []int32) []int32 {
	registry := crypto.NewRegistry()
	result := make([]int32, 0, len(candidates))
	for _, candidate := range candidates {
		if _, err := registry.Get(candidate); err == nil {
			result = append(result, candidate)
		}
	}
	return result
}

func checksumType(etype int32) int32 {
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

func sameProtocolPrincipal(value protocol.PrincipalName, expected principal.Principal) bool {
	return value.NameType == int32(expected.NameType) && slicesEqual(value.NameString, expected.Components)
}

func serviceWithRealm(value principal.Principal, realm string) principal.Principal {
	if value.Realm != "" {
		return value
	}
	value.Realm = realm
	return value
}

func isKRBError(err error) bool {
	var kerberosError *krberr.KRBError
	return errors.As(err, &kerberosError)
}

func randomNonce(value []byte) uint32 {
	return binary.BigEndian.Uint32(value) & 0x7fffffff
}

func (c *Client) defaultKDCOptions(realm string) types.KDCOptions {
	if c == nil || c.Config == nil {
		return 0
	}
	values := c.Config.LibDefaultValues(realm, "kdc_default_options")
	if len(values) == 0 {
		return types.KDCOptions(c.Config.KDCDefaultOptions)
	}
	var options uint64
	for _, value := range values {
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
		if err == nil {
			options |= parsed
		}
	}
	return types.KDCOptions(options)
}

func (c *Client) requestAddresses(realm string) protocol.HostAddresses {
	if c == nil || c.Config == nil || c.Config.NoAddressesEnabled(realm) {
		return nil
	}
	values := c.Config.LibDefaultValues(realm, "extra_addresses")
	if len(values) == 0 {
		values = append([]string(nil), c.Config.ExtraAddresses...)
	}
	addresses := make(protocol.HostAddresses, 0)
	add := func(ip net.IP) {
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			for _, existing := range addresses {
				if existing.AddrType == 2 && string(existing.Address) == string(ip) {
					return
				}
			}
			addresses = append(addresses, protocol.HostAddress{AddrType: 2, Address: append([]byte(nil), ip...)})
			return
		}
		for _, existing := range addresses {
			if existing.AddrType == 24 && string(existing.Address) == string(ip) {
				return
			}
		}
		addresses = append(addresses, protocol.HostAddress{AddrType: 24, Address: append([]byte(nil), ip...)})
	}
	for _, value := range values {
		for _, field := range strings.Fields(value) {
			add(net.ParseIP(field))
		}
	}
	if interfaces, err := net.InterfaceAddrs(); err == nil {
		for _, address := range interfaces {
			switch value := address.(type) {
			case *net.IPNet:
				add(value.IP)
			case *net.IPAddr:
				add(value.IP)
			}
		}
	}
	return addresses
}

func (c *Client) requestTimeout(realm string) time.Duration {
	if c == nil || c.Config == nil {
		return 5 * time.Second
	}
	values := c.Config.LibDefaultValues(realm, "request_timeout")
	if len(values) == 0 {
		if c.Config.RequestTimeout > 0 {
			return c.Config.RequestTimeout
		}
		return 5 * time.Second
	}
	timeout, err := config.ParseDuration(values[len(values)-1])
	if err != nil || timeout <= 0 {
		return 5 * time.Second
	}
	return timeout
}

func (c *Client) sortPreferredPadata(realm string, data protocol.MethodData) protocol.MethodData {
	preferred := []int32{17, 16, 15, 14}
	if c != nil && c.Config != nil {
		values := c.Config.LibDefaultValues(realm, "preferred_preauth_types")
		if len(values) == 0 {
			preferred = append([]int32(nil), c.Config.PreferredPreauthTypes...)
		} else {
			preferred = parsePreferredPadata(values)
		}
		if len(preferred) == 0 {
			preferred = []int32{17, 16, 15, 14}
		}
	}
	result := append(protocol.MethodData(nil), data...)
	base := 0
	for _, padataType := range preferred {
		match := -1
		for i := base; i < len(result); i++ {
			if result[i].PADataType == padataType {
				match = i
				break
			}
		}
		if match < 0 {
			continue
		}
		value := result[match]
		copy(result[base+1:match+1], result[base:match])
		result[base] = value
		base++
	}
	return result
}

func parsePreferredPadata(values []string) []int32 {
	result := make([]int32, 0, len(values))
	for _, value := range values {
		for _, field := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			parsed, err := strconv.ParseInt(field, 0, 32)
			if err == nil {
				result = append(result, int32(parsed))
			}
		}
	}
	return result
}

func (c *Client) roundTrip(ctx context.Context, realm string, request protocol.ASReq) ([]byte, error) {
	payload, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("AS exchange request: %w", err)
	}
	c.tracef("Sending request (%d bytes) to %s", len(payload), realm)
	if c.Exchange != nil {
		response, err := c.Exchange(ctx, realm, payload)
		if err != nil {
			c.tracef("KDC exchange error: %v", err)
			return nil, fmt.Errorf("AS exchange transport: %w", err)
		}
		c.tracef("Received answer (%d bytes) from %s", len(response), realm)
		return response, nil
	}
	if c.Config == nil {
		return nil, fmt.Errorf("AS exchange: no configuration or exchange function")
	}
	c.tracef("Resolving hostname %s", realm)
	endpoint, ok := configuredKDC(c.Config, realm)
	if !ok {
		return nil, fmt.Errorf("AS exchange: no KDC configured for realm %q", realm)
	}
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		c.tracef("Sending HTTPS request to %s", endpoint)
		response, err := c.kkdcpClient().Exchange(ctx, endpoint, realm, payload)
		if err != nil {
			c.tracef("KDC exchange error: %v", err)
			return nil, err
		}
		c.tracef("Received answer (%d bytes) from %s", len(response), endpoint)
		return response, nil
	}
	address, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("AS exchange KDC address: %w", err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("AS exchange UDP socket: %w", err)
	}
	defer conn.Close()
	exchange := transport.Exchange{
		Dialer:             c.Dialer,
		Timeout:            c.requestTimeout(realm),
		UDPPreferenceLimit: 1,
	}
	if c.Config.UDPPreferenceLimit > 0 {
		exchange.UDPPreferenceLimit = c.Config.UDPPreferenceLimit
	}
	response, err := exchange.Request(ctx, conn, address, payload)
	if err != nil {
		c.tracef("KDC exchange error: %v", err)
		return nil, err
	}
	c.tracef("Received answer (%d bytes) from %s", len(response), trace.RemoteAddress("udp", address))
	return response, nil
}

func decodeKRBError(data []byte) (*krberr.KRBError, bool) {
	var value protocol.KRBError
	if err := asn1.Unmarshal(data, &value); err != nil {
		return nil, false
	}
	server := principalFromProtocol(value.SName).String()
	return krberr.NewKRBError(
		krberr.ErrorCode(value.ErrorCode), server, value.Realm,
		value.STime.Time, value.Susec, value.EData,
	), true
}

func protocolPrincipal(value principal.Principal) *protocol.PrincipalName {
	return &protocol.PrincipalName{NameType: int32(value.NameType), NameString: append([]string(nil), value.Components...)}
}

func principalFromProtocol(value protocol.PrincipalName) principal.Principal {
	return principal.Principal{NameType: principal.NameType(value.NameType), Components: append([]string(nil), value.NameString...)}
}

func samePrincipal(value protocol.PrincipalName, expected principal.Principal) bool {
	return value.NameType == int32(expected.NameType) &&
		len(value.NameString) == len(expected.Components) &&
		slicesEqual(value.NameString, expected.Components)
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (c *Client) clockSkew() time.Duration {
	if c.Config != nil && c.Config.ClockSkew > 0 {
		return c.Config.ClockSkew
	}
	return 5 * time.Minute
}

func validTimes(auth types.KerberosTime, start *types.KerberosTime, end types.KerberosTime, now time.Time, skew time.Duration) bool {
	if !auth.Present || !end.Present {
		return false
	}
	startTime := auth.Time
	if start != nil && start.Present {
		startTime = start.Time
	}
	if startTime.After(now.Add(skew)) {
		return false
	}
	return !end.Time.Before(now.Add(-skew))
}

func configuredKDC(cfg *config.Config, realm string) (string, bool) {
	if values, ok := cfg.Realms[realm]; ok && len(values) > 0 {
		return values[0], true
	}
	for configuredRealm, values := range cfg.Realms {
		if strings.EqualFold(configuredRealm, realm) && len(values) > 0 {
			return values[0], true
		}
	}
	return "", false
}

func (c *Client) kkdcpClient() *kkdcp.Client {
	if c.KKDCP != nil {
		return c.KKDCP
	}
	return &kkdcp.Client{RootCAs: c.HTTPAnchors, Dialer: c.Dialer}
}

func unixTime(value types.KerberosTime) uint32 {
	if !value.Present || value.Time.Unix() < 0 {
		return 0
	}
	return uint32(value.Time.Unix())
}

func unixOptional(value *types.KerberosTime) uint32 {
	if value == nil {
		return 0
	}
	return unixTime(*value)
}

// ASExchangePKINIT obtains initial credentials with the RFC 4556 Diffie-Hellman
// certificate preauthentication exchange. The password ASExchange path is
// unchanged; cert must contain the client's signing certificate and key must
// correspond to cert.
func (c *Client) ASExchangePKINIT(ctx context.Context, clientPrincipal principal.Principal, cert *x509.Certificate, key stdcrypto.Signer, anchors *x509.CertPool) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("PKINIT AS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("PKINIT AS exchange: nil context")
	}
	if clientPrincipal.Realm == "" || len(clientPrincipal.Components) == 0 {
		return nil, fmt.Errorf("PKINIT AS exchange: invalid client principal")
	}
	var pkMinBits string
	if c.Config != nil {
		pkMinBits = c.Config.PKINITDHMinBits
	}
	pk, err := pkinit.NewClientWithDHMinBits(cert, key, pkMinBits)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, err := c.newASReq(clientPrincipal, now)
	if err != nil {
		return nil, err
	}
	// Advertise RFC 8070 freshness support so a KDC can include an opaque
	// token in PREAUTH_REQUIRED method data.
	request.PAData = protocol.MethodData{{PADataType: pkinit.PADataASFreshness}}
	response, err := c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	var requestDER []byte
	if kerberosError, ok := decodeKRBError(response); ok {
		if kerberosError.Code != 25 {
			return nil, kerberosError
		}
		bodyDER, err := asn1.Marshal(request.ReqBody)
		if err != nil {
			return nil, fmt.Errorf("PKINIT AS request body: %w", err)
		}
		serverPrincipal := principal.Principal{
			Realm: clientPrincipal.Realm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", clientPrincipal.Realm},
		}
		freshnessToken := freshnessTokenFromError(kerberosError)
		pa, err := pk.BuildPAASReqForPrincipalsWithFreshness(bodyDER, now,
			request.ReqBody.Nonce, clientPrincipal, serverPrincipal,
			freshnessToken)
		if err != nil {
			return nil, err
		}
		request.PAData = protocol.MethodData{pa}
		requestDER, err = asn1.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("PKINIT AS request: %w", err)
		}
		for retries := 0; ; retries++ {
			response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
			if err != nil {
				return nil, err
			}
			kerberosError, ok := decodeKRBError(response)
			if !ok {
				break
			}
			retry, err := retryPKINITDHParameters(kerberosError, retries, pk)
			if err != nil {
				return nil, err
			}
			if !retry {
				return nil, kerberosError
			}
			pa, err := pk.BuildPAASReqForPrincipalsWithFreshness(bodyDER, now,
				request.ReqBody.Nonce, clientPrincipal, serverPrincipal,
				freshnessToken)
			if err != nil {
				return nil, err
			}
			request.PAData = protocol.MethodData{pa}
			requestDER, err = asn1.Marshal(request)
			if err != nil {
				return nil, fmt.Errorf("PKINIT AS request: %w", err)
			}
		}
	}
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		if kerberosError, ok := decodeKRBError(response); ok {
			return nil, kerberosError
		}
		return nil, fmt.Errorf("PKINIT AS exchange AS-REP: %w", err)
	}
	var pkReply []byte
	for _, pa := range reply.PAData {
		if pa.PADataType == pkinit.PADataASRep {
			pkReply = pa.PADataValue
			break
		}
	}
	if len(pkReply) == 0 {
		return nil, fmt.Errorf("PKINIT AS exchange: AS-REP has no PA-PK-AS-REP")
	}
	replyKey, err := pk.VerifyPAASRepWithContext(pkReply, anchors, reply.EncPart.EType,
		request.ReqBody.Nonce, clientPrincipal, principal.Principal{
			Realm: clientPrincipal.Realm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", clientPrincipal.Realm},
		}, requestDER)
	if err != nil {
		return nil, err
	}
	return c.decodeASRep(response, clientPrincipal, request.ReqBody.Nonce, reply.EncPart.EType, replyKey, now)
}

// AnonymousASExchange obtains an anonymous initial ticket using RFC 8062
// unsigned PKINIT. anchors must trust the KDC's PKINIT certificate.
func (c *Client) AnonymousASExchange(ctx context.Context, realm string, anchors *x509.CertPool) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("anonymous PKINIT AS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("anonymous PKINIT AS exchange: nil context")
	}
	if realm == "" {
		return nil, fmt.Errorf("anonymous PKINIT AS exchange: empty realm")
	}
	anon := principal.Principal{
		Realm: realm, NameType: principal.NTWellKnown,
		Components: []string{"WELLKNOWN", "ANONYMOUS"},
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", realm},
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, err := c.newASReqForService(anon, service, now)
	if err != nil {
		return nil, err
	}
	request.ReqBody.KDCOptions |= types.KDCRequestAnonymous
	request.PAData = protocol.MethodData{{PADataType: pkinit.PADataASFreshness}}
	response, err := c.roundTrip(ctx, realm, request)
	if err != nil {
		return nil, err
	}
	kerberosError, ok := decodeKRBError(response)
	if !ok || kerberosError.Code != 25 {
		if ok {
			return nil, kerberosError
		}
		return nil, fmt.Errorf("anonymous PKINIT AS exchange: expected PREAUTH_REQUIRED")
	}
	bodyDER, err := asn1.Marshal(request.ReqBody)
	if err != nil {
		return nil, fmt.Errorf("anonymous PKINIT AS request body: %w", err)
	}
	serverPrincipal := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", realm},
	}
	pkClient, err := pkinit.NewAnonymousClient()
	if err != nil {
		return nil, err
	}
	pa, err := pkClient.BuildPAASReqForPrincipalsWithFreshness(bodyDER, now,
		request.ReqBody.Nonce, anon, serverPrincipal,
		freshnessTokenFromError(kerberosError))
	if err != nil {
		return nil, err
	}
	request.PAData = protocol.MethodData{pa}
	requestDER, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("anonymous PKINIT AS request: %w", err)
	}
	for retries := 0; ; retries++ {
		response, err = c.roundTrip(ctx, realm, request)
		if err != nil {
			return nil, err
		}
		kerberosError, ok := decodeKRBError(response)
		if !ok {
			break
		}
		retry, err := retryPKINITDHParameters(kerberosError, retries, pkClient)
		if err != nil {
			return nil, err
		}
		if !retry {
			return nil, kerberosError
		}
		pa, err := pkClient.BuildPAASReqForPrincipalsWithFreshness(bodyDER, now,
			request.ReqBody.Nonce, anon, serverPrincipal,
			freshnessTokenFromError(kerberosError))
		if err != nil {
			return nil, err
		}
		request.PAData = protocol.MethodData{pa}
		requestDER, err = asn1.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("anonymous PKINIT AS request: %w", err)
		}
	}
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		if kerberosError, ok := decodeKRBError(response); ok {
			return nil, kerberosError
		}
		return nil, fmt.Errorf("anonymous PKINIT AS exchange AS-REP: %w", err)
	}
	var pkReply []byte
	for _, item := range reply.PAData {
		if item.PADataType == pkinit.PADataASRep {
			pkReply = item.PADataValue
			break
		}
	}
	if len(pkReply) == 0 {
		return nil, fmt.Errorf("anonymous PKINIT AS exchange: AS-REP has no PA-PK-AS-REP")
	}
	replyKey, err := pkClient.VerifyPAASRepWithContext(pkReply, anchors, reply.EncPart.EType,
		request.ReqBody.Nonce, principal.Principal{
			Realm: "WELLKNOWN:ANONYMOUS", NameType: principal.NTWellKnown,
			Components: []string{"WELLKNOWN", "ANONYMOUS"},
		}, serverPrincipal, requestDER)
	if err != nil {
		return nil, err
	}
	if err := verifyAnonymousReplyKX(reply, replyKey); err != nil {
		return nil, err
	}
	credentials, err := c.decodeASRepForService(
		response, anon, service, request.ReqBody.Nonce, reply.EncPart.EType, replyKey, now,
	)
	if err != nil {
		return nil, err
	}
	if err := requireAnonymousTicketFlag(credentials); err != nil {
		return nil, err
	}
	return credentials, nil
}

func requireAnonymousTicketFlag(credentials *Credentials) error {
	if credentials == nil || credentials.Flags&types.TicketAnonymous == 0 {
		return fmt.Errorf(
			"anonymous PKINIT: AS-REP lacks anonymous ticket flag: %w",
			krberr.ErrIntegrity,
		)
	}
	return nil
}

const (
	paPKINITKX         int32 = 147
	keyUsagePAPKINITKX       = 44
)

func verifyAnonymousReplyKX(reply protocol.ASRep, replyKey []byte) error {
	var kxValue []byte
	for _, item := range reply.PAData {
		if item.PADataType == paPKINITKX {
			kxValue = item.PADataValue
			break
		}
	}
	if len(kxValue) == 0 {
		return fmt.Errorf("anonymous PKINIT: missing PA-PKINIT-KX: %w", krberr.ErrIntegrity)
	}
	var encryptedKey protocol.EncryptedData
	if err := asn1.Unmarshal(kxValue, &encryptedKey); err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX: %w", krberr.ErrIntegrity)
	}
	if encryptedKey.EType != reply.EncPart.EType {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX enctype mismatch: %w", krberr.ErrIntegrity)
	}
	etype, err := crypto.NewRegistry().Get(reply.EncPart.EType)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX enctype: %w", krberr.ErrIntegrity)
	}
	plainKey, err := etype.Decrypt(replyKey, keyUsagePAPKINITKX, encryptedKey.Cipher)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX decrypt: %w", krberr.ErrIntegrity)
	}
	var kdcKey protocol.EncryptionKey
	if err := asn1.Unmarshal(plainKey, &kdcKey); err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX key: %w", krberr.ErrIntegrity)
	}
	if kdcKey.KeyType != reply.EncPart.EType {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX key enctype mismatch: %w", krberr.ErrIntegrity)
	}
	plainReply, err := etype.Decrypt(replyKey, 3, reply.EncPart.Cipher)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT AS-REP decrypt: %w", krberr.ErrIntegrity)
	}
	if len(plainReply) > 0 && plainReply[0] == 0x7a {
		plainReply = append([]byte(nil), plainReply...)
		plainReply[0] = 0x79
	}
	var part protocol.EncASRepPart
	if err := asn1.Unmarshal(plainReply, &part); err != nil {
		return fmt.Errorf("anonymous PKINIT AS-REP: %w", krberr.ErrIntegrity)
	}
	expected, err := crypto.CF2(
		etype, kdcKey.KeyValue, replyKey,
		[]byte("PKINIT"), []byte("KEYEXCHANGE"),
	)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX derive: %w", krberr.ErrIntegrity)
	}
	if part.Key.KeyType != reply.EncPart.EType ||
		len(part.Key.KeyValue) != len(expected) ||
		subtle.ConstantTimeCompare(part.Key.KeyValue, expected) != 1 {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX session key mismatch: %w", krberr.ErrIntegrity)
	}
	return nil
}

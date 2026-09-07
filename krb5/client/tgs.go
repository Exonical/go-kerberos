package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/internal/random"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/trace"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// TGSExchange obtains a service ticket using an existing TGT.
func (c *Client) TGSExchange(ctx context.Context, tgt *Credentials, service principal.Principal) (*Credentials, error) {
	candidates, err := c.serviceCandidates(ctx, service)
	if err != nil {
		return nil, err
	}
	if service.Realm == "" {
		for index := range candidates {
			candidates[index].Realm = ""
		}
	}
	var last error
	for index, candidate := range candidates {
		result, err := c.tgsExchangeOnce(ctx, tgt, candidate)
		if err == nil {
			return result, nil
		}
		last = err
		if index == 0 && len(candidates) > 1 && !isUnknownServiceError(err) {
			break
		}
	}
	return nil, last
}

func (c *Client) tgsExchangeOnce(ctx context.Context, tgt *Credentials, service principal.Principal) (*Credentials, error) {
	return c.tgsExchangeOnceWithMode(ctx, tgt, service, service.Realm == "", service.Realm != "")
}

func (c *Client) tgsExchangeOnceWithMode(ctx context.Context, tgt *Credentials,
	service principal.Principal, referral, serviceRealmKnown bool) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("TGS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("TGS exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("TGS exchange: %w", err)
	}
	if tgt == nil {
		return nil, fmt.Errorf("TGS exchange: nil TGT")
	}
	if len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("TGS exchange: incomplete TGT")
	}
	if len(service.Components) == 0 {
		return nil, fmt.Errorf("TGS exchange: invalid service principal")
	}
	requestedService := service
	realm := service.Realm
	if realm == "" {
		realm = tgt.Server.Realm
	}
	if realm == "" {
		realm = tgt.Client.Realm
	}
	if realm == "" {
		return nil, fmt.Errorf("TGS exchange: missing service realm")
	}
	service = serviceWithRealm(service, realm)
	c.tracef("Requesting tickets for %s, referrals on", trace.Principal(service))
	visited := make(map[string]bool)
	currentTGT := tgt
	currentRealm := currentTGT.Server.Realm
	if currentRealm == "" {
		currentRealm = currentTGT.Client.Realm
	}
	if currentRealm == "" {
		return nil, fmt.Errorf("TGS exchange: missing TGT realm")
	}
	if currentRealm != realm {
		now := time.Now().UTC()
		if c.Now != nil {
			now = c.Now().UTC()
		}
		realmPath := []string{currentRealm, realm}
		if c.Config != nil {
			if configuredPath, configured, err := c.Config.RealmPath(currentRealm, realm); err != nil {
				return nil, fmt.Errorf("TGS exchange: %w", err)
			} else if configured {
				realmPath = configuredPath
			}
		}
		if len(realmPath) < 2 || len(realmPath) > 11 {
			return nil, fmt.Errorf("TGS exchange: invalid capath")
		}
		for hop := 1; hop < len(realmPath); hop++ {
			nextRealm := realmPath[hop]
			if nextRealm == "" || strings.EqualFold(nextRealm, currentRealm) {
				return nil, fmt.Errorf("TGS exchange: capath realm loop at %s", nextRealm)
			}
			crossTGTService := principal.Principal{
				Realm: currentRealm, NameType: principal.NTSrvInstance,
				Components: []string{"krbtgt", nextRealm},
			}
			request, nonce, err := c.newTGSReq(currentTGT, crossTGTService, currentRealm, now,
				true)
			if err != nil {
				return nil, err
			}
			response, err := c.exchangePayload(ctx, currentRealm, request, "cross-realm TGS exchange request")
			if err != nil {
				return nil, err
			}
			crossRequestedService := crossTGTService
			crossRequestedService.Realm = nextRealm
			result, referral, err := c.decodeTGSRepForExchange(
				response, currentTGT.Client, crossTGTService, crossRequestedService,
				true, nonce, currentTGT.Key.KeyType, currentTGT.Key.KeyValue, now,
			)
			if err != nil {
				return nil, err
			}
			if referral || len(result.Server.Components) != 2 ||
				result.Server.Components[0] != "krbtgt" ||
				result.Server.Components[1] != nextRealm ||
				!strings.EqualFold(result.Server.Realm, currentRealm) {
				return nil, fmt.Errorf("TGS exchange: malformed cross-realm TGT")
			}
			currentTGT = result
			currentRealm = nextRealm
			now = time.Now().UTC()
			if c.Now != nil {
				now = c.Now().UTC()
			}
		}
		realm = currentRealm
	}
	for hops := 0; ; hops++ {
		if visited[realm] {
			return nil, fmt.Errorf("TGS exchange: referral realm loop at %s", realm)
		}
		if hops > 10 {
			return nil, fmt.Errorf("TGS exchange: referral hop limit exceeded")
		}
		visited[realm] = true
		now := time.Now().UTC()
		if c.Now != nil {
			now = c.Now().UTC()
		}
		request, nonce, err := c.newTGSReq(currentTGT, service, realm, now,
			hops > 0 || referral)
		if err != nil {
			return nil, err
		}
		response, err := c.exchangePayload(ctx, realm, request, "TGS exchange request")
		if err != nil {
			return nil, err
		}
		if kerberosError, ok := decodeKRBError(response); ok {
			if referral && hops == 0 && requestedService.Realm == "" {
				fallback, authoritative, fallbackErr := c.resolveServiceRealm(ctx, requestedService)
				if fallbackErr != nil {
					return nil, fallbackErr
				}
				if fallback != "" {
					fallbackService := requestedService
					fallbackService.Realm = fallback
					return c.tgsExchangeOnceWithMode(ctx, tgt, fallbackService,
						false, authoritative)
				}
			}
			return nil, kerberosError
		}
		result, gotReferral, err := c.decodeTGSRepForExchange(response, currentTGT.Client, service, requestedService, serviceRealmKnown, nonce, currentTGT.Key.KeyType, currentTGT.Key.KeyValue, now)
		if err != nil {
			return nil, err
		}
		if !gotReferral {
			return result, nil
		}
		if hops >= 10 {
			return nil, fmt.Errorf("TGS exchange: referral hop limit exceeded")
		}
		if len(result.Server.Components) != 2 || result.Server.Components[0] != "krbtgt" {
			return nil, fmt.Errorf("TGS exchange: malformed referral ticket")
		}
		nextRealm := result.Server.Components[1]
		if nextRealm == "" {
			return nil, fmt.Errorf("TGS exchange: referral ticket has empty realm")
		}
		currentTGT = result
		realm = nextRealm
	}
}

// TGSExchangeU2U obtains a service ticket encrypted in the session key of the
// supplied second ticket, as specified by RFC 4120 section 3.3.
func (c *Client) TGSExchangeU2U(ctx context.Context, tgt *Credentials, secondTicket []byte, service principal.Principal) (*Credentials, error) {
	candidates, err := c.serviceCandidates(ctx, service)
	if err != nil {
		return nil, err
	}
	if service.Realm == "" {
		for index := range candidates {
			candidates[index].Realm = ""
		}
	}
	var last error
	for index, candidate := range candidates {
		result, err := c.tgsExchangeU2UOnce(ctx, tgt, secondTicket, candidate)
		if err == nil {
			return result, nil
		}
		last = err
		if service.Realm == "" && (isKRBError(err) || errors.Is(err, errUnexpectedReferral)) {
			fallback, authoritative, fallbackErr := c.resolveServiceRealm(ctx, candidate)
			if fallbackErr != nil {
				return nil, errors.Join(last, fallbackErr)
			}
			if fallback != "" {
				fallbackCandidate := candidate
				fallbackCandidate.Realm = fallback
				result, fallbackErr := c.tgsExchangeU2UOnceWithMode(ctx, tgt, secondTicket,
					fallbackCandidate, false, authoritative)
				if fallbackErr == nil {
					return result, nil
				}
				last = errors.Join(last, fallbackErr)
			}
		}
		if index == 0 && len(candidates) > 1 && !isUnknownServiceError(err) {
			break
		}
	}
	return nil, last
}

func (c *Client) tgsExchangeU2UOnce(ctx context.Context, tgt *Credentials, secondTicket []byte, service principal.Principal) (*Credentials, error) {
	return c.tgsExchangeU2UOnceWithMode(ctx, tgt, secondTicket, service,
		service.Realm == "", service.Realm != "")
}

func (c *Client) tgsExchangeU2UOnceWithMode(ctx context.Context, tgt *Credentials,
	secondTicket []byte, service principal.Principal, referral, serviceRealmKnown bool) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("TGS U2U exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("TGS U2U exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("TGS U2U exchange: %w", err)
	}
	if tgt == nil || len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("TGS U2U exchange: incomplete TGT")
	}
	if len(secondTicket) == 0 {
		return nil, fmt.Errorf("TGS U2U exchange: missing second ticket")
	}
	if len(service.Components) == 0 {
		return nil, fmt.Errorf("TGS U2U exchange: invalid service principal")
	}
	realm := service.Realm
	if realm == "" {
		realm = tgt.Server.Realm
	}
	if realm == "" {
		realm = tgt.Client.Realm
	}
	if realm == "" {
		return nil, fmt.Errorf("TGS U2U exchange: missing service realm")
	}
	service = serviceWithRealm(service, realm)
	var second protocol.Ticket
	if err := asn1.Unmarshal(secondTicket, &second); err != nil {
		return nil, fmt.Errorf("TGS U2U exchange second ticket: %w", err)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, nonce, err := c.newTGSReqWithBody(tgt, service, realm, now, referral, func(body *protocol.KDCReqBody) {
		body.KDCOptions |= types.KDCEncTktInSkey
		body.AdditionalTickets = []protocol.Ticket{second}
	})
	if err != nil {
		return nil, err
	}
	if len(request.ReqBody.AdditionalTickets) != 1 {
		return nil, fmt.Errorf("TGS U2U exchange second ticket: invalid ticket")
	}
	response, err := c.exchangePayload(ctx, realm, request, "TGS U2U exchange request")
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		return nil, kerberosError
	}
	result, referralResult, err := c.decodeTGSRepForExchange(response, tgt.Client, service, service,
		serviceRealmKnown, nonce, tgt.Key.KeyType, tgt.Key.KeyValue, now)
	if err != nil {
		return nil, err
	}
	if referralResult {
		return nil, errUnexpectedReferral
	}
	result.IsSKey = true
	result.SecondTicket = append([]byte(nil), secondTicket...)
	return result, nil
}

// TGSExchangeForwarded obtains a forwarded copy of the client's local TGT.
// The request omits host addresses, as required for GSS credential
// delegation, and sets the FORWARDED ticket option.
func (c *Client) TGSExchangeForwarded(ctx context.Context, tgt *Credentials) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("forwarded TGS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("forwarded TGS exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("forwarded TGS exchange: %w", err)
	}
	if tgt == nil || len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("forwarded TGS exchange: incomplete TGT")
	}
	realm := tgt.Client.Realm
	if realm == "" {
		realm = tgt.Server.Realm
	}
	if realm == "" {
		return nil, fmt.Errorf("forwarded TGS exchange: missing realm")
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", realm},
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, nonce, err := c.newTGSReqWithBody(tgt, service, realm, now, false, func(body *protocol.KDCReqBody) {
		body.KDCOptions |= types.KDCForwarded
		body.Addresses = nil
	})
	if err != nil {
		return nil, err
	}
	response, err := c.exchangePayload(ctx, realm, request, "forwarded TGS exchange request")
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		return nil, kerberosError
	}
	result, _, err := c.decodeTGSRepForExchange(response, tgt.Client, service, service,
		true, nonce, tgt.Key.KeyType, tgt.Key.KeyValue, now)
	if err != nil {
		return nil, err
	}
	if result.Flags&types.TicketForwarded == 0 {
		return nil, fmt.Errorf("forwarded TGS exchange: reply ticket is not forwarded")
	}
	return result, nil
}

// TGSExchangeFAST obtains a service ticket using an RFC 6113 implicit TGS
// armor exchange. The TGS authenticator subkey supplies the armor key input.
func (c *Client) TGSExchangeFAST(ctx context.Context, tgt *Credentials, service principal.Principal) (*Credentials, error) {
	candidates, err := c.serviceCandidates(ctx, service)
	if err != nil {
		return nil, err
	}
	if service.Realm == "" {
		for index := range candidates {
			candidates[index].Realm = ""
		}
	}
	var last error
	for index, candidate := range candidates {
		result, err := c.tgsExchangeFASTOnce(ctx, tgt, candidate)
		if err == nil {
			return result, nil
		}
		last = err
		if service.Realm == "" && (isKRBError(err) || errors.Is(err, errUnexpectedReferral)) {
			fallback, authoritative, fallbackErr := c.resolveServiceRealm(ctx, candidate)
			if fallbackErr != nil {
				return nil, errors.Join(last, fallbackErr)
			}
			if fallback != "" {
				fallbackCandidate := candidate
				fallbackCandidate.Realm = fallback
				result, fallbackErr := c.tgsExchangeFASTOnceWithMode(ctx, tgt,
					fallbackCandidate, false, authoritative)
				if fallbackErr == nil {
					return result, nil
				}
				last = errors.Join(last, fallbackErr)
			}
		}
		if index == 0 && len(candidates) > 1 && !isUnknownServiceError(err) {
			break
		}
	}
	return nil, last
}

func (c *Client) tgsExchangeFASTOnce(ctx context.Context, tgt *Credentials, service principal.Principal) (*Credentials, error) {
	return c.tgsExchangeFASTOnceWithMode(ctx, tgt, service,
		service.Realm == "", service.Realm != "")
}

func (c *Client) tgsExchangeFASTOnceWithMode(ctx context.Context, tgt *Credentials,
	service principal.Principal, referral, serviceRealmKnown bool) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("FAST TGS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("FAST TGS exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("FAST TGS exchange: %w", err)
	}
	if tgt == nil || len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("FAST TGS exchange: incomplete TGT")
	}
	if len(service.Components) == 0 {
		return nil, fmt.Errorf("FAST TGS exchange: invalid service principal")
	}
	realm := service.Realm
	if realm == "" {
		realm = tgt.Server.Realm
	}
	if realm == "" {
		return nil, fmt.Errorf("FAST TGS exchange: missing service realm")
	}
	currentRealm := tgt.Server.Realm
	if currentRealm == "" {
		currentRealm = tgt.Client.Realm
	}
	if currentRealm != realm {
		return nil, fmt.Errorf("FAST TGS exchange: cross-realm FAST is not supported")
	}
	service = serviceWithRealm(service, realm)
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, nonce, armor, replyKey, err := c.newTGSReqFAST(tgt, service, realm, now, referral)
	if err != nil {
		return nil, err
	}
	response, err := c.exchangePayload(ctx, realm, request, "FAST TGS exchange request")
	if err != nil {
		return nil, err
	}
	result, referralResult, err := c.decodeFASTTGSRep(response, tgt.Client, service, service,
		serviceRealmKnown, nonce, replyKey, armor, now)
	if err != nil {
		return nil, err
	}
	if referralResult {
		return nil, errUnexpectedReferral
	}
	return result, nil
}

func (c *Client) newTGSReq(tgt *Credentials, service principal.Principal, realm string, now time.Time, referral bool) (protocol.TGSReq, uint32, error) {
	request, nonce, _, _, err := c.newTGSReqWithBodyOptions(tgt, service, realm, now, referral, nil, false)
	return request, nonce, err
}

// newTGSReqWithBody builds a TGS-REQ, letting the caller adjust the request
// body before it is marshalled and covered by the authenticator checksum.
func (c *Client) newTGSReqWithBody(tgt *Credentials, service principal.Principal, realm string, now time.Time, referral bool, adjust func(*protocol.KDCReqBody)) (protocol.TGSReq, uint32, error) {
	request, nonce, _, _, err := c.newTGSReqWithBodyOptions(tgt, service, realm, now, referral, adjust, false)
	return request, nonce, err
}

func (c *Client) newTGSReqFAST(tgt *Credentials, service principal.Principal, realm string, now time.Time, referral bool) (protocol.TGSReq, uint32, *fast.Armor, protocol.EncryptionKey, error) {
	return c.newTGSReqWithBodyOptions(tgt, service, realm, now, referral, nil, true)
}

func (c *Client) newTGSReqWithBodyOptions(tgt *Credentials, service principal.Principal, realm string, now time.Time, referral bool, adjust func(*protocol.KDCReqBody), useFAST bool) (protocol.TGSReq, uint32, *fast.Armor, protocol.EncryptionKey, error) {
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, err
	}
	nonceBytes := make([]byte, 4)
	if _, err := io.ReadFull(random.Reader(), nonceBytes); err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange nonce: %w", err)
	}
	options := types.KDCRenewableOK | c.defaultKDCOptions(realm)
	if c.canonicalizeEnabled() || referral {
		options |= types.KDCCanonicalize
	}
	body := protocol.KDCReqBody{
		KDCOptions: options,
		Realm:      realm,
		SName: &protocol.PrincipalName{
			NameType: int32(service.NameType), NameString: append([]string(nil), service.Components...),
		},
		Till:  types.KerberosTime{Time: now.Add(c.ticketLifetime()), Present: true},
		Nonce: randomNonce(nonceBytes),
		EType: c.tgsRequestEnctypes(),
	}
	if adjust != nil {
		adjust(&body)
	}
	bodyDER, err := asn1.Marshal(body)
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange request body: %w", err)
	}
	checksum, err := etype.Checksum(tgt.Key.KeyValue, 6, bodyDER)
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange request checksum: %w", err)
	}
	usec := int32(now.Nanosecond() / 1000)
	var subkey *protocol.EncryptionKey
	if useFAST {
		subkeyValue := make([]byte, etype.KeySize())
		if _, err := io.ReadFull(random.Reader(), subkeyValue); err != nil {
			return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("FAST TGS subkey: %w", err)
		}
		subkey = &protocol.EncryptionKey{KeyType: tgt.Key.KeyType, KeyValue: subkeyValue}
	}
	authenticatorDER, err := asn1.Marshal(protocol.Authenticator{
		AuthenticatorVNO: 5,
		CRealm:           tgt.Client.Realm,
		CName:            *protocolPrincipal(tgt.Client),
		Checksum: &protocol.Checksum{
			ChecksumType: checksumType(tgt.Key.KeyType),
			Checksum:     checksum,
		},
		Cusec:  usec,
		Ctime:  types.KerberosTime{Time: now, Microseconds: usec, Present: true},
		SubKey: subkey,
	})
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange authenticator: %w", err)
	}
	encryptedAuthenticator, err := etype.Encrypt(tgt.Key.KeyValue, 7, authenticatorDER)
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange authenticator encryption: %w", err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &ticket); err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange ticket: %w", err)
	}
	apReqDER, err := asn1.Marshal(protocol.APReq{
		PVNO: 5, MsgType: 14, Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: tgt.Key.KeyType, Cipher: encryptedAuthenticator},
	})
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange AP-REQ: %w", err)
	}
	request := protocol.TGSReq{
		PVNO: 5, MsgType: 12,
		PAData:  protocol.MethodData{{PADataType: 1, PADataValue: apReqDER}},
		ReqBody: body,
	}
	if !useFAST {
		return request, body.Nonce, nil, protocol.EncryptionKey{}, nil
	}
	armor, err := fast.NewTGSArmor(fast.TGT{Key: tgt.Key}, *subkey)
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, err
	}
	fastData, err := armor.WrapTGSReq(body, nil, apReqDER)
	if err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, err
	}
	request.PAData = append(request.PAData, fastData)
	return request, body.Nonce, armor, *subkey, nil
}

func (c *Client) decodeTGSRep(data []byte, clientPrincipal, service principal.Principal, nonce uint32, keyType int32, key []byte, now time.Time) (*Credentials, error) {
	result, _, err := c.decodeTGSRepForExchange(data, clientPrincipal, service, service, true, nonce, keyType, key, now)
	return result, err
}

func (c *Client) decodeTGSRepForExchange(data []byte, clientPrincipal, service, requestedService principal.Principal, serviceRealmKnown bool, nonce uint32, keyType int32, key []byte, now time.Time) (*Credentials, bool, error) {
	return c.decodeTGSRepForExchangeWithUsage(data, clientPrincipal, service, requestedService,
		serviceRealmKnown, nonce, keyType, key, 8, now)
}

func (c *Client) decodeFASTTGSRep(data []byte, clientPrincipal, service, requestedService principal.Principal, serviceRealmKnown bool, nonce uint32, replyKey protocol.EncryptionKey, armor *fast.Armor, now time.Time) (*Credentials, bool, error) {
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(data, &reply); err != nil {
		if kerberosError, ok := decodeKRBError(data); ok {
			return nil, false, kerberosError
		}
		return nil, false, fmt.Errorf("FAST TGS exchange TGS-REP: %w", err)
	}
	ticket, err := asn1.Marshal(reply.Ticket)
	if err != nil {
		return nil, false, fmt.Errorf("FAST TGS exchange ticket: %w", err)
	}
	fastReply, err := armor.UnwrapReply(reply.PAData, ticket, nonce)
	if err != nil {
		return nil, false, err
	}
	replyKey, err = armor.ReplyKey(replyKey, fastReply.StrengthenKey)
	if err != nil {
		return nil, false, err
	}
	if fastReply.Finished != nil {
		clientPrincipal = principalFromProtocol(fastReply.Finished.CName)
		clientPrincipal.Realm = fastReply.Finished.CRealm
		reply.CRealm = fastReply.Finished.CRealm
		reply.CName = fastReply.Finished.CName
	}
	rewrapped, err := asn1.Marshal(reply)
	if err != nil {
		return nil, false, fmt.Errorf("FAST TGS exchange reply: %w", err)
	}
	result, referral, err := c.decodeTGSRepForExchangeWithUsage(rewrapped, clientPrincipal, service,
		requestedService, serviceRealmKnown, nonce, replyKey.KeyType, replyKey.KeyValue, 9, now)
	return result, referral, err
}

func (c *Client) decodeTGSRepForExchangeWithUsage(data []byte, clientPrincipal, service, requestedService principal.Principal, serviceRealmKnown bool, nonce uint32, keyType int32, key []byte, usage uint32, now time.Time) (*Credentials, bool, error) {
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(data, &reply); err != nil {
		if kerberosError, ok := decodeKRBError(data); ok {
			return nil, false, kerberosError
		}
		return nil, false, fmt.Errorf("TGS exchange TGS-REP: %w", err)
	}
	if reply.MsgType != 13 {
		return nil, false, fmt.Errorf("TGS exchange: unexpected message type %d", reply.MsgType)
	}
	if reply.CRealm != clientPrincipal.Realm || !samePrincipal(reply.CName, clientPrincipal) {
		return nil, false, fmt.Errorf("TGS exchange: TGS-REP client principal mismatch")
	}
	if reply.EncPart.EType != keyType {
		return nil, false, fmt.Errorf("TGS exchange TGS-REP enctype %d: %w", reply.EncPart.EType, krberr.ErrUnsupportedEType)
	}
	etype, err := crypto.NewRegistry().Get(keyType)
	if err != nil {
		return nil, false, err
	}
	plaintext, err := etype.Decrypt(key, usage, reply.EncPart.Cipher)
	if err != nil {
		return nil, false, fmt.Errorf("TGS exchange decrypt TGS-REP: %w", err)
	}
	if len(plaintext) > 0 && plaintext[0] == 0x79 {
		plaintext = append([]byte(nil), plaintext...)
		plaintext[0] = 0x7a
	}
	var part protocol.EncTGSRepPart
	if err := asn1.Unmarshal(plaintext, &part); err != nil {
		return nil, false, fmt.Errorf("TGS exchange EncTGSRepPart: %w", err)
	}
	if part.Nonce != nonce {
		return nil, false, fmt.Errorf("TGS exchange: TGS-REP nonce mismatch")
	}
	referral := isReferralPrincipal(part.SName, requestedService)
	if !referral {
		serviceNameMatches := sameProtocolPrincipal(part.SName, service)
		canonicalizedService := c.canonicalizeEnabled()
		if (serviceRealmKnown && part.SRealm != service.Realm) ||
			(!serviceNameMatches && !canonicalizedService) {
			return nil, false, fmt.Errorf("TGS exchange: service principal mismatch")
		}
	} else if len(reply.Ticket.SName.NameString) != 2 {
		return nil, false, fmt.Errorf("TGS exchange: malformed referral service principal")
	}
	if !validTimes(part.AuthTime, part.StartTime, part.EndTime, now, c.clockSkew()) {
		return nil, false, fmt.Errorf("TGS exchange: %w", krberr.ErrClockSkew)
	}
	ticket, err := asn1.Marshal(reply.Ticket)
	if err != nil {
		return nil, false, fmt.Errorf("TGS exchange ticket: %w", err)
	}
	server := principalFromProtocol(part.SName)
	server.Realm = part.SRealm
	return &Credentials{
		Client: clientPrincipal, Server: server, Key: part.Key, Flags: part.Flags,
		AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, Ticket: ticket,
	}, referral, nil
}

package client

import (
	"context"
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// Client performs Kerberos client exchanges.
type Client struct {
	Config   *config.Config
	Dialer   transport.Dialer
	Now      func() time.Time
	Exchange func(ctx context.Context, realm string, payload []byte) ([]byte, error)
	// Canonicalize requests KDC canonicalization and permits the KDC to
	// return a canonical client principal in an AS-REP.
	Canonicalize bool
}

// Credentials contains the initial credentials returned by an AS exchange.
type Credentials struct {
	Client    principal.Principal
	Server    principal.Principal
	Key       protocol.EncryptionKey
	Flags     types.TicketFlags
	AuthTime  types.KerberosTime
	StartTime *types.KerberosTime
	EndTime   types.KerberosTime
	RenewTill *types.KerberosTime
	Ticket    []byte
}

// ToCCacheCredential converts credentials to a FILE ccache credential.
func (c Credentials) ToCCacheCredential() ccache.Credential {
	return ccache.Credential{
		Client:      c.Client,
		Server:      c.Server,
		Enctype:     c.Key.KeyType,
		Key:         append([]byte(nil), c.Key.KeyValue...),
		TicketFlags: uint32(c.Flags),
		AuthTime:    unixTime(c.AuthTime),
		StartTime:   unixOptional(c.StartTime),
		EndTime:     unixTime(c.EndTime),
		RenewTill:   unixOptional(c.RenewTill),
		Ticket:      append([]byte(nil), c.Ticket...),
	}
}

// ASExchange obtains initial credentials using a password.
func (c *Client) ASExchange(ctx context.Context, clientPrincipal principal.Principal, password string) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("AS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("AS exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("AS exchange: %w", err)
	}
	if clientPrincipal.Realm == "" || len(clientPrincipal.Components) == 0 {
		return nil, fmt.Errorf("AS exchange: invalid client principal")
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, err := c.newASReq(clientPrincipal, now)
	if err != nil {
		return nil, err
	}
	registry := crypto.NewRegistry()
	var initialETypeID int32
	var initialEType crypto.EType
	for _, candidate := range request.ReqBody.EType {
		initialEType, err = registry.Get(candidate)
		if err == nil {
			initialETypeID = candidate
			break
		}
	}
	if initialEType == nil {
		return nil, fmt.Errorf("AS exchange: %w", krberrors.ErrUnsupportedEType)
	}
	initialSalt := []byte(clientPrincipal.Realm + strings.Join(clientPrincipal.Components, ""))
	initialKey, err := initialEType.StringToKey([]byte(password), initialSalt, nil)
	if err != nil {
		return nil, fmt.Errorf("AS exchange string-to-key: %w", err)
	}
	response, err := c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		if kerberosError.Code != 25 {
			return nil, kerberosError
		}
		methodData, err := preauth.ParseMethodData(kerberosError.ErrorData())
		if err != nil {
			return nil, fmt.Errorf("AS exchange preauthentication: %w", err)
		}
		etypeID, salt, params, err := preauth.SelectEType(methodData, clientPrincipal.Realm, clientPrincipal, registry)
		if err != nil {
			return nil, err
		}
		etype, err := registry.Get(etypeID)
		if err != nil {
			return nil, err
		}
		key, err := etype.StringToKey([]byte(password), salt, params)
		if err != nil {
			return nil, fmt.Errorf("AS exchange string-to-key: %w", err)
		}
		timestamp, err := preauth.BuildEncryptedTimestamp(etype, key, now, 0)
		if err != nil {
			return nil, err
		}
		request.PAData = protocol.MethodData{timestamp}
		response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
		if err != nil {
			return nil, err
		}
		return c.decodeASRep(response, clientPrincipal, request.ReqBody.Nonce, etypeID, key, now)
	}
	return c.decodeASRep(response, clientPrincipal, request.ReqBody.Nonce, initialETypeID, initialKey, now)
}

// ASExchangeFAST obtains initial credentials using an RFC 6113 armor TGT.
func (c *Client) ASExchangeFAST(ctx context.Context, clientPrincipal principal.Principal, password string, armorTGT *Credentials) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("FAST AS exchange: nil client")
	}
	if armorTGT == nil {
		return nil, fmt.Errorf("FAST AS exchange: nil armor TGT")
	}
	if ctx == nil {
		return nil, fmt.Errorf("FAST AS exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("FAST AS exchange: %w", err)
	}
	if clientPrincipal.Realm == "" || len(clientPrincipal.Components) == 0 {
		return nil, fmt.Errorf("FAST AS exchange: invalid client principal")
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	armor, err := fast.NewArmor(fast.TGT{
		Ticket: armorTGT.Ticket, Client: armorTGT.Client, Key: armorTGT.Key,
	}, now)
	if err != nil {
		return nil, err
	}
	request, err := c.newASReq(clientPrincipal, now)
	if err != nil {
		return nil, err
	}
	registry := crypto.NewRegistry()
	var initialETypeID int32
	var initialEType crypto.EType
	for _, candidate := range request.ReqBody.EType {
		initialEType, err = registry.Get(candidate)
		if err == nil {
			initialETypeID = candidate
			break
		}
	}
	if initialEType == nil {
		return nil, fmt.Errorf("FAST AS exchange: %w", krberrors.ErrUnsupportedEType)
	}
	initialSalt := []byte(clientPrincipal.Realm + strings.Join(clientPrincipal.Components, ""))
	initialKey, err := initialEType.StringToKey([]byte(password), initialSalt, nil)
	if err != nil {
		return nil, fmt.Errorf("FAST AS exchange string-to-key: %w", err)
	}
	fastData, err := armor.WrapASReq(request.ReqBody, nil)
	if err != nil {
		return nil, err
	}
	request.PAData = protocol.MethodData{fastData}
	response, err := c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		if kerberosError.Code != 25 {
			return nil, kerberosError
		}
		fastReply, err := armor.UnwrapReply(errorMethodData(kerberosError), nil, request.ReqBody.Nonce)
		if err != nil {
			return nil, fmt.Errorf("FAST AS exchange preauthentication: %w", err)
		}
		etypeID, salt, params, err := preauth.SelectEType(fastReply.PAData, clientPrincipal.Realm, clientPrincipal, registry)
		if err != nil {
			return nil, err
		}
		etype, err := registry.Get(etypeID)
		if err != nil {
			return nil, err
		}
		clientKey, err := etype.StringToKey([]byte(password), salt, params)
		if err != nil {
			return nil, fmt.Errorf("FAST AS exchange string-to-key: %w", err)
		}
		timestamp, err := preauth.BuildEncryptedTimestamp(etype, clientKey, now, 0)
		if err != nil {
			return nil, err
		}
		fastData, err = armor.WrapASReq(request.ReqBody, protocol.MethodData{timestamp})
		if err != nil {
			return nil, err
		}
		request.PAData = protocol.MethodData{fastData}
		response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
		if err != nil {
			return nil, err
		}
		return c.decodeFASTASRep(response, clientPrincipal, request.ReqBody.Nonce, etypeID, clientKey, armor, now)
	}
	return c.decodeFASTASRep(response, clientPrincipal, request.ReqBody.Nonce, initialETypeID, initialKey, armor, now)
}

func (c *Client) decodeFASTASRep(data []byte, clientPrincipal principal.Principal, nonce uint32, etypeID int32, key []byte, armor *fast.Armor, now time.Time) (*Credentials, error) {
	var reply protocol.ASRep
	if err := asn1.Unmarshal(data, &reply); err != nil {
		if kerberosError, ok := decodeKRBError(data); ok {
			return nil, kerberosError
		}
		return nil, fmt.Errorf("FAST AS exchange AS-REP: %w", err)
	}
	ticket, err := asn1.Marshal(reply.Ticket)
	if err != nil {
		return nil, fmt.Errorf("FAST AS exchange ticket: %w", err)
	}
	fastReply, err := armor.UnwrapReply(reply.PAData, ticket, nonce)
	if err != nil {
		return nil, err
	}
	replyKey, err := armor.ReplyKey(protocol.EncryptionKey{KeyType: etypeID, KeyValue: key}, fastReply.StrengthenKey)
	if err != nil {
		return nil, err
	}
	return c.decodeASRep(data, clientPrincipal, nonce, replyKey.KeyType, replyKey.KeyValue, now)
}

func errorMethodData(value *krberrors.KRBError) protocol.MethodData {
	if value == nil || len(value.ErrorData()) == 0 {
		return nil
	}
	var data protocol.MethodData
	if asn1.Unmarshal(value.ErrorData(), &data) != nil {
		return nil
	}
	return data
}

// TGSExchange obtains a service ticket using an existing TGT.
func (c *Client) TGSExchange(ctx context.Context, tgt *Credentials, service principal.Principal) (*Credentials, error) {
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
	realm, mapped := ServiceRealm(c.Config, service)
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
			hops > 0 || (!mapped && requestedService.Realm == ""))
		if err != nil {
			return nil, err
		}
		response, err := c.exchangePayload(ctx, realm, request, "TGS exchange request")
		if err != nil {
			return nil, err
		}
		if kerberosError, ok := decodeKRBError(response); ok {
			return nil, kerberosError
		}
		result, referral, err := c.decodeTGSRepForExchange(response, currentTGT.Client, service, requestedService, mapped, nonce, currentTGT.Key.KeyType, currentTGT.Key.KeyValue, now)
		if err != nil {
			return nil, err
		}
		if !referral {
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

func (c *Client) newTGSReq(tgt *Credentials, service principal.Principal, realm string, now time.Time, referral bool) (protocol.TGSReq, uint32, error) {
	return c.newTGSReqWithBody(tgt, service, realm, now, referral, nil)
}

// newTGSReqWithBody builds a TGS-REQ, letting the caller adjust the request
// body before it is marshalled and covered by the authenticator checksum.
func (c *Client) newTGSReqWithBody(tgt *Credentials, service principal.Principal, realm string, now time.Time, referral bool, adjust func(*protocol.KDCReqBody)) (protocol.TGSReq, uint32, error) {
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		return protocol.TGSReq{}, 0, err
	}
	nonceBytes := make([]byte, 4)
	if _, err := io.ReadFull(crypto.RandomSource, nonceBytes); err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange nonce: %w", err)
	}
	options := types.KDCRenewableOK
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
		EType: c.requestEnctypes(),
	}
	if adjust != nil {
		adjust(&body)
	}
	bodyDER, err := asn1.Marshal(body)
	if err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange request body: %w", err)
	}
	checksum, err := etype.Checksum(tgt.Key.KeyValue, 6, bodyDER)
	if err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange request checksum: %w", err)
	}
	usec := int32(now.Nanosecond() / 1000)
	authenticatorDER, err := asn1.Marshal(protocol.Authenticator{
		AuthenticatorVNO: 5,
		CRealm:           tgt.Client.Realm,
		CName:            *protocolPrincipal(tgt.Client),
		Checksum: &protocol.Checksum{
			ChecksumType: checksumType(tgt.Key.KeyType),
			Checksum:     checksum,
		},
		Cusec: usec,
		Ctime: types.KerberosTime{Time: now, Microseconds: usec, Present: true},
	})
	if err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange authenticator: %w", err)
	}
	encryptedAuthenticator, err := etype.Encrypt(tgt.Key.KeyValue, 7, authenticatorDER)
	if err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange authenticator encryption: %w", err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(tgt.Ticket, &ticket); err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange ticket: %w", err)
	}
	apReqDER, err := asn1.Marshal(protocol.APReq{
		PVNO: 5, MsgType: 14, Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: tgt.Key.KeyType, Cipher: encryptedAuthenticator},
	})
	if err != nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS exchange AP-REQ: %w", err)
	}
	return protocol.TGSReq{
		PVNO: 5, MsgType: 12,
		PAData:  protocol.MethodData{{PADataType: 1, PADataValue: apReqDER}},
		ReqBody: body,
	}, body.Nonce, nil
}

func (c *Client) decodeTGSRep(data []byte, clientPrincipal, service principal.Principal, nonce uint32, keyType int32, key []byte, now time.Time) (*Credentials, error) {
	result, _, err := c.decodeTGSRepForExchange(data, clientPrincipal, service, service, true, nonce, keyType, key, now)
	return result, err
}

func (c *Client) decodeTGSRepForExchange(data []byte, clientPrincipal, service, requestedService principal.Principal, serviceRealmKnown bool, nonce uint32, keyType int32, key []byte, now time.Time) (*Credentials, bool, error) {
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
		return nil, false, fmt.Errorf("TGS exchange TGS-REP enctype %d: %w", reply.EncPart.EType, krberrors.ErrUnsupportedEType)
	}
	etype, err := crypto.NewRegistry().Get(keyType)
	if err != nil {
		return nil, false, err
	}
	plaintext, err := etype.Decrypt(key, 8, reply.EncPart.Cipher)
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
	referral := isReferralPrincipal(reply.Ticket.SName, requestedService)
	if !referral {
		if (serviceRealmKnown && (reply.Ticket.Realm != service.Realm || part.SRealm != service.Realm)) ||
			!sameProtocolPrincipal(reply.Ticket.SName, service) ||
			!sameProtocolPrincipal(part.SName, service) {
			return nil, false, fmt.Errorf("TGS exchange: service principal mismatch")
		}
	} else if len(reply.Ticket.SName.NameString) != 2 {
		return nil, false, fmt.Errorf("TGS exchange: malformed referral service principal")
	}
	if !validTimes(part.AuthTime, part.StartTime, part.EndTime, now, c.clockSkew()) {
		return nil, false, fmt.Errorf("TGS exchange: %w", krberrors.ErrClockSkew)
	}
	ticket, err := asn1.Marshal(reply.Ticket)
	if err != nil {
		return nil, false, fmt.Errorf("TGS exchange ticket: %w", err)
	}
	server := principalFromProtocol(reply.Ticket.SName)
	server.Realm = reply.Ticket.Realm
	return &Credentials{
		Client: clientPrincipal, Server: server, Key: part.Key, Flags: part.Flags,
		AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, Ticket: ticket,
	}, referral, nil
}

func (c *Client) exchangePayload(ctx context.Context, realm string, request any, label string) ([]byte, error) {
	payload, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if c.Exchange != nil {
		response, err := c.Exchange(ctx, realm, payload)
		if err != nil {
			return nil, fmt.Errorf("TGS exchange transport: %w", err)
		}
		return response, nil
	}
	if c.Config == nil {
		return nil, fmt.Errorf("TGS exchange: no configuration or exchange function")
	}
	endpoint, ok := configuredKDC(c.Config, realm)
	if !ok {
		return nil, fmt.Errorf("TGS exchange: no KDC configured for realm %q", realm)
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
		Dialer: c.Dialer, Timeout: 5 * time.Second, UDPPreferenceLimit: 1,
	}
	if c.Config.UDPPreferenceLimit > 0 {
		exchange.UDPPreferenceLimit = c.Config.UDPPreferenceLimit
	}
	return exchange.Request(ctx, conn, address, payload)
}

func (c *Client) ticketLifetime() time.Duration {
	if c.Config != nil && c.Config.TicketLifetime > 0 {
		return c.Config.TicketLifetime
	}
	return 10 * time.Hour
}

func (c *Client) canonicalizeEnabled() bool {
	return c.Canonicalize || (c.Config != nil && c.Config.Canonicalize)
}

func (c *Client) requestEnctypes() []int32 {
	if c.Config != nil && len(c.Config.DefaultTKTEnctypes) > 0 {
		return append([]int32(nil), c.Config.DefaultTKTEnctypes...)
	}
	return []int32{crypto.EnctypeAES256SHA1, crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA384, crypto.EnctypeAES128SHA256}
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

// ServiceRealm resolves the target realm for a service principal. The bool
// reports whether the realm came from the principal or an explicit mapping;
// the configured default realm is a fallback for unmapped host services.
func ServiceRealm(cfg *config.Config, service principal.Principal) (string, bool) {
	if service.Realm != "" {
		return service.Realm, true
	}
	if cfg != nil && len(service.Components) > 1 {
		if realm, ok := cfg.RealmForHost(service.Components[1]); ok {
			return realm, true
		}
	}
	if cfg != nil && cfg.DefaultRealm != "" {
		return cfg.DefaultRealm, false
	}
	return "", false
}

func isReferralPrincipal(value protocol.PrincipalName, requested principal.Principal) bool {
	if len(value.NameString) != 2 || value.NameString[0] != "krbtgt" {
		return false
	}
	return requested.Realm == "" || value.NameString[1] != requested.Realm
}

func randomNonce(value []byte) uint32 {
	return binary.BigEndian.Uint32(value) & 0x7fffffff
}

func (c *Client) newASReq(clientPrincipal principal.Principal, now time.Time) (protocol.ASReq, error) {
	nonceBytes := make([]byte, 4)
	if _, err := io.ReadFull(crypto.RandomSource, nonceBytes); err != nil {
		return protocol.ASReq{}, fmt.Errorf("AS exchange nonce: %w", err)
	}
	lifetime := 10 * time.Hour
	forwardable := true
	if c.Config != nil {
		if c.Config.TicketLifetime > 0 {
			lifetime = c.Config.TicketLifetime
		}
		forwardable = c.Config.Forwardable
	}
	options := types.KDCRenewableOK
	if forwardable {
		options |= types.KDCForwardable
	}
	if c.canonicalizeEnabled() {
		options |= types.KDCCanonicalize
	}
	enctypes := []int32{crypto.EnctypeAES256SHA1, crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA384, crypto.EnctypeAES128SHA256}
	if c.Config != nil && len(c.Config.DefaultTKTEnctypes) > 0 {
		enctypes = append([]int32(nil), c.Config.DefaultTKTEnctypes...)
	}
	return protocol.ASReq{
		PVNO: 5, MsgType: 10,
		ReqBody: protocol.KDCReqBody{
			KDCOptions: options,
			CName:      protocolPrincipal(clientPrincipal),
			Realm:      clientPrincipal.Realm,
			SName: &protocol.PrincipalName{
				NameType:   int32(principal.NTSrvInstance),
				NameString: []string{"krbtgt", clientPrincipal.Realm},
			},
			Till:  types.KerberosTime{Time: now.Add(lifetime), Present: true},
			Nonce: randomNonce(nonceBytes),
			EType: enctypes,
		},
	}, nil
}

func (c *Client) roundTrip(ctx context.Context, realm string, request protocol.ASReq) ([]byte, error) {
	payload, err := asn1.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("AS exchange request: %w", err)
	}
	if c.Exchange != nil {
		response, err := c.Exchange(ctx, realm, payload)
		if err != nil {
			return nil, fmt.Errorf("AS exchange transport: %w", err)
		}
		return response, nil
	}
	if c.Config == nil {
		return nil, fmt.Errorf("AS exchange: no configuration or exchange function")
	}
	endpoint, ok := configuredKDC(c.Config, realm)
	if !ok {
		return nil, fmt.Errorf("AS exchange: no KDC configured for realm %q", realm)
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
		Timeout:            5 * time.Second,
		UDPPreferenceLimit: 1,
	}
	if c.Config.UDPPreferenceLimit > 0 {
		exchange.UDPPreferenceLimit = c.Config.UDPPreferenceLimit
	}
	return exchange.Request(ctx, conn, address, payload)
}

func (c *Client) decodeASRep(data []byte, clientPrincipal principal.Principal, nonce uint32, etypeID int32, key []byte, now time.Time) (*Credentials, error) {
	var reply protocol.ASRep
	if len(data) > 0 && data[0] == 0x7a {
		data = append([]byte(nil), data...)
		data[0] = 0x79
	}
	if err := asn1.Unmarshal(data, &reply); err != nil {
		if kerberosError, ok := decodeKRBError(data); ok {
			return nil, kerberosError
		}
		return nil, fmt.Errorf("AS exchange AS-REP: %w", err)
	}
	if reply.MsgType != 11 {
		return nil, fmt.Errorf("AS exchange: unexpected message type %d", reply.MsgType)
	}
	if reply.CRealm != clientPrincipal.Realm ||
		(!samePrincipal(reply.CName, clientPrincipal) && !c.canonicalizeEnabled()) {
		return nil, fmt.Errorf("AS exchange: AS-REP client principal mismatch")
	}
	if reply.EncPart.EType != etypeID {
		return nil, fmt.Errorf("AS exchange AS-REP enctype %d: %w", reply.EncPart.EType, krberrors.ErrUnsupportedEType)
	}
	etype, err := crypto.NewRegistry().Get(reply.EncPart.EType)
	if err != nil {
		return nil, err
	}
	plaintext, err := etype.Decrypt(key, 3, reply.EncPart.Cipher)
	if err != nil {
		return nil, fmt.Errorf("AS exchange decrypt AS-REP: %w", err)
	}
	var part protocol.EncASRepPart
	if len(plaintext) > 0 && plaintext[0] == 0x7a {
		plaintext = append([]byte(nil), plaintext...)
		plaintext[0] = 0x79
	}
	if err := asn1.Unmarshal(plaintext, &part); err != nil {
		return nil, fmt.Errorf("AS exchange EncASRepPart: %w", err)
	}
	if part.Nonce != nonce {
		return nil, fmt.Errorf("AS exchange: AS-REP nonce mismatch")
	}
	if reply.Ticket.Realm != clientPrincipal.Realm ||
		reply.Ticket.SName.NameType != int32(principal.NTSrvInstance) ||
		len(reply.Ticket.SName.NameString) != 2 ||
		reply.Ticket.SName.NameString[0] != "krbtgt" ||
		reply.Ticket.SName.NameString[1] != clientPrincipal.Realm ||
		part.SRealm != clientPrincipal.Realm ||
		part.SName.NameType != int32(principal.NTSrvInstance) ||
		len(part.SName.NameString) != 2 ||
		part.SName.NameString[0] != "krbtgt" ||
		part.SName.NameString[1] != clientPrincipal.Realm {
		return nil, fmt.Errorf("AS exchange: invalid ticket server principal")
	}
	if !validTimes(part.AuthTime, part.StartTime, part.EndTime, now, c.clockSkew()) {
		return nil, fmt.Errorf("AS exchange: %w", krberrors.ErrClockSkew)
	}
	ticket, err := asn1.Marshal(reply.Ticket)
	if err != nil {
		return nil, fmt.Errorf("AS exchange ticket: %w", err)
	}
	server := principalFromProtocol(reply.Ticket.SName)
	server.Realm = reply.Ticket.Realm
	returnedClient := principalFromProtocol(reply.CName)
	returnedClient.Realm = reply.CRealm
	return &Credentials{
		Client: returnedClient, Server: server,
		Key: part.Key, Flags: part.Flags, AuthTime: part.AuthTime,
		StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, Ticket: ticket,
	}, nil
}

func decodeKRBError(data []byte) (*krberrors.KRBError, bool) {
	var value protocol.KRBError
	if err := asn1.Unmarshal(data, &value); err != nil {
		return nil, false
	}
	server := principalFromProtocol(value.SName).String()
	return krberrors.NewKRBError(
		krberrors.ErrorCode(value.ErrorCode), server, value.Realm,
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
	if start != nil && start.Present && start.Time.After(end.Time) {
		return false
	}
	return !auth.Time.Before(now.Add(-skew)) && !auth.Time.After(now.Add(skew)) &&
		!end.Time.Before(now.Add(-skew))
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
	pk, err := pkinit.NewClient(cert, key)
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
	response, err := c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		if kerberosError.Code != 25 {
			return nil, kerberosError
		}
		bodyDER, err := asn1.Marshal(request.ReqBody)
		if err != nil {
			return nil, fmt.Errorf("PKINIT AS request body: %w", err)
		}
		pa, err := pk.BuildPAASReq(bodyDER, now, request.ReqBody.Nonce)
		if err != nil {
			return nil, err
		}
		request.PAData = protocol.MethodData{pa}
		response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
		if err != nil {
			return nil, err
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
	replyKey, err := pk.VerifyPAASRep(pkReply, anchors, reply.EncPart.EType, request.ReqBody.Nonce)
	if err != nil {
		return nil, err
	}
	return c.decodeASRep(response, clientPrincipal, request.ReqBody.Nonce, reply.EncPart.EType, replyKey, now)
}

package client

import (
	"context"
	stdcrypto "crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
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
	"github.com/Exonical/go-kerberos/krb5/hostrealm"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
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
	groups := c.SPAKEGroups
	if len(groups) == 0 {
		groups = []int32{spake.GroupEdwards25519}
	}
	support, err := spake.EncodeSupport(groups)
	if err != nil {
		return nil, err
	}
	request.PAData = protocol.MethodData{{PADataType: preauth.PADataSPAKE, PADataValue: support}}
	response, err := c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		if kerberosError.Code != 25 && kerberosError.Code != 91 {
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
		if challengePA := preauth.FindPAData(methodData, preauth.PADataSPAKE); challengePA != nil {
			if len(challengePA.PADataValue) == 0 {
				goto timestampFallback
			}
			msg, err := spake.Decode(challengePA.PADataValue)
			if err != nil {
				return nil, fmt.Errorf("AS exchange SPAKE challenge: %w", err)
			}
			if msg.Challenge == nil {
				// A KDC may advertise SPAKE without selecting it.  Keep the
				// established PA-ENC-TIMESTAMP fallback in that case.
				goto timestampFallback
			}
			supportsFactor := false
			for _, factor := range msg.Challenge.Factors {
				if factor.Type == spake.FactorNone {
					supportsFactor = true
					break
				}
			}
			if !supportsFactor {
				return nil, fmt.Errorf("AS exchange SPAKE: challenge has no supported factor")
			}
			groups := c.SPAKEGroups
			if len(groups) == 0 {
				groups = []int32{spake.GroupEdwards25519}
			}
			offered := false
			for _, group := range groups {
				if group == msg.Challenge.Group {
					offered = true
					break
				}
			}
			if !offered {
				return nil, fmt.Errorf("AS exchange SPAKE: challenge group %d was not offered", msg.Challenge.Group)
			}
			challengeDER := challengePA.PADataValue
			w, err := spake.DeriveW(etype, key, msg.Challenge.Group)
			if err != nil {
				return nil, err
			}
			private, public, err := spake.Keygen(msg.Challenge.Group, w, false)
			if err != nil {
				return nil, err
			}
			result, err := spake.Result(msg.Challenge.Group, w, private, msg.Challenge.PubKey, true)
			if err != nil {
				return nil, err
			}
			transcript := spake.TranscriptForGroup(msg.Challenge.Group, nil, support, challengeDER)
			transcript = spake.TranscriptForGroup(msg.Challenge.Group, transcript, public, nil)
			bodyDER, err := asn1.Marshal(request.ReqBody)
			if err != nil {
				return nil, err
			}
			k0, err := spake.DeriveKey(etype, key, w, result, transcript, bodyDER,
				msg.Challenge.Group, 0)
			if err != nil {
				return nil, err
			}
			k1, err := spake.DeriveKey(etype, key, w, result, transcript, bodyDER,
				msg.Challenge.Group, 1)
			if err != nil {
				return nil, err
			}
			factorDER, err := spake.EncodeFactor()
			if err != nil {
				return nil, err
			}
			factorCipher, err := etype.Encrypt(k1, spake.KeyUsage, factorDER)
			if err != nil {
				return nil, err
			}
			responseDER, err := spake.EncodeResponse(public, factorCipher, etype.ID())
			if err != nil {
				return nil, err
			}
			request.PAData = protocol.MethodData{{PADataType: preauth.PADataSPAKE, PADataValue: responseDER}}
			if cookie := preauth.FindPAData(methodData, preauth.PADataCookie); cookie != nil {
				request.PAData = append(request.PAData, *cookie)
			}
			response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
			if err != nil {
				return nil, err
			}
			return c.decodeASRep(response, clientPrincipal, request.ReqBody.Nonce, etype.ID(), k0, now)
		}
	timestampFallback:
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

// ASExchangeService obtains initial credentials for a specific service
// principal, rather than the realm TGT. This is used by protocols such as
// RFC 3244 kpasswd whose service principal intentionally rejects TGT-based
// service-ticket requests.
func (c *Client) ASExchangeService(ctx context.Context, clientPrincipal principal.Principal, password string, service principal.Principal) (*Credentials, error) {
	candidates, err := c.serviceCandidates(ctx, service)
	if err != nil {
		return nil, err
	}
	for index := range candidates {
		if candidates[index].Realm == "" {
			// AS requests are always sent to the client's realm, and the
			// request body's service realm follows that realm.  Host-realm
			// mappings still determine the candidate hostname, but cannot
			// redirect an initial-credentials request to another KDC realm.
			candidates[index].Realm = clientPrincipal.Realm
		}
	}
	var last error
	for index, candidate := range candidates {
		result, err := c.asExchangeServiceOnce(ctx, clientPrincipal, password, candidate)
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

func (c *Client) asExchangeServiceOnce(ctx context.Context, clientPrincipal principal.Principal, password string, service principal.Principal) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("AS service exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("AS service exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("AS service exchange: %w", err)
	}
	if clientPrincipal.Realm == "" || len(clientPrincipal.Components) == 0 {
		return nil, fmt.Errorf("AS service exchange: invalid client principal")
	}
	if service.NameType == 0 {
		service.NameType = principal.NTSrvInstance
	}
	if len(service.Components) == 0 {
		return nil, fmt.Errorf("AS service exchange: invalid service principal")
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, err := c.newASReqForService(clientPrincipal, service, now)
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
		return nil, fmt.Errorf("AS service exchange: %w", krberrors.ErrUnsupportedEType)
	}
	initialSalt := []byte(clientPrincipal.Realm + strings.Join(clientPrincipal.Components, ""))
	initialKey, err := initialEType.StringToKey([]byte(password), initialSalt, nil)
	if err != nil {
		return nil, fmt.Errorf("AS service exchange string-to-key: %w", err)
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
			return nil, fmt.Errorf("AS service exchange preauthentication: %w", err)
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
			return nil, fmt.Errorf("AS service exchange string-to-key: %w", err)
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
		return c.decodeASRepForService(response, clientPrincipal, service, request.ReqBody.Nonce, etypeID, key, now)
	}
	return c.decodeASRepForService(response, clientPrincipal, service, request.ReqBody.Nonce, initialETypeID, initialKey, now)
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
		var retryPA protocol.PAData
		if challengePA := preauth.FindPAData(fastReply.PAData, preauth.PADataEncryptedChallenge); challengePA != nil {
			retryPA, err = preauth.BuildEncryptedChallengeWithKeyEType(
				armor.EType, armor.Key, etype, clientKey, now)
		} else {
			retryPA, err = preauth.BuildEncryptedTimestamp(etype, clientKey, now, 0)
		}
		if err != nil {
			return nil, fmt.Errorf("FAST AS exchange preauthentication: %w", err)
		}
		retryPAData := protocol.MethodData{retryPA}
		if cookie := preauth.FindPAData(fastReply.PAData, preauth.PADataCookie); cookie != nil {
			retryPAData = append(retryPAData, *cookie)
		}
		fastData, err = armor.WrapASReq(request.ReqBody, retryPAData)
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

// ASExchangeFASTOTP obtains initial credentials with RFC 6560 OTP
// preauthentication inside RFC 6113 FAST. MIT uses the FAST armor key
// directly both to protect the OTP nonce (usage 45) and as the AS reply key.
func (c *Client) ASExchangeFASTOTP(ctx context.Context, clientPrincipal principal.Principal,
	armorTGT *Credentials, provider OTPProvider) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("OTP FAST AS exchange: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("OTP FAST AS exchange: nil context")
	}
	if armorTGT == nil {
		return nil, fmt.Errorf("OTP FAST AS exchange: nil armor TGT")
	}
	if provider == nil {
		return nil, fmt.Errorf("OTP FAST AS exchange: nil OTP provider")
	}
	if clientPrincipal.Realm == "" || len(clientPrincipal.Components) == 0 {
		return nil, fmt.Errorf("OTP FAST AS exchange: invalid client principal")
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
	request.PAData = nil
	fastData, err := armor.WrapASReq(request.ReqBody, nil)
	if err != nil {
		return nil, err
	}
	request.PAData = protocol.MethodData{fastData}
	response, err := c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	kerberosError, ok := decodeKRBError(response)
	if !ok {
		return nil, fmt.Errorf("OTP FAST AS exchange: expected PREAUTH_REQUIRED")
	}
	if kerberosError.Code != 25 {
		return nil, kerberosError
	}
	fastReply, err := armor.UnwrapReply(errorMethodData(kerberosError), nil, request.ReqBody.Nonce)
	if err != nil {
		return nil, fmt.Errorf("OTP FAST AS exchange preauthentication: %w", err)
	}
	challengePA := preauth.FindPAData(fastReply.PAData, otp.PADataChallenge)
	if challengePA == nil {
		return nil, fmt.Errorf("OTP FAST AS exchange: missing PA-OTP-CHALLENGE")
	}
	challenge, err := otp.DecodeChallenge(challengePA.PADataValue)
	if err != nil {
		return nil, fmt.Errorf("OTP FAST AS challenge: %w", err)
	}
	value, pin, err := provider(challenge)
	if err != nil {
		return nil, fmt.Errorf("OTP FAST AS provider: %w", err)
	}
	if len(challenge.TokenInfo) == 0 {
		return nil, fmt.Errorf("OTP FAST AS challenge: no token information")
	}
	ti := challenge.TokenInfo[0]
	otpRequest := otp.Request{
		Flags: ti.Flags & otp.FlagNextOTP, OTPValue: []byte(value),
		Format: ti.Format, TokenID: append([]byte(nil), ti.TokenID...),
		AlgID: ti.AlgID, Vendor: ti.Vendor,
	}
	if pin != "" {
		pinValue := types.UTF8String(pin)
		otpRequest.PIN = &pinValue
	}
	otpRequest.EncData, err = otp.EncryptNonce(armor.EType, armor.Key, challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("OTP FAST AS request: %w", err)
	}
	otpDER, err := otp.EncodeRequest(otpRequest)
	if err != nil {
		return nil, fmt.Errorf("OTP FAST AS request: %w", err)
	}
	fastData, err = armor.WrapASReq(request.ReqBody, protocol.MethodData{
		{PADataType: otp.PADataRequest, PADataValue: otpDER},
	})
	if err != nil {
		return nil, err
	}
	request.PAData = protocol.MethodData{fastData}
	response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
	if err != nil {
		return nil, err
	}
	return c.decodeFASTASRep(response, clientPrincipal, request.ReqBody.Nonce,
		armor.EType.ID(), armor.Key, armor, now)
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
	if challengePA := preauth.FindPAData(fastReply.PAData, preauth.PADataEncryptedChallenge); challengePA != nil {
		clientEType, err := crypto.NewRegistry().Get(etypeID)
		if err != nil {
			return nil, err
		}
		if err := preauth.VerifyEncryptedChallengeReplyWithKeyEType(
			armor.EType, armor.Key, clientEType, key, challengePA.PADataValue); err != nil {
			return nil, fmt.Errorf("FAST AS exchange encrypted challenge: %w", err)
		}
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

func freshnessTokenFromError(value *krberrors.KRBError) []byte {
	for _, pa := range errorMethodData(value) {
		if pa.PADataType == pkinit.PADataASFreshness {
			return append([]byte(nil), pa.PADataValue...)
		}
	}
	return nil
}

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
	if _, err := io.ReadFull(crypto.RandomSource, nonceBytes); err != nil {
		return protocol.TGSReq{}, 0, nil, protocol.EncryptionKey{}, fmt.Errorf("TGS exchange nonce: %w", err)
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
		if _, err := io.ReadFull(crypto.RandomSource, subkeyValue); err != nil {
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
		return nil, false, fmt.Errorf("TGS exchange TGS-REP enctype %d: %w", reply.EncPart.EType, krberrors.ErrUnsupportedEType)
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
	referral := isReferralPrincipal(reply.Ticket.SName, requestedService)
	if !referral {
		serviceNameMatches := sameProtocolPrincipal(reply.Ticket.SName, service) &&
			sameProtocolPrincipal(part.SName, service)
		canonicalizedService := c.canonicalizeEnabled() &&
			sameProtocolPrincipal(reply.Ticket.SName, principalFromProtocol(part.SName))
		if (serviceRealmKnown && (reply.Ticket.Realm != service.Realm || part.SRealm != service.Realm)) ||
			(!serviceNameMatches && !canonicalizedService) {
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
	if c.Exchange != nil {
		response, err := c.Exchange(ctx, realm, payload)
		if err != nil {
			return nil, fmt.Errorf("%s transport: %w", label, err)
		}
		return response, nil
	}
	if c.Config == nil {
		return nil, fmt.Errorf("%s: no configuration or exchange function", label)
	}
	endpoint, ok := configuredKDC(c.Config, realm)
	if !ok {
		return nil, fmt.Errorf("%s: no KDC configured for realm %q", label, realm)
	}
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return c.kkdcpClient().Exchange(ctx, endpoint, realm, payload)
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

// BuildASRequest constructs an AS-REQ without sending it.
func (c *Client) BuildASRequest(clientPrincipal principal.Principal, now time.Time) (protocol.ASReq, error) {
	return c.newASReq(clientPrincipal, now)
}

// DecodeASResponse validates and decrypts an AS-REP.
func (c *Client) DecodeASResponse(data []byte, clientPrincipal principal.Principal,
	nonce uint32, etypeID int32, key []byte, now time.Time) (*Credentials, error) {
	return c.decodeASRep(data, clientPrincipal, nonce, etypeID, key, now)
}

// BuildTGSRequest constructs a TGS-REQ without sending it.
func (c *Client) BuildTGSRequest(tgt *Credentials, service principal.Principal,
	now time.Time) (protocol.TGSReq, uint32, error) {
	if tgt == nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS request: nil TGT")
	}
	realm := service.Realm
	if realm == "" {
		realm = tgt.Server.Realm
	}
	return c.newTGSReq(tgt, service, realm, now, false)
}

// BuildTGSRequestForRealm constructs one step of a possibly cross-realm TGS
// exchange. The caller supplies the KDC realm and whether referrals should be
// requested.
func (c *Client) BuildTGSRequestForRealm(tgt *Credentials, service principal.Principal,
	realm string, referral bool, now time.Time) (protocol.TGSReq, uint32, error) {
	if tgt == nil {
		return protocol.TGSReq{}, 0, fmt.Errorf("TGS request: nil TGT")
	}
	return c.newTGSReq(tgt, service, realm, now, referral)
}

// DecodeTGSResponseForExchange decodes one TGS exchange and reports whether
// the response is a referral ticket that requires another proxy step.
func (c *Client) DecodeTGSResponseForExchange(data []byte, tgt *Credentials,
	service, requestedService principal.Principal, mapped bool, nonce uint32,
	now time.Time) (*Credentials, bool, error) {
	if tgt == nil {
		return nil, false, fmt.Errorf("TGS response: nil TGT")
	}
	return c.decodeTGSRepForExchange(data, tgt.Client, service, requestedService,
		mapped, nonce, tgt.Key.KeyType, tgt.Key.KeyValue, now)
}

// DecodeTGSResponse validates and decrypts a TGS-REP.
func (c *Client) DecodeTGSResponse(data []byte, tgt *Credentials,
	service principal.Principal, nonce uint32, now time.Time) (*Credentials, error) {
	if tgt == nil {
		return nil, fmt.Errorf("TGS response: nil TGT")
	}
	result, referral, err := c.decodeTGSRepForExchange(data, tgt.Client, service, service,
		true, nonce, tgt.Key.KeyType, tgt.Key.KeyValue, now)
	if err != nil {
		return nil, err
	}
	if referral {
		return nil, fmt.Errorf("TGS response: unexpected referral")
	}
	return result, nil
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

func (c *Client) resolveServiceRealm(ctx context.Context, service principal.Principal) (string, bool, error) {
	if service.Realm != "" {
		return service.Realm, true, nil
	}
	if service.NameType == principal.NTSrvHst && len(service.Components) > 1 {
		realm, authoritative, err := hostrealm.HostRealm(ctx, c.Config, service.Components[1], hostrealm.Options{})
		if err != nil {
			return "", false, err
		}
		if realm != "" {
			return realm, authoritative, nil
		}
	}
	realm, mapped := ServiceRealm(c.Config, service)
	return realm, mapped, nil
}

func (c *Client) serviceCandidates(ctx context.Context, service principal.Principal) ([]principal.Principal, error) {
	if c == nil {
		return nil, fmt.Errorf("client: nil client")
	}
	if service.NameType == 0 {
		service.NameType = principal.NTSrvInstance
	}
	candidates, err := hostrealm.CanonicalizePrincipalCandidates(ctx, c.Config, service, hostrealm.Options{})
	if err != nil {
		return nil, err
	}
	return candidates, nil
}

func isUnknownServiceError(err error) bool {
	var kerberosError *krberrors.KRBError
	return errors.As(err, &kerberosError) &&
		kerberosError.Code == krberrors.KDCErrSPrincipalUnknown
}

func isKRBError(err error) bool {
	var kerberosError *krberrors.KRBError
	return errors.As(err, &kerberosError)
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
	return c.newASReqForService(clientPrincipal, principal.Principal{
		Realm: clientPrincipal.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", clientPrincipal.Realm},
	}, now)
}

func (c *Client) newASReqForService(clientPrincipal, service principal.Principal, now time.Time) (protocol.ASReq, error) {
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
	return protocol.ASReq{
		PVNO: 5, MsgType: 10,
		ReqBody: protocol.KDCReqBody{
			KDCOptions: options,
			CName:      protocolPrincipal(clientPrincipal),
			Realm:      service.Realm,
			SName: &protocol.PrincipalName{
				NameType:   int32(service.NameType),
				NameString: append([]string(nil), service.Components...),
			},
			Till:  types.KerberosTime{Time: now.Add(lifetime), Present: true},
			Nonce: randomNonce(nonceBytes),
			EType: c.asRequestEnctypes(),
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
	if strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return c.kkdcpClient().Exchange(ctx, endpoint, realm, payload)
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
	return c.decodeASRepForService(data, clientPrincipal, principal.Principal{
		Realm: clientPrincipal.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", clientPrincipal.Realm},
	}, nonce, etypeID, key, now)
}

func (c *Client) decodeASRepForService(data []byte, clientPrincipal, service principal.Principal, nonce uint32, etypeID int32, key []byte, now time.Time) (*Credentials, error) {
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
	anonymousReply := clientPrincipal.NameType == principal.NTWellKnown &&
		len(clientPrincipal.Components) == 2 &&
		clientPrincipal.Components[0] == "WELLKNOWN" &&
		clientPrincipal.Components[1] == "ANONYMOUS" &&
		reply.CRealm == "WELLKNOWN:ANONYMOUS"
	if (reply.CRealm != clientPrincipal.Realm && !anonymousReply) ||
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
	if reply.Ticket.Realm != service.Realm ||
		reply.Ticket.SName.NameType != int32(service.NameType) ||
		len(reply.Ticket.SName.NameString) != len(service.Components) ||
		!slicesEqual(reply.Ticket.SName.NameString, service.Components) ||
		part.SRealm != service.Realm ||
		part.SName.NameType != int32(service.NameType) ||
		len(part.SName.NameString) != len(service.Components) ||
		!slicesEqual(part.SName.NameString, service.Components) {
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
	response, err = c.roundTrip(ctx, realm, request)
	if err != nil {
		return nil, err
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
			krberrors.ErrIntegrity,
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
		return fmt.Errorf("anonymous PKINIT: missing PA-PKINIT-KX: %w", krberrors.ErrIntegrity)
	}
	var encryptedKey protocol.EncryptedData
	if err := asn1.Unmarshal(kxValue, &encryptedKey); err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX: %w", krberrors.ErrIntegrity)
	}
	if encryptedKey.EType != reply.EncPart.EType {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX enctype mismatch: %w", krberrors.ErrIntegrity)
	}
	etype, err := crypto.NewRegistry().Get(reply.EncPart.EType)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX enctype: %w", krberrors.ErrIntegrity)
	}
	plainKey, err := etype.Decrypt(replyKey, keyUsagePAPKINITKX, encryptedKey.Cipher)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX decrypt: %w", krberrors.ErrIntegrity)
	}
	var kdcKey protocol.EncryptionKey
	if err := asn1.Unmarshal(plainKey, &kdcKey); err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX key: %w", krberrors.ErrIntegrity)
	}
	if kdcKey.KeyType != reply.EncPart.EType {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX key enctype mismatch: %w", krberrors.ErrIntegrity)
	}
	plainReply, err := etype.Decrypt(replyKey, 3, reply.EncPart.Cipher)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT AS-REP decrypt: %w", krberrors.ErrIntegrity)
	}
	if len(plainReply) > 0 && plainReply[0] == 0x7a {
		plainReply = append([]byte(nil), plainReply...)
		plainReply[0] = 0x79
	}
	var part protocol.EncASRepPart
	if err := asn1.Unmarshal(plainReply, &part); err != nil {
		return fmt.Errorf("anonymous PKINIT AS-REP: %w", krberrors.ErrIntegrity)
	}
	expected, err := crypto.CF2(
		etype, kdcKey.KeyValue, replyKey,
		[]byte("PKINIT"), []byte("KEYEXCHANGE"),
	)
	if err != nil {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX derive: %w", krberrors.ErrIntegrity)
	}
	if part.Key.KeyType != reply.EncPart.EType ||
		len(part.Key.KeyValue) != len(expected) ||
		subtle.ConstantTimeCompare(part.Key.KeyValue, expected) != 1 {
		return fmt.Errorf("anonymous PKINIT PA-PKINIT-KX session key mismatch: %w", krberrors.ErrIntegrity)
	}
	return nil
}

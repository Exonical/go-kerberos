package client

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/internal/random"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
	"github.com/Exonical/go-kerberos/krb5/trace"
	"github.com/Exonical/go-kerberos/krb5/types"
)

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
	c.tracef("Getting initial credentials for %s", trace.Principal(clientPrincipal))
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
		return nil, fmt.Errorf("AS exchange: %w", krberr.ErrUnsupportedEType)
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
		methodData = c.sortPreferredPadata(clientPrincipal.Realm, methodData)
		etypeID, salt, params, err := preauth.SelectEType(methodData, clientPrincipal.Realm, clientPrincipal, registry, c.asRequestEnctypes())
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
		modulePA, handled, updatedKey, err := c.processClientPreauthModules(
			request, methodData, clientPrincipal, etypeID, key, nil, kerberosError)
		if err != nil {
			return nil, fmt.Errorf("AS exchange module preauthentication: %w", err)
		}
		if handled {
			request.PAData = appendClientPreauthCookie(modulePA, methodData)
			response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
			if err != nil {
				return nil, err
			}
			return c.decodeASRep(response, clientPrincipal, request.ReqBody.Nonce,
				updatedKey.KeyType, updatedKey.KeyValue, now)
		}
		etypeID = updatedKey.KeyType
		etype, err = registry.Get(etypeID)
		if err != nil {
			return nil, err
		}
		key = updatedKey.KeyValue
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
			request.PAData = append(protocol.MethodData{
				{PADataType: preauth.PADataSPAKE, PADataValue: responseDER},
			}, modulePA...)
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
		request.PAData = append(protocol.MethodData{timestamp}, modulePA...)
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

// ASExchangeServiceWithKey obtains initial credentials using a keytab entry
// for the client principal.
func (c *Client) ASExchangeServiceWithKey(ctx context.Context, clientPrincipal principal.Principal,
	entry keytab.Entry, service principal.Principal) (*Credentials, error) {
	candidates, err := c.serviceCandidates(ctx, service)
	if err != nil {
		return nil, err
	}
	for index := range candidates {
		if candidates[index].Realm == "" {
			candidates[index].Realm = clientPrincipal.Realm
		}
	}
	var last error
	for index, candidate := range candidates {
		result, err := c.asExchangeServiceOnceWithKey(ctx, clientPrincipal, entry, candidate, "")
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
	return c.asExchangeServiceOnceWithKey(ctx, clientPrincipal, keytab.Entry{}, service, password)
}

func (c *Client) asExchangeServiceOnceWithKey(ctx context.Context, clientPrincipal principal.Principal,
	entry keytab.Entry, service principal.Principal, password string) (*Credentials, error) {
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
		return nil, fmt.Errorf("AS service exchange: %w", krberr.ErrUnsupportedEType)
	}
	var initialKey []byte
	if entry.Key != nil {
		if entry.Enctype != initialETypeID {
			initialETypeID = entry.Enctype
			initialEType, err = registry.Get(initialETypeID)
			if err != nil {
				return nil, err
			}
		}
		initialKey = append([]byte(nil), entry.Key...)
	} else {
		initialSalt := []byte(clientPrincipal.Realm + strings.Join(clientPrincipal.Components, ""))
		initialKey, err = initialEType.StringToKey([]byte(password), initialSalt, nil)
		if err != nil {
			return nil, fmt.Errorf("AS service exchange string-to-key: %w", err)
		}
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
		methodData = c.sortPreferredPadata(clientPrincipal.Realm, methodData)
		etypeID, salt, params, err := preauth.SelectEType(methodData, clientPrincipal.Realm, clientPrincipal, registry, c.asRequestEnctypes())
		if err != nil {
			return nil, err
		}
		etype, err := registry.Get(etypeID)
		if err != nil {
			return nil, err
		}
		var key []byte
		if entry.Key != nil {
			if entry.Enctype != etypeID {
				return nil, fmt.Errorf("AS service exchange keytab entry enctype %d does not match KDC enctype %d", entry.Enctype, etypeID)
			}
			key = append([]byte(nil), entry.Key...)
		} else {
			key, err = etype.StringToKey([]byte(password), salt, params)
			if err != nil {
				return nil, fmt.Errorf("AS service exchange string-to-key: %w", err)
			}
		}
		modulePA, handled, updatedKey, err := c.processClientPreauthModules(
			request, methodData, clientPrincipal, etypeID, key, nil, kerberosError)
		if err != nil {
			return nil, fmt.Errorf("AS service exchange module preauthentication: %w", err)
		}
		if handled {
			request.PAData = appendClientPreauthCookie(modulePA, methodData)
			response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
			if err != nil {
				return nil, err
			}
			return c.decodeASRepForService(response, clientPrincipal, service,
				request.ReqBody.Nonce, updatedKey.KeyType, updatedKey.KeyValue, now)
		}
		etypeID = updatedKey.KeyType
		etype, err = registry.Get(etypeID)
		if err != nil {
			return nil, err
		}
		key = updatedKey.KeyValue
		timestamp, err := preauth.BuildEncryptedTimestamp(etype, key, now, 0)
		if err != nil {
			return nil, err
		}
		request.PAData = append(protocol.MethodData{timestamp}, modulePA...)
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
		return nil, fmt.Errorf("FAST AS exchange: %w", krberr.ErrUnsupportedEType)
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
		fastReply.PAData = c.sortPreferredPadata(clientPrincipal.Realm, fastReply.PAData)
		etypeID, salt, params, err := preauth.SelectEType(fastReply.PAData, clientPrincipal.Realm, clientPrincipal, registry, c.asRequestEnctypes())
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
		armorKey := &protocol.EncryptionKey{
			KeyType: armor.EType.ID(), KeyValue: append([]byte(nil), armor.Key...),
		}
		modulePA, handled, updatedKey, err := c.processClientPreauthModules(
			request, fastReply.PAData, clientPrincipal, etypeID, clientKey,
			armorKey, kerberosError)
		if err != nil {
			return nil, fmt.Errorf("FAST AS exchange module preauthentication: %w", err)
		}
		if handled {
			retryPAData := appendClientPreauthCookie(modulePA, fastReply.PAData)
			fastData, err = armor.WrapASReq(request.ReqBody, retryPAData)
			if err != nil {
				return nil, err
			}
			request.PAData = protocol.MethodData{fastData}
			response, err = c.roundTrip(ctx, clientPrincipal.Realm, request)
			if err != nil {
				return nil, err
			}
			return c.decodeFASTASRep(response, clientPrincipal, request.ReqBody.Nonce,
				updatedKey.KeyType, updatedKey.KeyValue, armor, now)
		}
		etypeID = updatedKey.KeyType
		etype, err = registry.Get(etypeID)
		if err != nil {
			return nil, err
		}
		var retryPA protocol.PAData
		if challengePA := preauth.FindPAData(fastReply.PAData, preauth.PADataEncryptedChallenge); challengePA != nil {
			retryPA, err = preauth.BuildEncryptedChallengeWithKeyEType(
				armor.EType, armor.Key, etype, updatedKey.KeyValue, now)
		} else {
			retryPA, err = preauth.BuildEncryptedTimestamp(etype, updatedKey.KeyValue, now, 0)
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
		return c.decodeFASTASRep(response, clientPrincipal, request.ReqBody.Nonce,
			etypeID, updatedKey.KeyValue, armor, now)
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
	if fastReply.Finished != nil {
		clientPrincipal = principalFromProtocol(fastReply.Finished.CName)
		clientPrincipal.Realm = fastReply.Finished.CRealm
		reply.CRealm = fastReply.Finished.CRealm
		reply.CName = fastReply.Finished.CName
	}
	if fastReply.Finished != nil {
		data, err = asn1.Marshal(reply)
		if err != nil {
			return nil, fmt.Errorf("FAST AS exchange reply: %w", err)
		}
	}
	return c.decodeASRep(data, clientPrincipal, nonce, replyKey.KeyType, replyKey.KeyValue, now)
}

func errorMethodData(value *krberr.KRBError) protocol.MethodData {
	if value == nil || len(value.ErrorData()) == 0 {
		return nil
	}
	var data protocol.MethodData
	if asn1.Unmarshal(value.ErrorData(), &data) != nil {
		return nil
	}
	return data
}

func (c *Client) processClientPreauthModules(request protocol.ASReq,
	methodData protocol.MethodData, clientPrincipal principal.Principal,
	etypeID int32, key []byte, armorKey *protocol.EncryptionKey,
	previousError *krberr.KRBError) (protocol.MethodData, bool, protocol.EncryptionKey, error) {
	if c == nil || len(c.PreauthModules) == 0 {
		return nil, false, protocol.EncryptionKey{
			KeyType: etypeID, KeyValue: append([]byte(nil), key...),
		}, nil
	}
	bodyDER, err := asn1.Marshal(request.ReqBody)
	if err != nil {
		return nil, false, protocol.EncryptionKey{}, fmt.Errorf("marshal request body: %w", err)
	}
	moduleContext := &preauth.ClientRequestContext{
		Client:      clientPrincipal,
		Request:     &request,
		RequestBody: bodyDER,
		EType:       etypeID,
		ArmorKey:    armorKey,
		State:       make(map[string]any),
		ASKey:       protocol.EncryptionKey{KeyType: etypeID, KeyValue: append([]byte(nil), key...)},
		HasASKey:    true,
	}
	info := preauth.ASReqInfo{
		Client:        clientPrincipal,
		Request:       request,
		RequestBody:   bodyDER,
		PreviousError: previousError,
	}
	var answers protocol.MethodData
	for _, infoPhase := range []bool{true, false} {
		for _, pa := range methodData {
			if clientBuiltinPAType(pa.PADataType) {
				continue
			}
			for _, module := range c.PreauthModules {
				if module == nil || !claimsPAType(module.PATypes(), pa.PADataType) {
					continue
				}
				flags := module.Flags(pa.PADataType)
				if (flags&preauth.PAInfo != 0) != infoPhase {
					continue
				}
				result, processErr := module.Process(moduleContext, pa, info)
				if processErr != nil {
					return nil, false, protocol.EncryptionKey{}, fmt.Errorf("%s: %w", module.Name(), processErr)
				}
				answers = append(answers, result...)
				if !infoPhase && len(result) > 0 {
					updated, keyErr := moduleContext.GetASKey()
					if keyErr != nil {
						return nil, false, protocol.EncryptionKey{}, keyErr
					}
					return answers, true, updated, nil
				}
			}
		}
	}
	if moduleContext.HasASKey {
		key = moduleContext.ASKey.KeyValue
	}
	return answers, false, moduleContext.ASKey, nil
}

func claimsPAType(values []int32, typ int32) bool {
	for _, value := range values {
		if value == typ {
			return true
		}
	}
	return false
}

func appendClientPreauthCookie(data protocol.MethodData,
	methodData protocol.MethodData) protocol.MethodData {
	if cookie := preauth.FindPAData(methodData, preauth.PADataCookie); cookie != nil {
		data = append(data, *cookie)
	}
	return data
}

func clientBuiltinPAType(typ int32) bool {
	switch typ {
	case preauth.PADataEncryptedTimestamp, preauth.PADataEncryptedChallenge,
		preauth.PADataSPAKE, otp.PADataRequest, protocol.PADataPKASReq:
		return true
	default:
		return false
	}
}

func freshnessTokenFromError(value *krberr.KRBError) []byte {
	for _, pa := range errorMethodData(value) {
		if pa.PADataType == pkinit.PADataASFreshness {
			return append([]byte(nil), pa.PADataValue...)
		}
	}
	return nil
}

func findPKINITDHParameters(value *krberr.KRBError) []byte {
	if value == nil || value.Code != krberr.KDCErrDHKeyParameters || len(value.ErrorData()) == 0 {
		return nil
	}
	var data protocol.TypedData
	if asn1.Unmarshal(value.ErrorData(), &data) != nil {
		return nil
	}
	for _, item := range data {
		if item.DataType == pkinit.PADataTDHParameters {
			return append([]byte(nil), item.DataValue...)
		}
	}
	return nil
}

func retryPKINITDHParameters(value *krberr.KRBError, retries int, client *pkinit.Client) (bool, error) {
	if value == nil || value.Code != krberr.KDCErrDHKeyParameters {
		return false, nil
	}
	if retries >= 2 {
		return false, nil
	}
	td := findPKINITDHParameters(value)
	if td == nil {
		return false, nil
	}
	if err := client.SelectDHParameters(td); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) newASReq(clientPrincipal principal.Principal, now time.Time) (protocol.ASReq, error) {
	return c.newASReqForService(clientPrincipal, principal.Principal{
		Realm: clientPrincipal.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", clientPrincipal.Realm},
	}, now)
}

func (c *Client) newASReqForService(clientPrincipal, service principal.Principal, now time.Time) (protocol.ASReq, error) {
	nonceBytes := make([]byte, 4)
	if _, err := io.ReadFull(random.Reader(), nonceBytes); err != nil {
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
	options := types.KDCRenewableOK | c.defaultKDCOptions(clientPrincipal.Realm)
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
			Till:      types.KerberosTime{Time: now.Add(lifetime), Present: true},
			Nonce:     randomNonce(nonceBytes),
			Addresses: c.requestAddresses(clientPrincipal.Realm),
			EType:     c.asRequestEnctypes(),
		},
	}, nil
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
		return nil, fmt.Errorf("AS exchange AS-REP enctype %d: %w", reply.EncPart.EType, krberr.ErrUnsupportedEType)
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
		return nil, fmt.Errorf("AS exchange: %w", krberr.ErrClockSkew)
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

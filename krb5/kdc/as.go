package kdc

import (
	stderrors "errors"
	"io"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/internal/random"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/spake"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func (s *Server) handleASReq(request protocol.ASReq, raw []byte, remoteAddr string) []byte {
	state := newASAuditState(request)
	state.RemoteAddr = remoteAddr
	response := s.handleASReqCore(request, raw, &state)
	state.SuccessState(response)
	if !isKRBErrorResponse(response) {
		state.Stage = AuditEncryptReply
	}
	s.auditAS(!isKRBErrorResponse(response), state)
	return response
}

func (s *Server) handleASReqCore(request protocol.ASReq, raw []byte, auditState *AuditState) []byte {
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
	if s.restrictAnonymous(clientName, serviceName) {
		return s.errorResponse(kdcErrPolicy, request.ReqBody.SName)
	}
	serviceRecord, ok, err := s.DB.Lookup(serviceName)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	if !ok {
		return s.errorResponse(kdcErrSPrincipal, request.ReqBody.SName)
	}
	if auditState != nil {
		auditState.Client = clientName
		auditState.Service = serviceName
		auditState.Stage = AuditServicePrincipal
	}
	if code := s.validateASAccount(clientRecord, serviceRecord, request.ReqBody.KDCOptions); code != 0 {
		return s.errorResponse(code, request.ReqBody.SName)
	}
	if auditState != nil {
		auditState.Stage = AuditValidatePolicy
	}
	requiresHWAuth := clientRecord.Flags&kdb.RequiresHWAuth != 0
	customPreauthRequired := s.customPreauthRequired()
	preauthRequired := !s.DisablePreauth || customPreauthRequired ||
		clientRecord.Flags&(kdb.RequiresPreAuth|kdb.RequiresHWAuth) != 0
	timestampPA := findPA(request.PAData, paEncTimestamp)
	spakePA := findPA(request.PAData, paSPAKE)
	pkinitPA := findPA(request.PAData, protocol.PADataPKASReq)
	otpPA := findPA(request.PAData, otp.PADataRequest)
	otpEnabled := s.OTPValidator != nil || s.OTPVerifier != nil
	var etypeID int32
	var clientKey, serviceKey kdb.Key
	if pkinitPA != nil || anonymousRequest || otpEnabled {
		etypeID, serviceKey, ok = selectPKINITServiceKey(request.ReqBody.EType, serviceRecord)
	} else {
		etypeID, clientKey, serviceKey, ok = s.selectASKeys(request.ReqBody.EType, clientRecord, serviceRecord)
		if !ok && (len(s.PreauthModules) > 0 ||
			(s.PKINITCertificate != nil && s.PKINITSigner != nil && s.PKINITClientCAs != nil)) {
			etypeID, serviceKey, ok = selectPKINITServiceKey(request.ReqBody.EType, serviceRecord)
		}
	}
	if !ok {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	rock := &PreauthRock{
		Client:        clientName,
		Service:       serviceName,
		ClientEntry:   &clientRecord,
		ClientDBEntry: &clientRecord,
		Request:       request,
		RequestBody:   marshalDER(request.ReqBody),
		State:         make(map[string]any),
	}
	if clientKey.Enctype != 0 {
		rock.ClientKeys = []kdb.Key{clientKey}
	}
	seenClientKeys := make(map[int32]bool, len(rock.ClientKeys))
	for _, key := range rock.ClientKeys {
		seenClientKeys[key.Enctype] = true
	}
	for _, requestedEType := range request.ReqBody.EType {
		key, exists := clientRecord.Keys[requestedEType]
		if !exists || seenClientKeys[requestedEType] {
			continue
		}
		key.Enctype = requestedEType
		rock.ClientKeys = append(rock.ClientKeys, key)
		seenClientKeys[requestedEType] = true
	}
	if armor != nil {
		rock.ArmorKey = &protocol.EncryptionKey{
			KeyType: armor.etype.ID(), KeyValue: append([]byte(nil), armor.key...),
		}
	}
	customResult, customSuccesses, customErr :=
		s.verifyPreauthModules(rock, request.PAData)
	if customErr != nil {
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
	}
	if customResult != nil && customResult.Authenticated {
		if response := s.customPreauthFailure(rock, request, armor); response != nil {
			return response
		}
		if requiresHWAuth && !customResult.HardwareAuthenticated {
			if armor != nil {
				return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
					nil, request.ReqBody.Nonce, armor)
			}
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		if clientKey.Enctype == 0 && customResult.ReplacedReplyKey == nil {
			if armor != nil {
				return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
					nil, request.ReqBody.Nonce, armor)
			}
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		s.recordPreauthSuccess(clientName, &clientRecord)
		if auditState != nil {
			auditState.PreauthType = customResult.PreauthType
			auditState.AuthIndicators = append([]string(nil), customResult.AuthIndicators...)
			auditState.Stage = AuditIssueTicket
		}
		replyPAs := protocol.MethodData(nil)
		for _, success := range customSuccesses {
			returner, ok := success.module.(ReturnPadata)
			if !ok {
				continue
			}
			data, err := returner.ReturnPadata(rock, success.result)
			if err != nil {
				if armor != nil {
					return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
						nil, request.ReqBody.Nonce, armor)
				}
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			replyPAs = append(replyPAs, data...)
		}
		var replyKey *kdb.Key
		if customResult.ReplacedReplyKey != nil {
			key := *customResult.ReplacedReplyKey
			replyKey = &key
		}
		return s.buildASRepWithPreauth(request, clientName, clientRecord,
			serviceName, serviceRecord, etypeID, clientKey, serviceKey, armor,
			true, replyKey, replyPAs, customResult.AuthIndicators,
			customResult.HardwareAuthenticated, customResult.AuthorizationData, auditState)
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
	if otpEnabled && !requiresHWAuth && !anonymousRequest && pkinitPA == nil && timestampPA == nil &&
		spakePA == nil && otpPA == nil && preauthRequired {
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
		if _, err := io.ReadFull(random.Reader(), cookie); err != nil {
			return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
		}
		methodData = append(methodData, protocol.PAData{
			PADataType: fast.PAFXCookie, PADataValue: cookie,
		})
		return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName,
			marshalDER(methodData), request.ReqBody.Nonce, armor)
	}
	if otpPA != nil {
		if armor == nil || (s.OTPValidator == nil && s.OTPVerifier == nil) {
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
		var indicators []string
		var verifyErr error
		if s.OTPVerifier != nil {
			indicators, verifyErr = s.OTPVerifier.VerifyOTP(clientName, otpRequest.OTPValue)
		} else {
			verifyErr = s.OTPValidator(clientName, string(otpRequest.OTPValue))
			indicators = append([]string(nil), s.OTPIndicators...)
		}
		if verifyErr != nil {
			s.recordPreauthFailure(clientName, &clientRecord)
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		if requiresHWAuth {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		s.recordPreauthSuccess(clientName, &clientRecord)
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		if auditState != nil {
			auditState.PreauthType = "otp"
			auditState.AuthIndicators = append([]string(nil), indicators...)
		}
		if auditState != nil {
			auditState.Stage = AuditIssueTicket
		}
		if response := s.customPreauthFailure(rock, request, armor); response != nil {
			return response
		}
		replyKey := &kdb.Key{Enctype: armor.etype.ID(), Key: append([]byte(nil), armor.key...)}
		return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
			armor.etype.ID(), clientKey, serviceKey, armor, true, replyKey, nil, indicators, auditState)
	}
	if otpEnabled && !requiresHWAuth && armor == nil && !anonymousRequest {
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
		if s.passwordExpiredForService(clientRecord, serviceRecord) {
			return s.fastErrorResponse(kdcErrKeyExpired, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		if requiresHWAuth {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		s.recordPreauthSuccess(clientName, &clientRecord)
		if auditState != nil {
			auditState.PreauthType = "enc-challenge"
			if s.EncryptedChallengeIndicator != "" {
				auditState.AuthIndicators = []string{s.EncryptedChallengeIndicator}
			}
		}
		if auditState != nil {
			auditState.Stage = AuditIssueTicket
		}
		if response := s.customPreauthFailure(rock, request, armor); response != nil {
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
			configuredIndicator(s.EncryptedChallengeIndicator), auditState)
	}
	if !anonymousRequest && !requiresHWAuth && s.EnableSPAKE && spakePA == nil && timestampPA == nil &&
		pkinitPA == nil && preauthRequired {
		methodData := protocol.MethodData{
			{PADataType: paEncTimestamp},
			{PADataType: paSPAKE},
		}
		if clientKey.Enctype != 0 {
			methodData = append(methodData, protocol.PAData{PADataType: 19, PADataValue: marshalDER(protocol.ETypeInfo2{{
				EType: etypeID, Salt: stringPointer(principalSalt(clientKey, clientName)),
			}})})
		}
		methodData = append(methodData, s.preauthModuleHints(rock)...)
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData), request.ReqBody.Nonce, armor)
		}
		return s.errorResponseWithData(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData))
	}
	selectedSPAKEGroup := s.selectSPAKEGroup(spakePA)
	if !anonymousRequest && !requiresHWAuth && selectedSPAKEGroup != 0 &&
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
		methodData = append(methodData, s.preauthModuleHints(rock)...)
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
			if s.passwordExpiredForService(clientRecord, serviceRecord) {
				return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
			}
			if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
				return response
			}
			if requiresHWAuth {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			s.recordPreauthSuccess(clientName, &clientRecord)
			if auditState != nil {
				auditState.PreauthType = "spake"
				auditState.AuthIndicators = append([]string(nil), s.SPAKEPreauthIndicators...)
			}
			if auditState != nil {
				auditState.Stage = AuditIssueTicket
			}
			if response := s.customPreauthFailure(rock, request, armor); response != nil {
				return response
			}
			return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
				etypeID, clientKey, serviceKey, armor, true, &kdb.Key{Enctype: etypeID, Key: k0}, nil,
				append([]string(nil), s.SPAKEPreauthIndicators...), auditState)
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
		var hwauth bool
		var accepted bool
		var certIndicators []string
		if anonymousRequest {
			if verified.Signed {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
		} else {
			if !verified.Signed {
				return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
			}
			if err := pkinit.VerifyClientCertificateTrust(verified.Certificate,
				s.PKINITClientCAs, verified.Intermediates...); err != nil {
				return s.errorResponse(kdcErrClientNotTrusted, request.ReqBody.SName)
			}
			accepted, hwauth, certIndicators, err = s.authorizeCertificate(
				verified.Certificate, requestClientName, &clientRecord)
			if err != nil {
				code := int32(kdcErrClientNotTrusted)
				var certErr *CertAuthError
				if stderrors.As(err, &certErr) {
					code = certErr.Code
				}
				return s.errorResponse(code, request.ReqBody.SName)
			}
			if !accepted {
				return s.errorResponse(kdcErrClientNotTrusted, request.ReqBody.SName)
			}
		}
		if requiresHWAuth && !hwauth {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		if s.passwordExpiredForService(clientRecord, serviceRecord) {
			return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
		}
		s.recordPreauthSuccess(clientName, &clientRecord)
		if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
			return response
		}
		if auditState != nil {
			auditState.PreauthType = "pkinit"
			if !anonymousRequest {
				auditState.AuthIndicators = append(append([]string(nil), s.PKINITIndicators...), certIndicators...)
			}
		}
		if auditState != nil {
			auditState.Stage = AuditIssueTicket
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
		paRep, replyKey, err := pkinit.BuildPAASRepWithKDFAndMinBits(verified.PublicValue, etypeID,
			request.ReqBody.Nonce, s.PKINITCertificate, s.PKINITSigner, selectedKDF,
			kdfClientName, serviceName, requestDER, s.PKINITDHMinBits)
		if err != nil {
			var policyErr *pkinit.GroupPolicyError
			if stderrors.As(err, &policyErr) {
				td, tdErr := pkinit.MarshalDHParameters(policyErr.Supported)
				if tdErr == nil {
					typedData := protocol.TypedData{{DataType: pkinit.PADataTDHParameters, DataValue: td}}
					return s.errorResponseWithData(kdcErrDHKeyParameters, request.ReqBody.SName,
						marshalDER(typedData))
				}
			}
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
		replyEncryptionKey := &kdb.Key{Enctype: etypeID, Key: replyKey}
		replyPAs := protocol.MethodData{paRep}
		if response := s.customPreauthFailure(rock, request, armor); response != nil {
			return response
		}
		return s.buildASRepWithHWAuth(request, clientName, clientRecord, serviceName, serviceRecord,
			etypeID, clientKey, serviceKey, armor, true, replyEncryptionKey, replyPAs,
			func() []string {
				if anonymousRequest {
					return nil
				}
				return append(append([]string(nil), s.PKINITIndicators...), certIndicators...)
			}(), hwauth, auditState)
	}
	if timestampPA == nil {
		if !preauthRequired {
			if s.passwordExpiredForService(clientRecord, serviceRecord) {
				return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
			}
			if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
				return response
			}
			if auditState != nil {
				auditState.Stage = AuditIssueTicket
			}
			return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
				etypeID, clientKey, serviceKey, armor, false, nil, nil, nil, auditState)
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
		methodData = append(methodData, s.preauthModuleHints(rock)...)
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
	if s.passwordExpiredForService(clientRecord, serviceRecord) {
		if armor != nil {
			return s.fastErrorResponse(kdcErrKeyExpired, request.ReqBody.SName, nil, request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(kdcErrKeyExpired, request.ReqBody.SName)
	}
	if response := s.authorizationError(clientName, serviceName, true, armor); response != nil {
		return response
	}
	if requiresHWAuth {
		if armor != nil {
			return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
				nil, request.ReqBody.Nonce, armor)
		}
		return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
	}
	s.recordPreauthSuccess(clientName, &clientRecord)
	if auditState != nil {
		auditState.PreauthType = "enc-timestamp"
	}
	if auditState != nil {
		auditState.Stage = AuditIssueTicket
	}
	if response := s.customPreauthFailure(rock, request, armor); response != nil {
		return response
	}
	return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord,
		etypeID, clientKey, serviceKey, armor, true, nil, nil, nil, auditState)
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

func (s *Server) buildASRep(request protocol.ASReq, clientName principal.Principal, clientRecord kdb.PrincipalRecord, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, clientKey, serviceKey kdb.Key, armor *fastContext, preauthenticated bool, replyEncryptionKey *kdb.Key, replyPAs protocol.MethodData, assertedIndicators []string, auditStates ...*AuditState) []byte {
	return s.buildASRepWithPreauth(request, clientName, clientRecord, serviceName,
		serviceRecord, etypeID, clientKey, serviceKey, armor, preauthenticated,
		replyEncryptionKey, replyPAs, assertedIndicators, false, nil, auditStates...)
}

func (s *Server) buildASRepWithHWAuth(request protocol.ASReq, clientName principal.Principal, clientRecord kdb.PrincipalRecord, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, clientKey, serviceKey kdb.Key, armor *fastContext, preauthenticated bool, replyEncryptionKey *kdb.Key, replyPAs protocol.MethodData, assertedIndicators []string, hwAuthenticated bool, auditStates ...*AuditState) []byte {
	return s.buildASRepWithPreauth(request, clientName, clientRecord, serviceName,
		serviceRecord, etypeID, clientKey, serviceKey, armor, preauthenticated,
		replyEncryptionKey, replyPAs, assertedIndicators, hwAuthenticated, nil, auditStates...)
}

func (s *Server) buildASRepWithPreauth(request protocol.ASReq, clientName principal.Principal, clientRecord kdb.PrincipalRecord, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, clientKey, serviceKey kdb.Key, armor *fastContext, preauthenticated bool, replyEncryptionKey *kdb.Key, replyPAs protocol.MethodData, assertedIndicators []string, hwAuthenticated bool, preauthAuthData protocol.AuthorizationData, auditStates ...*AuditState) []byte {
	if response := s.requireAuthError(serviceRecord, assertedIndicators, armor, request.ReqBody.SName); response != nil {
		return response
	}
	var auditState *AuditState
	if len(auditStates) > 0 {
		auditState = auditStates[0]
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	sessionValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(random.Reader(), sessionValue); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	now := s.now().UTC().Truncate(time.Second)
	authTime := types.KerberosTime{Time: now, Present: true}
	startTime := authTime
	flags := types.TicketInitial
	if preauthenticated {
		flags |= types.TicketPreAuthent
	}
	if hwAuthenticated {
		flags |= types.TicketHWAuthent
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
	applyPrincipalFlagPolicy(&flags, &clientRecord, &serviceRecord)
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
	endTime := s.ticketEndFromRecords(request.ReqBody.Till, startTime.Time,
		&clientRecord, &serviceRecord)
	renewTill := s.renewTillRecords(request.ReqBody.KDCOptions, request.ReqBody.RTime,
		request.ReqBody.Till, startTime.Time, endTime.Time, &clientRecord, &serviceRecord)
	if err := s.applyASPolicies(request, clientName, serviceName, clientRecord,
		serviceRecord, assertedIndicators, now, &endTime, &renewTill, auditState); err != nil {
		if armor != nil {
			return s.fastErrorResponseWithText(policyErrorCode(err), request.ReqBody.SName,
				nil, armor.nonce, armor, err.Error())
		}
		return s.errorResponseWithText(policyErrorCode(err), request.ReqBody.SName, err.Error())
	}
	if s.Policy != nil && !s.Policy.AllowRenewable {
		renewTill = nil
	}
	if clientRecord.Flags&kdb.DisallowRenewable != 0 ||
		serviceRecord.Flags&kdb.DisallowRenewable != 0 {
		flags &^= types.TicketRenewable
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
	s.handleAuthData(&AuthDataRequest{
		Flags:     AuthDataASReq,
		Client:    clientName,
		Server:    serviceName,
		ClientKey: &clientKey,
		ServerKey: &serviceKey,
		Request:   request,
		Reply:     &ticketPart,
	})
	if len(preauthAuthData) > 0 {
		ticketPart.AuthorizationData = append(ticketPart.AuthorizationData, preauthAuthData...)
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
		if _, err := crypto.NewRegistry().Get(replyKey.Enctype); err != nil {
			return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
		}
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
		EncPart: protocol.EncryptedData{EType: replyKey.Enctype, Cipher: replyCipher},
	}
	if len(replyPAs) > 0 {
		reply.PAData = replyPAs
	}
	if armor == nil {
		return marshalDER(reply)
	}
	return s.wrapFASTASRep(reply, replyKey, armor, replyPAs)
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

func (s *Server) validateASAccount(client, service kdb.PrincipalRecord, options types.KDCOptions) int32 {
	now := s.now()
	if !client.Expiration.IsZero() && now.After(client.Expiration) {
		return kdcErrNameExpired
	}
	if s.passwordExpiredForService(client, service) {
		return kdcErrKeyExpired
	}
	if !service.Expiration.IsZero() && now.After(service.Expiration) {
		return kdcErrServiceExpired
	}
	if client.Flags&kdb.DisallowAllTickets != 0 {
		return kdcErrClientRevoked
	}
	if service.Flags&kdb.DisallowAllTickets != 0 {
		return kdcErrSPrincipal
	}
	if service.Flags&kdb.DisallowServer != 0 {
		return kdcErrMustUseUser2User
	}
	if client.Flags&kdb.RequiresPWChange != 0 &&
		service.Flags&kdb.PWChangeService == 0 {
		return kdcErrKeyExpired
	}
	if options&(types.KDCAllowPostdate|types.KDCPostdated) != 0 &&
		(client.Flags&kdb.DisallowPostdated != 0 || service.Flags&kdb.DisallowPostdated != 0) {
		return kdcErrCannotPostdate
	}
	return 0
}

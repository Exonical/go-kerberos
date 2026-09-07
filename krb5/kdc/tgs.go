// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/internal/random"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func (s *Server) tgsErrorResponse(armor *fastContext, code int32, service *protocol.PrincipalName) []byte {
	if armor == nil {
		return s.errorResponse(code, service)
	}
	return s.fastErrorResponse(code, service, nil, armor.nonce, armor)
}

func (s *Server) handleTGSReq(request protocol.TGSReq, raw []byte, remoteAddr string) []byte {
	state := newTGSAuditState(request)
	state.RemoteAddr = remoteAddr
	response := s.handleTGSReqCore(request, raw, &state)
	state.SuccessState(response)
	if !isKRBErrorResponse(response) {
		state.Stage = AuditEncryptReply
	}
	s.auditTGS(!isKRBErrorResponse(response), state)
	return response
}

func (s *Server) handleTGSReqCore(request protocol.TGSReq, raw []byte, auditState *AuditState) []byte {
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
	if auditState != nil {
		auditState.InputTicketID = auditID(marshalDER(apRequest.Ticket))
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
	if auditState != nil {
		auditState.RequestType = classifyTGSRequest(request)
		auditState.Client = principalFromProtocol(ticketPart.CName, ticketPart.CRealm)
		if request.ReqBody.SName != nil {
			auditState.Service = principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
		}
	}
	requestedServiceName := principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	var verifiedHeaderCAMMACElements protocol.AuthorizationData
	if elements, elementsErr := cammac.ProtectedElements(ticketPart.AuthorizationData); elementsErr != nil {
		if !stderrors.Is(elementsErr, cammac.ErrNotFound) {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		}
	} else if localKDCKey, ok := s.freshnessKey(nil); ok {
		verifyErr := cammac.VerifyKDC(ticketPart.AuthorizationData, ticketPart,
			protocol.EncryptionKey{KeyType: localKDCKey.Enctype, KeyValue: localKDCKey.Key})
		if verifyErr == nil {
			verifiedHeaderCAMMACElements = elements
		} else if !stderrors.Is(verifyErr, krberr.ErrIntegrity) {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		} else if ticketPart.AuthorizationData, err = stripCAMMAC(ticketPart.AuthorizationData); err != nil {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		}
	} else if ticketPart.AuthorizationData, err = stripCAMMAC(ticketPart.AuthorizationData); err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
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
	if record, exists, lookupErr := s.DB.Lookup(ticketClient); lookupErr != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	} else if exists {
		if !record.Expiration.IsZero() && s.now().After(record.Expiration) {
			return s.tgsErrorResponse(armor, kdcErrNameExpired, request.ReqBody.SName)
		}
		if record.Flags&kdb.DisallowAllTickets != 0 {
			return s.tgsErrorResponse(armor, kdcErrClientRevoked, request.ReqBody.SName)
		}
	}
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
	if options&types.KDCForwarded != 0 &&
		ticketPart.Flags&types.TicketForwardable == 0 {
		return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
	}
	if options&types.KDCProxy != 0 &&
		ticketPart.Flags&types.TicketProxiable == 0 {
		return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
	}
	serviceName := requestedServiceName
	if options&(types.KDCRenew|types.KDCValidate) != 0 {
		serviceName = principalFromProtocol(apRequest.Ticket.SName, apRequest.Ticket.Realm)
	} else if serviceName.Realm != s.Realm {
		if !s.referralAllowed(requestedServiceName,
			options&types.KDCCanonicalize != 0,
			options&types.KDCEncTktInSkey != 0) {
			return s.tgsErrorResponse(armor, kdcErrServiceUnknown, request.ReqBody.SName)
		}
		serviceName = principal.Principal{
			Realm: s.Realm, NameType: principal.NTSrvInstance,
			Components: []string{"krbtgt", request.ReqBody.Realm},
		}
	}
	if s.restrictAnonymous(ticketClient, serviceName) {
		return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
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
	if auditState != nil {
		auditState.Stage = AuditServicePrincipal
	}
	if !serviceRecord.Expiration.IsZero() && s.now().After(serviceRecord.Expiration) {
		return s.tgsErrorResponse(armor, kdcErrServiceExpired, request.ReqBody.SName)
	}
	if serviceRecord.Flags&kdb.DisallowAllTickets != 0 {
		return s.tgsErrorResponse(armor, kdcErrSPrincipal, request.ReqBody.SName)
	}
	if serviceRecord.Flags&kdb.DisallowServer != 0 &&
		options&types.KDCEncTktInSkey == 0 {
		return s.tgsErrorResponse(armor, kdcErrMustUseUser2User, request.ReqBody.SName)
	}
	if options&types.KDCRenewable != 0 && serviceRecord.Flags&kdb.DisallowRenewable != 0 {
		return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
	}
	if options&types.KDCAllowPostdate != 0 && serviceRecord.Flags&kdb.DisallowPostdated != 0 {
		return s.tgsErrorResponse(armor, kdcErrCannotPostdate, request.ReqBody.SName)
	}
	if options&types.KDCEncTktInSkey != 0 && serviceRecord.Flags&kdb.DisallowDupSkey != 0 {
		return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
	}
	if serviceRecord.Flags&kdb.DisallowTGTBased != 0 &&
		len(apRequest.Ticket.SName.NameString) > 0 &&
		apRequest.Ticket.SName.NameString[0] == "krbtgt" {
		return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
	}
	if serviceRecord.Flags&kdb.RequiresHWAuth != 0 &&
		ticketPart.Flags&types.TicketHWAuthent == 0 {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	if serviceRecord.Flags&kdb.RequiresPreAuth != 0 &&
		ticketPart.Flags&types.TicketPreAuthent == 0 {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	if auditState != nil {
		auditState.Stage = AuditValidatePolicy
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
		if auditState != nil {
			user := principalFromProtocol(*id.CName, id.CRealm)
			auditState.S4U2SelfUser = &user
		}
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
		if auditState != nil {
			user := principalFromProtocol(*id.CName, id.CRealm)
			auditState.S4U2SelfUser = &user
		}
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
		if code := s.validateS4UClient(record); code != 0 {
			return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
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
		if auditState != nil {
			auditState.EvidenceTicketID = auditID(marshalDER(evidence))
		}
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
		if key, ok := s.freshnessKey(nil); ok {
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
		privKey, ok := s.pacPrivsvrKey()
		if !ok {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		privEType, err := crypto.NewRegistry().Get(privKey.Enctype)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		evidencePAC, err := pac.FromTicket(evidencePart,
			pac.Key{EType: evidenceEType, Key: evidenceKey.Key},
			&pac.Key{EType: privEType, Key: privKey.Key})
		if err != nil {
			if stderrors.Is(err, pac.ErrNotFound) {
				return s.tgsErrorResponse(armor, kdcErrBadOption, request.ReqBody.SName)
			}
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		_, clientName, err := evidencePAC.ClientInfo()
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		clientValue, err := principal.Parse(clientName)
		if err != nil {
			return s.tgsErrorResponse(armor, krbAPErrBadIntegrity, request.ReqBody.SName)
		}
		client := *clientValue
		if clientRecord, found, lookupErr := s.DB.Lookup(client); lookupErr != nil {
			return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
		} else if found {
			if code := s.validateS4UClient(clientRecord); code != 0 {
				return s.tgsErrorResponse(armor, code, request.ReqBody.SName)
			}
		}
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
	if auditState != nil {
		auditState.Stage = AuditValidatePolicy
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
	if auditState != nil {
		if indicators, err := authIndicatorsFromElements(verifiedCAMMACElements); err == nil {
			auditState.AuthIndicators = append([]string(nil), indicators...)
		}
		auditState.Stage = AuditIssueTicket
	}
	return s.buildTGSRep(request, ticketPart, apRequest.Ticket, ticketKey, serviceName, serviceRecord, etypeID, serviceKey, replyKey, replyUsage, armor, issuedClient, s4uReplyPA, delegationEvidence, verifiedCAMMACElements, pacVerifyKey, u2uTicketKey, auditState, authenticator.SubKey)
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
	digest := md5.Sum(hashInput) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.crypto.use-of-md5 -- MS-PAC KERB_CHECKSUM_HMAC_MD5 mandates MD5
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
	case crypto.ChecksumCMACCamellia128:
		etypeID = crypto.EnctypeCamellia128
	case crypto.ChecksumCMACCamellia256:
		etypeID = crypto.EnctypeCamellia256
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
	case crypto.ChecksumCMACCamellia128:
		etypeID = crypto.EnctypeCamellia128
	case crypto.ChecksumCMACCamellia256:
		etypeID = crypto.EnctypeCamellia256
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

func (s *Server) buildTGSRep(request protocol.TGSReq, ticketPart protocol.EncTicketPart, headerTicket protocol.Ticket, headerKey kdb.Key, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, serviceKey kdb.Key, replyKey protocol.EncryptionKey, replyUsage uint32, armor *fastContext, issuedClient *principal.Principal, replyPA *protocol.PAData, delegationEvidence *principal.Principal, verifiedCAMMACElements protocol.AuthorizationData, pacVerifyKey *kdb.Key, u2uTicketKey *kdb.Key, auditState *AuditState, authenticatorSubKeys ...*protocol.EncryptionKey) []byte {
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.tgsErrorResponse(armor, 14, request.ReqBody.SName)
	}
	sessionValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(random.Reader(), sessionValue); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	now := s.now().UTC().Truncate(time.Second)
	var clientRecord *kdb.PrincipalRecord
	ticketClient := principalFromProtocol(ticketPart.CName, ticketPart.CRealm)
	if issuedClient != nil {
		ticketClient = *issuedClient
	}
	if record, ok, err := s.DB.Lookup(ticketClient); err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	} else if ok {
		clientRecord = &record
	}
	authIndicators, err := authIndicatorsFromElements(verifiedCAMMACElements)
	if err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
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
		endTime = s.ticketEndFromRecords(request.ReqBody.Till, start,
			clientRecord, &serviceRecord)
		renewTill = s.renewTillRecords(request.ReqBody.KDCOptions, request.ReqBody.RTime,
			request.ReqBody.Till, start, endTime.Time, clientRecord, &serviceRecord)
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
	applyPrincipalFlagPolicy(&flags, clientRecord, &serviceRecord)
	if (clientRecord != nil && clientRecord.Flags&kdb.DisallowRenewable != 0) ||
		serviceRecord.Flags&kdb.DisallowRenewable != 0 {
		flags &^= types.TicketRenewable
		renewTill = nil
	}
	if err := s.applyTGSPolicies(request, serviceName, serviceRecord, headerTicket, ticketPart,
		authIndicators, now, &endTime, &renewTill, auditState); err != nil {
		code := policyErrorCode(err)
		if armor != nil {
			return s.fastErrorResponseWithText(code, request.ReqBody.SName, nil,
				armor.nonce, armor, err.Error())
		}
		return s.errorResponseWithText(code, request.ReqBody.SName, err.Error())
	}
	addresses := append(protocol.HostAddresses(nil), ticketPart.CAddr...)
	if request.ReqBody.KDCOptions&(types.KDCForwarded|types.KDCProxy) != 0 {
		addresses = append(protocol.HostAddresses(nil), request.ReqBody.Addresses...)
	}
	tgtPart := ticketPart
	tgtAuthData := append(protocol.AuthorizationData(nil), ticketPart.AuthorizationData...)
	var authenticatorSubKey *protocol.EncryptionKey
	if len(authenticatorSubKeys) > 0 {
		authenticatorSubKey = authenticatorSubKeys[0]
	}
	requestAuthData, err := decryptTGSRequestAuthData(request, ticketPart.Key, authenticatorSubKey)
	if err != nil {
		return s.tgsErrorResponse(armor, kdcErrGeneric, request.ReqBody.SName)
	}
	if hasMandatoryKDCAuthData(requestAuthData) {
		return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
	}
	ticketPart = protocol.EncTicketPart{
		Flags:  flags,
		Key:    protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		CRealm: ticketPart.CRealm, CName: ticketPart.CName,
		Transited: ticketPart.Transited,
		AuthTime:  authTime, StartTime: startTime, EndTime: endTime, RenewTill: renewTill,
		CAddr: addresses, AuthorizationData: requestAuthData,
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
			if s.rejectBadTransit() {
				return s.tgsErrorResponse(armor, kdcErrPolicy, request.ReqBody.SName)
			}
		} else {
			flags |= types.TicketTransited
		}
	}
	ticketPart.Flags = flags
	s.handleAuthData(&AuthDataRequest{
		Flags:         AuthDataTGSReq,
		Client:        principalFromProtocol(ticketPart.CName, ticketPart.CRealm),
		Server:        serviceName,
		SubjectServer: delegationEvidence,
		ClientKey:     nil,
		ServerKey:     &serviceKey,
		SubjectKey:    pacVerifyKey,
		Request:       request,
		TGT:           &tgtPart,
		Reply:         &ticketPart,
	})
	ticketPart.AuthorizationData = append(ticketPart.AuthorizationData, tgtAuthData...)
	ticketEncryptionKey := serviceKey
	ticketKVNO := serviceKey.KVNO
	var ticketKVNOPtr = &ticketKVNO
	if u2uTicketKey != nil {
		ticketEncryptionKey = *u2uTicketKey
		ticketKVNO = 0
		// MIT's optional-zero KVNO encoder omits a zero value on U2U tickets.
		ticketKVNOPtr = nil
	}
	if findPA(request.PAData, protocol.PADataForUser) == nil &&
		findPA(request.PAData, protocol.PADataS4UX509User) == nil {
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

func (s *Server) validateS4UClient(client kdb.PrincipalRecord) int32 {
	now := s.now()
	if !client.Expiration.IsZero() && now.After(client.Expiration) {
		return kdcErrNameExpired
	}
	if client.Flags&kdb.DisallowAllTickets != 0 {
		return kdcErrClientRevoked
	}
	return 0
}

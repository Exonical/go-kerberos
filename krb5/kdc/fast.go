// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"io"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/internal/random"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func (s *Server) wrapFASTASRep(reply protocol.ASRep, clientKey kdb.Key, armor *fastContext, replyPAs protocol.MethodData) []byte {
	strengthenValue := make([]byte, armor.etype.KeySize())
	if _, err := io.ReadFull(random.Reader(), strengthenValue); err != nil {
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
	if _, err := io.ReadFull(random.Reader(), strengthenValue); err != nil {
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

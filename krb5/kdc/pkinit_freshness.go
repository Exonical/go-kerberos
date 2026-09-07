// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"encoding/binary"
	"sort"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const freshnessKeyUsage uint32 = 514

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

func (s *Server) freshnessKey(enctypes []int32) (kdb.Key, bool) {
	name := principal.Principal{
		Realm: s.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", s.Realm},
	}
	record, ok, err := s.DB.Lookup(name)
	if err != nil || !ok {
		return kdb.Key{}, false
	}
	if len(enctypes) == 0 {
		enctypes = []int32{
			crypto.EnctypeAES256SHA1,
			crypto.EnctypeAES128SHA1,
			crypto.EnctypeAES256SHA384,
			crypto.EnctypeAES128SHA256,
			crypto.EnctypeCamellia128,
			crypto.EnctypeCamellia256,
		}
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
	// Keep a usable key fallback for principals containing an enctype outside
	// the preferred list, but do not let map iteration choose unpredictably.
	available := make([]int32, 0, len(record.Keys))
	for enctype := range record.Keys {
		available = append(available, enctype)
	}
	sort.Slice(available, func(i, j int) bool { return available[i] < available[j] })
	for _, enctype := range available {
		key := record.Keys[enctype]
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

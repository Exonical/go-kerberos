package kdc

import (
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func decryptTGSRequestAuthData(request protocol.TGSReq, sessionKey protocol.EncryptionKey,
	subKey *protocol.EncryptionKey) (protocol.AuthorizationData, error) {
	encrypted := request.ReqBody.EncAuthorizationData
	if encrypted == nil || len(encrypted.Cipher) == 0 {
		return nil, nil
	}
	decrypt := func(key protocol.EncryptionKey, usage uint32) (protocol.AuthorizationData, error) {
		etype, err := crypto.NewRegistry().Get(key.KeyType)
		if err != nil {
			return nil, fmt.Errorf("TGS request authorization-data enctype: %w", err)
		}
		if len(key.KeyValue) == 0 {
			return nil, fmt.Errorf("TGS request authorization-data key is empty")
		}
		plain, err := etype.Decrypt(key.KeyValue, usage, encrypted.Cipher)
		if err != nil {
			return nil, fmt.Errorf("TGS request authorization-data decrypt: %w", err)
		}
		var result protocol.AuthorizationData
		if err := asn1.Unmarshal(plain, &result); err != nil {
			return nil, fmt.Errorf("TGS request authorization-data decode: %w", err)
		}
		return result, nil
	}
	result, err := decrypt(sessionKey, 4)
	if err == nil {
		return result, nil
	}
	if subKey != nil {
		return decrypt(*subKey, 5)
	}
	return nil, err
}

func hasMandatoryKDCAuthData(data protocol.AuthorizationData) bool {
	for _, entry := range data {
		if entry.ADType == protocol.ADMandatoryForKDC {
			return true
		}
		if entry.ADType != protocol.ADIfRelevant {
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(entry.ADData, &inner); err == nil &&
			hasMandatoryKDCAuthData(inner) {
			return true
		}
	}
	return false
}

// AuthDataASReq and AuthDataTGSReq identify the KDC request surface exposed
// to an authorization-data module.
const (
	AuthDataASReq  uint32 = 1
	AuthDataTGSReq uint32 = 2
)

// AuthDataRequest contains the request and mutable ticket state supplied to a
// KDC authorization-data module.
type AuthDataRequest struct {
	Flags         uint32
	Client        principal.Principal
	Server        principal.Principal
	SubjectServer *principal.Principal
	ClientKey     *kdb.Key
	ServerKey     *kdb.Key
	SubjectKey    *kdb.Key
	Request       any
	TGT           *protocol.EncTicketPart
	Reply         *protocol.EncTicketPart
}

// AuthDataModule adds authorization data to newly issued tickets. Module
// failures are logged and ignored, matching MIT's kdcauthdata contract.
type AuthDataModule interface {
	Name() string
	Handle(req *AuthDataRequest) error
}

func (s *Server) handleAuthData(req *AuthDataRequest) {
	if s == nil || req == nil || req.Reply == nil ||
		len(s.AuthDataModules) == 0 ||
		req.Reply.Flags&types.TicketAnonymous != 0 {
		return
	}
	for _, module := range s.AuthDataModules {
		if module == nil {
			continue
		}
		if err := module.Handle(req); err != nil && s.Logger != nil {
			s.Logger.Error("KDC authdata module %s: %v", module.Name(), err)
		}
	}
}

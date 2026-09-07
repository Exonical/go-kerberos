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

func authDataChecksumType(enctype int32) (int32, error) {
	switch enctype {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128, nil
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256, nil
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128, nil
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256, nil
	case crypto.EnctypeCamellia128:
		return crypto.ChecksumCMACCamellia128, nil
	case crypto.EnctypeCamellia256:
		return crypto.ChecksumCMACCamellia256, nil
	default:
		return 0, fmt.Errorf("unsupported authdata checksum enctype %d", enctype)
	}
}

// GreetAuthDataModule is the MIT sample kdcauthdata module. It emits a
// KDC-issued -42 authorization-data value for TGS requests.
type GreetAuthDataModule struct{}

func (GreetAuthDataModule) Name() string { return "greet" }

func (GreetAuthDataModule) Handle(req *AuthDataRequest) error {
	if req == nil || req.Reply == nil || req.Flags&AuthDataTGSReq == 0 {
		return nil
	}
	if len(req.Reply.Key.KeyValue) == 0 {
		return fmt.Errorf("greet: missing ticket session key")
	}
	value := []byte("Hello, KDC issued acceptor world!")
	elements := protocol.AuthorizationData{{
		ADType: -42,
		ADData: value,
	}}
	encoded, err := asn1.Marshal(elements)
	if err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(req.Reply.Key.KeyType)
	if err != nil {
		return err
	}
	checksum, err := etype.Checksum(req.Reply.Key.KeyValue, 19, encoded)
	if err != nil {
		return err
	}
	checksumType, err := authDataChecksumType(req.Reply.Key.KeyType)
	if err != nil {
		return err
	}
	issuer := protocol.PrincipalName{
		NameType:   int32(req.Server.NameType),
		NameString: append([]string(nil), req.Server.Components...),
	}
	realm := req.Server.Realm
	issued, err := asn1.Marshal(protocol.KDCIssued{
		Checksum: protocol.Checksum{
			ChecksumType: checksumType,
			Checksum:     checksum,
		},
		IRealm:   &realm,
		IName:    &issuer,
		Elements: elements,
	})
	if err != nil {
		return err
	}
	wrapped, err := asn1.Marshal(protocol.AuthorizationData{{
		ADType: protocol.ADKDCIssued,
		ADData: issued,
	}})
	if err != nil {
		return err
	}
	req.Reply.AuthorizationData = append(req.Reply.AuthorizationData,
		protocol.AuthorizationDataEntry{ADType: protocol.ADIfRelevant, ADData: wrapped})
	return nil
}

package client

import (
	"context"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	s4uRequestChecksumUsage = 26
	s4uReplyChecksumUsage   = 27
)

// S4U2Self obtains a service ticket to the service that owns tgt on behalf of
// user, using the certificate-style protocol transition padata described by
// [MS-SFU] section 2.2.1. PA-FOR-USER is deliberately omitted: its checksum is
// defined only for the RC4 HMAC-MD5 family, and MIT KDCs accept
// PA-S4U-X509-USER on its own. The returned credentials name the impersonated
// user as their client.
func (c *Client) S4U2Self(ctx context.Context, tgt *Credentials, user principal.Principal) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("S4U2Self: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("S4U2Self: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("S4U2Self: %w", err)
	}
	if tgt == nil || len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("S4U2Self: incomplete TGT")
	}
	if len(user.Components) == 0 || user.Realm == "" {
		return nil, fmt.Errorf("S4U2Self: invalid user principal")
	}
	service := tgt.Client
	if len(service.Components) == 0 {
		return nil, fmt.Errorf("S4U2Self: TGT has no client principal")
	}
	realm := tgt.Server.Realm
	if realm == "" {
		realm = service.Realm
	}
	if realm == "" {
		return nil, fmt.Errorf("S4U2Self: missing service realm")
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	etype, err := crypto.NewRegistry().Get(tgt.Key.KeyType)
	if err != nil {
		return nil, err
	}
	request, nonce, err := c.newTGSReq(tgt, service, realm, now, false)
	if err != nil {
		return nil, err
	}
	options := protocol.S4UOptionsUseReplyKeyUsage
	userID := protocol.S4UUserID{
		Nonce: nonce,
		CName: &protocol.PrincipalName{
			NameType: int32(user.NameType), NameString: append([]string(nil), user.Components...),
		},
		CRealm:  user.Realm,
		Options: &options,
	}
	userIDDER, err := asn1.Marshal(userID)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self user identity: %w", err)
	}
	checksum, err := etype.Checksum(tgt.Key.KeyValue, s4uRequestChecksumUsage, userIDDER)
	if err != nil {
		return nil, fmt.Errorf("S4U2Self checksum: %w", err)
	}
	padata, err := asn1.Marshal(protocol.PAS4UX509User{
		UserID: userID,
		Checksum: protocol.Checksum{
			ChecksumType: checksumType(tgt.Key.KeyType), Checksum: checksum,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("S4U2Self padata: %w", err)
	}
	request.PAData = append(request.PAData, protocol.PAData{
		PADataType: protocol.PADataS4UX509User, PADataValue: padata,
	})
	response, err := c.exchangePayload(ctx, realm, request, "S4U2Self request")
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		return nil, kerberosError
	}
	if err := verifyS4USelfReply(response, user, etype, tgt.Key.KeyValue, nonce); err != nil {
		return nil, err
	}
	return c.decodeTGSRep(response, user, service, nonce, tgt.Key.KeyType, tgt.Key.KeyValue, now)
}

// S4U2Proxy obtains a service ticket for service on behalf of the client named
// by the evidence ticket, using constrained delegation ([MS-SFU] section 3.1).
func (c *Client) S4U2Proxy(ctx context.Context, tgt, evidence *Credentials, service principal.Principal) (*Credentials, error) {
	if c == nil {
		return nil, fmt.Errorf("S4U2Proxy: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("S4U2Proxy: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("S4U2Proxy: %w", err)
	}
	if tgt == nil || len(tgt.Ticket) == 0 || len(tgt.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("S4U2Proxy: incomplete TGT")
	}
	if evidence == nil || len(evidence.Ticket) == 0 || len(evidence.Client.Components) == 0 {
		return nil, fmt.Errorf("S4U2Proxy: incomplete evidence ticket")
	}
	if len(service.Components) == 0 {
		return nil, fmt.Errorf("S4U2Proxy: invalid service principal")
	}
	realm, _ := ServiceRealm(c.Config, service)
	if realm == "" {
		realm = tgt.Server.Realm
	}
	if realm == "" {
		realm = tgt.Client.Realm
	}
	if realm == "" {
		return nil, fmt.Errorf("S4U2Proxy: missing service realm")
	}
	service = serviceWithRealm(service, realm)
	var evidenceTicket protocol.Ticket
	if err := asn1.Unmarshal(evidence.Ticket, &evidenceTicket); err != nil {
		return nil, fmt.Errorf("S4U2Proxy evidence ticket: %w", err)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	request, nonce, err := c.newTGSReqWithBody(tgt, service, realm, now, false, func(body *protocol.KDCReqBody) {
		body.KDCOptions |= types.KDCCNameInAddlTkt
		body.AdditionalTickets = []protocol.Ticket{evidenceTicket}
	})
	if err != nil {
		return nil, err
	}
	response, err := c.exchangePayload(ctx, realm, request, "S4U2Proxy request")
	if err != nil {
		return nil, err
	}
	if kerberosError, ok := decodeKRBError(response); ok {
		return nil, kerberosError
	}
	return c.decodeTGSRep(response, evidence.Client, service, nonce, tgt.Key.KeyType, tgt.Key.KeyValue, now)
}

func verifyS4USelfReply(response []byte, user principal.Principal, etype crypto.EType, key []byte, nonce uint32) error {
	var reply protocol.TGSRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		return fmt.Errorf("S4U2Self TGS-REP: %w", err)
	}
	for _, pa := range reply.PAData {
		if pa.PADataType != protocol.PADataS4UX509User {
			continue
		}
		var value protocol.PAS4UX509User
		if err := asn1.Unmarshal(pa.PADataValue, &value); err != nil {
			return fmt.Errorf("S4U2Self reply padata: %w", err)
		}
		if value.UserID.Nonce != nonce {
			return fmt.Errorf("S4U2Self: reply nonce mismatch")
		}
		if value.UserID.CRealm != user.Realm || value.UserID.CName == nil ||
			!sameProtocolPrincipal(*value.UserID.CName, user) {
			return fmt.Errorf("S4U2Self: reply user mismatch")
		}
		if value.Checksum.ChecksumType != checksumType(etype.ID()) {
			return fmt.Errorf("S4U2Self: reply checksum type %d: %w",
				value.Checksum.ChecksumType, krberrors.ErrIntegrity)
		}
		userIDDER, err := asn1.FieldContent(pa.PADataValue, 0)
		if err != nil {
			return fmt.Errorf("S4U2Self reply user identity: %w", err)
		}
		usage := uint32(s4uRequestChecksumUsage)
		if value.UserID.Options != nil && *value.UserID.Options&protocol.S4UOptionsUseReplyKeyUsage != 0 {
			usage = s4uReplyChecksumUsage
		}
		if err := etype.VerifyChecksum(key, usage, userIDDER, value.Checksum.Checksum); err != nil {
			return fmt.Errorf("S4U2Self reply checksum: %w", krberrors.ErrIntegrity)
		}
		return nil
	}
	return nil
}

package client

import (
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

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

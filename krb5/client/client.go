package client

import (
	"context"
	"encoding/binary"
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
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// Client performs Kerberos client exchanges.
type Client struct {
	Config   *config.Config
	Dialer   transport.Dialer
	Now      func() time.Time
	Exchange func(ctx context.Context, realm string, payload []byte) ([]byte, error)
}

// Credentials contains the initial credentials returned by an AS exchange.
type Credentials struct {
	Client    principal.Principal
	Server    principal.Principal
	Key       protocol.EncryptionKey
	Flags     types.TicketFlags
	AuthTime  types.KerberosTime
	StartTime *types.KerberosTime
	EndTime   types.KerberosTime
	RenewTill *types.KerberosTime
	Ticket    []byte
}

// ToCCacheCredential converts credentials to a FILE ccache credential.
func (c Credentials) ToCCacheCredential() ccache.Credential {
	return ccache.Credential{
		Client:      c.Client,
		Server:      c.Server,
		Enctype:     c.Key.KeyType,
		Key:         append([]byte(nil), c.Key.KeyValue...),
		TicketFlags: uint32(c.Flags),
		AuthTime:    unixTime(c.AuthTime),
		StartTime:   unixOptional(c.StartTime),
		EndTime:     unixTime(c.EndTime),
		RenewTill:   unixOptional(c.RenewTill),
		Ticket:      append([]byte(nil), c.Ticket...),
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

func (c *Client) newASReq(clientPrincipal principal.Principal, now time.Time) (protocol.ASReq, error) {
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
	enctypes := []int32{crypto.EnctypeAES256SHA1, crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA384, crypto.EnctypeAES128SHA256}
	if c.Config != nil && len(c.Config.DefaultTKTEnctypes) > 0 {
		enctypes = append([]int32(nil), c.Config.DefaultTKTEnctypes...)
	}
	return protocol.ASReq{
		PVNO: 5, MsgType: 10,
		ReqBody: protocol.KDCReqBody{
			KDCOptions: options,
			CName:      protocolPrincipal(clientPrincipal),
			Realm:      clientPrincipal.Realm,
			SName: &protocol.PrincipalName{
				NameType:   int32(principal.NTSrvInstance),
				NameString: []string{"krbtgt", clientPrincipal.Realm},
			},
			Till:  types.KerberosTime{Time: now.Add(lifetime), Present: true},
			Nonce: binary.BigEndian.Uint32(nonceBytes),
			EType: enctypes,
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
	if reply.CRealm != clientPrincipal.Realm ||
		!samePrincipal(reply.CName, clientPrincipal) {
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
	if reply.Ticket.Realm != clientPrincipal.Realm ||
		reply.Ticket.SName.NameType != int32(principal.NTSrvInstance) ||
		len(reply.Ticket.SName.NameString) != 2 ||
		reply.Ticket.SName.NameString[0] != "krbtgt" ||
		reply.Ticket.SName.NameString[1] != clientPrincipal.Realm ||
		part.SRealm != clientPrincipal.Realm ||
		part.SName.NameType != int32(principal.NTSrvInstance) ||
		len(part.SName.NameString) != 2 ||
		part.SName.NameString[0] != "krbtgt" ||
		part.SName.NameString[1] != clientPrincipal.Realm {
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
	return &Credentials{
		Client: clientPrincipal, Server: server,
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

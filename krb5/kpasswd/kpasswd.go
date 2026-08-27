package kpasswd

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	kpasswdPort        = 464
	kpasswdVersion     = 1
	setPasswordVersion = 0xff80
	kpasswdPrivUsage   = 13
	kpasswdMaxPacket   = 1<<16 - 1
	kpasswdResultCode  = 2
)

// Client performs RFC 3244 password changes and set-password requests using a
// Kerberos client.
type Client struct {
	Kerberos *client.Client
	// Port overrides the RFC 3244 default port 464 for isolated services.
	Port int
}

// ChangePassword authenticates the principal directly to kadmin/changepw and
// changes its password using the RFC 3244 kpasswd protocol.
func (c *Client) ChangePassword(ctx context.Context, clientPrincipal principal.Principal, currentPassword, newPassword string) error {
	if c == nil {
		return fmt.Errorf("password change: nil client")
	}
	if c.Kerberos == nil {
		return fmt.Errorf("password change: nil Kerberos client")
	}
	if ctx == nil {
		return fmt.Errorf("password change: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("password change: %w", err)
	}
	if clientPrincipal.Realm == "" || len(clientPrincipal.Components) == 0 {
		return fmt.Errorf("password change: invalid client principal")
	}
	if currentPassword == "" {
		return fmt.Errorf("password change: empty current password")
	}
	if newPassword == "" {
		return fmt.Errorf("password change: empty new password")
	}
	realm := clientPrincipal.Realm
	if realm == "" {
		return fmt.Errorf("password change: missing realm")
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	}
	changepw, err := c.Kerberos.ASExchangeService(ctx, clientPrincipal, currentPassword, service)
	if err != nil {
		return fmt.Errorf("password change service ticket: %w", err)
	}
	return c.ChangePasswordWithCredentials(ctx, changepw, newPassword)
}

// ChangePasswordWithCredentials sends a password change using a service
// credential for kadmin/changepw obtained by ASExchangeService or another
// compatible Kerberos exchange.
func (c *Client) ChangePasswordWithCredentials(ctx context.Context, changepw *client.Credentials, newPassword string) error {
	if c == nil {
		return fmt.Errorf("password change: nil client")
	}
	if c.Kerberos == nil {
		return fmt.Errorf("password change: nil Kerberos client")
	}
	if ctx == nil {
		return fmt.Errorf("password change: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("password change: %w", err)
	}
	if changepw == nil || len(changepw.Ticket) == 0 || len(changepw.Key.KeyValue) == 0 {
		return fmt.Errorf("password change: incomplete service credentials")
	}
	if newPassword == "" {
		return fmt.Errorf("password change: empty new password")
	}
	return c.sendPasswordRequest(ctx, changepw, kpasswdVersion, []byte(newPassword),
		"password change", kpasswdVersion)
}

// SetPassword authenticates an administrator to kadmin/changepw and sets the
// password of target.
func (c *Client) SetPassword(ctx context.Context, adminPrincipal principal.Principal, adminPassword string, target principal.Principal, newPassword string) error {
	if c == nil {
		return fmt.Errorf("set password: nil client")
	}
	if c.Kerberos == nil {
		return fmt.Errorf("set password: nil Kerberos client")
	}
	if ctx == nil {
		return fmt.Errorf("set password: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if adminPrincipal.Realm == "" || len(adminPrincipal.Components) == 0 {
		return fmt.Errorf("set password: invalid admin principal")
	}
	if adminPassword == "" {
		return fmt.Errorf("set password: empty admin password")
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	if newPassword == "" {
		return fmt.Errorf("set password: empty new password")
	}
	service := principal.Principal{
		Realm: adminPrincipal.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	}
	changepw, err := c.Kerberos.ASExchangeService(ctx, adminPrincipal, adminPassword, service)
	if err != nil {
		return fmt.Errorf("set password service ticket: %w", err)
	}
	return c.SetPasswordWithCredentials(ctx, changepw, target, newPassword)
}

// SetPasswordWithCredentials sets target's password using a kadmin/changepw
// service credential obtained by ASExchangeService or another compatible
// Kerberos exchange.
func (c *Client) SetPasswordWithCredentials(ctx context.Context, changepw *client.Credentials, target principal.Principal, newPassword string) error {
	if c == nil {
		return fmt.Errorf("set password: nil client")
	}
	if c.Kerberos == nil {
		return fmt.Errorf("set password: nil Kerberos client")
	}
	if ctx == nil {
		return fmt.Errorf("set password: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if changepw == nil || len(changepw.Ticket) == 0 || len(changepw.Key.KeyValue) == 0 {
		return fmt.Errorf("set password: incomplete service credentials")
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	if newPassword == "" {
		return fmt.Errorf("set password: empty new password")
	}
	targetName := protocol.PrincipalName{
		NameType:   int32(target.NameType),
		NameString: append([]string(nil), target.Components...),
	}
	targetRealm := target.Realm
	userData, err := asn1.Marshal(protocol.ChangePasswdData{
		NewPassword: []byte(newPassword),
		TargetName:  &targetName,
		TargetRealm: &targetRealm,
	})
	if err != nil {
		return fmt.Errorf("set password data: %w", err)
	}
	return c.sendPasswordRequest(ctx, changepw, setPasswordVersion, userData,
		"set password", kpasswdVersion, setPasswordVersion)
}

func validateTarget(target principal.Principal) error {
	if target.Realm == "" || len(target.Components) == 0 {
		return fmt.Errorf("set password: invalid target principal")
	}
	return nil
}

func (c *Client) sendPasswordRequest(ctx context.Context, changepw *client.Credentials, version uint16, userData []byte, operation string, replyVersions ...uint16) error {
	realm := changepw.Client.Realm
	if realm == "" {
		realm = changepw.Server.Realm
	}
	if realm == "" {
		return fmt.Errorf("%s: missing realm", operation)
	}
	now := time.Now().UTC()
	if c.Kerberos.Now != nil {
		now = c.Kerberos.Now().UTC()
	}
	apState, apDER, err := ap.BuildAPReq(changepw, types.APMutualRequired, now)
	if err != nil {
		return fmt.Errorf("%s AP-REQ: %w", operation, err)
	}
	privDER, err := buildKRBPriv(apState, userData, now)
	if err != nil {
		return fmt.Errorf("%s KRB-PRIV: %w", operation, err)
	}
	packet, err := buildPasswordPacket(version, apDER, privDER)
	if err != nil {
		return fmt.Errorf("%s packet: %w", operation, err)
	}
	response, err := c.passwordChangeRoundTrip(ctx, realm, packet)
	if err != nil {
		return err
	}
	result, err := parsePasswordReply(response, apState, now, c.clockSkew(), replyVersions...)
	if err != nil {
		return err
	}
	if result.Code != 0 {
		return fmt.Errorf("%s rejected (%d): %s", operation, result.Code, result.Message)
	}
	return nil
}

type passwordChangeResult struct {
	Code    uint16
	Message string
}

func buildPasswordChangePacket(apReq, priv []byte) ([]byte, error) {
	return buildPasswordPacket(kpasswdVersion, apReq, priv)
}

func buildPasswordPacket(version uint16, apReq, priv []byte) ([]byte, error) {
	if len(apReq) > 0xffff {
		return nil, fmt.Errorf("AP-REQ exceeds 16-bit length")
	}
	total := 6 + len(apReq) + len(priv)
	if total > kpasswdMaxPacket {
		return nil, fmt.Errorf("packet exceeds 16-bit length")
	}
	packet := make([]byte, total)
	binary.BigEndian.PutUint16(packet[0:2], uint16(total))
	binary.BigEndian.PutUint16(packet[2:4], version)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(apReq)))
	copy(packet[6:], apReq)
	copy(packet[6+len(apReq):], priv)
	return packet, nil
}

func buildKRBPriv(state *ap.APReq, password []byte, now time.Time) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("nil AP-REQ state")
	}
	key := state.SubKey
	if key == nil {
		key = &state.SessionKey
	}
	if key == nil || len(key.KeyValue) == 0 {
		return nil, fmt.Errorf("missing AP-REQ encryption key")
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	timestamp := types.KerberosTime{Time: now.UTC(), Present: true}
	usec := int32(now.Nanosecond() / 1000)
	part := protocol.EncKRBPrivPart{
		UserData:  append([]byte(nil), password...),
		Timestamp: &timestamp,
		Usec:      &usec,
		SeqNumber: state.SeqNumber,
		SAddress:  protocol.HostAddress{},
	}
	plaintext, err := asn1.Marshal(part)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted part: %w", err)
	}
	ciphertext, err := etype.Encrypt(key.KeyValue, kpasswdPrivUsage, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt encrypted part: %w", err)
	}
	return asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: key.KeyType, Cipher: ciphertext},
	})
}

func parsePasswordChangeReply(data []byte, state *ap.APReq, now time.Time, skew time.Duration) (passwordChangeResult, error) {
	return parsePasswordReply(data, state, now, skew, kpasswdVersion)
}

func parsePasswordReply(data []byte, state *ap.APReq, now time.Time, skew time.Duration, versions ...uint16) (passwordChangeResult, error) {
	if result, ok := decodeKRBError(data); ok {
		return passwordChangeResult{}, fmt.Errorf("password change: %w", result)
	}
	if len(data) < 6 {
		return passwordChangeResult{}, fmt.Errorf("password change reply: truncated")
	}
	if int(binary.BigEndian.Uint16(data[0:2])) != len(data) {
		return passwordChangeResult{}, fmt.Errorf("password change reply: inconsistent length")
	}
	version := binary.BigEndian.Uint16(data[2:4])
	accepted := false
	for _, candidate := range versions {
		if version == candidate {
			accepted = true
			break
		}
	}
	if !accepted {
		return passwordChangeResult{}, fmt.Errorf("password change reply: unsupported version")
	}
	apLength := int(binary.BigEndian.Uint16(data[4:6]))
	if apLength > len(data)-6 {
		return passwordChangeResult{}, fmt.Errorf("password change reply: truncated AP-REP")
	}
	if apLength == 0 {
		if result, ok := decodeKRBError(data[6:]); ok {
			return passwordChangeResult{}, fmt.Errorf("password change: %w", result)
		}
		return passwordChangeResult{}, fmt.Errorf("password change reply: missing AP-REP")
	}
	if state == nil {
		return passwordChangeResult{}, fmt.Errorf("password change reply: nil AP-REQ state")
	}
	if err := ap.VerifyAPRep(state, data[6:6+apLength]); err != nil {
		return passwordChangeResult{}, fmt.Errorf("password change reply AP-REP: %w", err)
	}
	key := state.SubKey
	if key == nil {
		key = &state.SessionKey
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return passwordChangeResult{}, err
	}
	var priv protocol.KRBPriv
	if err := asn1.Unmarshal(data[6+apLength:], &priv); err != nil {
		return passwordChangeResult{}, fmt.Errorf("password change reply KRB-PRIV: %w", err)
	}
	if priv.PVNO != 5 || priv.MsgType != 21 || priv.EncPart.EType != key.KeyType {
		return passwordChangeResult{}, fmt.Errorf("password change reply: invalid KRB-PRIV")
	}
	plaintext, err := etype.Decrypt(key.KeyValue, kpasswdPrivUsage, priv.EncPart.Cipher)
	if err != nil {
		return passwordChangeResult{}, fmt.Errorf("password change reply KRB-PRIV: %w", err)
	}
	var part protocol.EncKRBPrivPart
	if err := asn1.Unmarshal(plaintext, &part); err != nil {
		return passwordChangeResult{}, fmt.Errorf("password change reply encrypted part: %w", err)
	}
	if part.Timestamp == nil || !part.Timestamp.Present {
		// MIT kadmind enables sequence protection but not timestamp
		// protection on its reply auth context. A sequence-protected reply
		// is therefore valid without a timestamp.
		if part.SeqNumber == nil {
			return passwordChangeResult{}, fmt.Errorf("password change reply: missing timestamp and sequence")
		}
	} else if !kpasswdWithinSkew(part.Timestamp.Time, now, skew) {
		return passwordChangeResult{}, fmt.Errorf("password change reply: stale timestamp")
	}
	if len(part.UserData) < kpasswdResultCode {
		return passwordChangeResult{}, fmt.Errorf("password change reply: missing result code")
	}
	return passwordChangeResult{
		Code:    binary.BigEndian.Uint16(part.UserData[:kpasswdResultCode]),
		Message: strings.TrimSpace(string(part.UserData[kpasswdResultCode:])),
	}, nil
}

func kpasswdWithinSkew(value, now time.Time, skew time.Duration) bool {
	if skew < 0 {
		return false
	}
	return !value.Before(now.Add(-skew)) && !value.After(now.Add(skew))
}

func (c *Client) passwordChangeRoundTrip(ctx context.Context, realm string, payload []byte) ([]byte, error) {
	if c.Kerberos.Exchange != nil {
		response, err := c.Kerberos.Exchange(ctx, realm, payload)
		if err != nil {
			return nil, fmt.Errorf("password change transport: %w", err)
		}
		return response, nil
	}
	if c.Kerberos.Config == nil {
		return nil, fmt.Errorf("password change: no configuration or exchange function")
	}
	endpoint, ok := configuredKDC(c.Kerberos.Config, realm)
	if !ok {
		return nil, fmt.Errorf("password change: no server configured for realm %q", realm)
	}
	address, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("password change address: %w", err)
	}
	address.Port = c.port(realm)
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("password change UDP socket: %w", err)
	}
	defer conn.Close()
	exchange := transport.Exchange{Dialer: c.Kerberos.Dialer, Timeout: 5 * time.Second}
	return exchange.Request(ctx, conn, address, payload)
}

func (c *Client) port(realm string) int {
	if c.Port > 0 {
		return c.Port
	}
	if c.Kerberos != nil && c.Kerberos.Config != nil {
		for configuredRealm, options := range c.Kerberos.Config.RealmOptions {
			if !strings.EqualFold(configuredRealm, realm) {
				continue
			}
			values := options["kpasswd_port"]
			if len(values) > 0 {
				if port, err := strconv.Atoi(values[len(values)-1]); err == nil &&
					port > 0 && port <= 0xffff {
					return port
				}
			}
		}
	}
	return kpasswdPort
}

func (c *Client) clockSkew() time.Duration {
	if c.Kerberos != nil && c.Kerberos.Config != nil && c.Kerberos.Config.ClockSkew > 0 {
		return c.Kerberos.Config.ClockSkew
	}
	return 5 * time.Minute
}

func decodeKRBError(data []byte) (*krberrors.KRBError, bool) {
	var value protocol.KRBError
	if err := asn1.Unmarshal(data, &value); err != nil {
		return nil, false
	}
	server := append([]string(nil), value.SName.NameString...)
	return krberrors.NewKRBError(
		krberrors.ErrorCode(value.ErrorCode),
		strings.Join(server, "/")+"@"+value.Realm,
		value.Realm, value.STime.Time, value.Susec, value.EData,
	), true
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

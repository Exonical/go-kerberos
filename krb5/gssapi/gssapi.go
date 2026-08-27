package gssapi

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	// KerberosMechOID is the RFC 4121 Kerberos mechanism OID.
	KerberosMechOID = "1.2.840.113554.1.2.2"

	GSSDelegFlag           uint32 = 1 << 0
	GSSMutualFlag          uint32 = 1 << 1
	GSSReplayFlag          uint32 = 1 << 2
	GSSSequenceFlag        uint32 = 1 << 3
	GSSAnonFlag            uint32 = 1 << 4
	GSSConfidentialityFlag uint32 = 1 << 5
	GSSIntegrityFlag       uint32 = 1 << 6

	GSS_C_DELEG_FLAG    = GSSDelegFlag
	GSS_C_MUTUAL_FLAG   = GSSMutualFlag
	GSS_C_REPLAY_FLAG   = GSSReplayFlag
	GSS_C_SEQUENCE_FLAG = GSSSequenceFlag
	GSS_C_ANON_FLAG     = GSSAnonFlag
	GSS_C_CONF_FLAG     = GSSConfidentialityFlag
	GSS_C_INTEG_FLAG    = GSSIntegrityFlag

	tokenFlagSentByAcceptor byte = 1 << 0
	tokenFlagSealed         byte = 1 << 1
	tokenFlagAcceptorSubkey byte = 1 << 2
)

var kerberosOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// Initiator establishes a Kerberos GSS security context.
type Initiator struct {
	creds *client.Credentials
	flags uint32
	state *ap.APReq
	ctx   *Context
}

// Acceptor accepts Kerberos GSS security contexts using a service keytab.
type Acceptor struct {
	keytab *keytab.Keytab
}

// Context is an established Kerberos GSS security context.
type Context struct {
	key       protocol.EncryptionKey
	initiator bool
	flags     uint32
	sendSeq   uint64
	recvSeq   uint64
}

// NewInitiator creates an initiator for the supplied service credentials.
func NewInitiator(creds *client.Credentials, flags uint32) (*Initiator, error) {
	if creds == nil || len(creds.Ticket) == 0 || len(creds.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("GSS initiator: incomplete credentials")
	}
	return &Initiator{creds: creds, flags: flags}, nil
}

// NewAcceptor creates an acceptor backed by a service keytab.
func NewAcceptor(kt *keytab.Keytab) *Acceptor {
	return &Acceptor{keytab: kt}
}

// InitialToken creates the RFC 2743 initial context token.
func (i *Initiator) InitialToken(now time.Time) ([]byte, error) {
	if i == nil || i.creds == nil {
		return nil, fmt.Errorf("GSS initiator: incomplete context")
	}
	checksumData := make([]byte, 20)
	binary.LittleEndian.PutUint32(checksumData[16:], i.flags)
	checksum := &protocol.Checksum{ChecksumType: 0x8003, Checksum: checksumData}
	opts := types.APOptions(0)
	if i.flags&GSSMutualFlag != 0 {
		opts |= types.APMutualRequired
	}
	state, apDER, err := ap.BuildAPReqWithOptions(i.creds, opts, now, ap.APReqOptions{Checksum: checksum})
	if err != nil {
		return nil, fmt.Errorf("GSS initial AP-REQ: %w", err)
	}
	i.state = state
	i.ctx = &Context{
		key:       contextKey(state.SessionKey, state.SubKey),
		initiator: true,
		flags:     i.flags,
		sendSeq:   sequenceValue(state.SeqNumber),
	}
	return frameToken([]byte{0x01, 0x00}, apDER), nil
}

// VerifyToken verifies the AP-REP returned for a mutually authenticated context.
func (i *Initiator) VerifyToken(token []byte) error {
	if i == nil || i.state == nil {
		return fmt.Errorf("GSS initiator: context is not established")
	}
	inner, err := unframeToken(token, []byte{0x02, 0x00})
	if err != nil {
		return err
	}
	if err := ap.VerifyAPRep(i.state, inner); err != nil {
		return fmt.Errorf("GSS AP-REP: %w", err)
	}
	return nil
}

// Accept verifies an initial context token and optionally returns an AP-REP.
func (a *Acceptor) Accept(token []byte, now time.Time) (*Context, []byte, error) {
	if a == nil || a.keytab == nil {
		return nil, nil, fmt.Errorf("GSS acceptor: incomplete keytab")
	}
	inner, err := unframeToken(token, []byte{0x01, 0x00})
	if err != nil {
		return nil, nil, err
	}
	verified, err := ap.VerifyAPReq(a.keytab, inner, now, 5*time.Minute)
	if err != nil {
		return nil, nil, fmt.Errorf("GSS AP-REQ: %w", err)
	}
	flags, err := checksumFlags(verified.Checksum)
	if err != nil {
		return nil, nil, err
	}
	ctx := &Context{
		key:     contextKey(verified.SessionKey, verified.SubKey),
		flags:   flags,
		recvSeq: sequenceValue(verified.SeqNumber),
	}
	if flags&GSSMutualFlag != 0 {
		reply, err := ap.BuildAPRep(verified)
		if err != nil {
			return nil, nil, fmt.Errorf("GSS AP-REP: %w", err)
		}
		return ctx, frameToken([]byte{0x02, 0x00}, reply), nil
	}
	return ctx, nil, nil
}

// Wrap protects a message with an RFC 4121 MIC or encrypted token.
func (i *Initiator) Wrap(data []byte, sealed bool) ([]byte, error) {
	if i == nil || i.ctx == nil {
		return nil, fmt.Errorf("GSS initiator: context is not established")
	}
	return i.ctx.wrap(data, sealed)
}

// Unwrap verifies and decodes a message from an acceptor.
func (i *Initiator) Unwrap(token []byte) ([]byte, error) {
	if i == nil || i.ctx == nil {
		return nil, fmt.Errorf("GSS initiator: context is not established")
	}
	return i.ctx.unwrap(token)
}

// MIC creates an RFC 4121 integrity token.
func (i *Initiator) MIC(data []byte) ([]byte, error) {
	if i == nil || i.ctx == nil {
		return nil, fmt.Errorf("GSS initiator: context is not established")
	}
	return i.ctx.mic(data)
}

// VerifyMIC verifies an RFC 4121 integrity token.
func (i *Initiator) VerifyMIC(data, token []byte) error {
	if i == nil || i.ctx == nil {
		return fmt.Errorf("GSS initiator: context is not established")
	}
	return i.ctx.verifyMIC(data, token)
}

// Wrap protects a message with an RFC 4121 MIC or encrypted token.
func (c *Context) Wrap(data []byte, sealed bool) ([]byte, error) {
	return c.wrap(data, sealed)
}

// Unwrap verifies and decodes a message from the peer.
func (c *Context) Unwrap(token []byte) ([]byte, error) {
	return c.unwrap(token)
}

// MIC creates an RFC 4121 integrity token.
func (c *Context) MIC(data []byte) ([]byte, error) {
	return c.mic(data)
}

// VerifyMIC verifies an RFC 4121 integrity token.
func (c *Context) VerifyMIC(data, token []byte) error {
	return c.verifyMIC(data, token)
}

func (c *Context) wrap(data []byte, sealed bool) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("GSS message: nil context")
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return nil, err
	}
	flags := byte(0)
	if !c.initiator {
		flags |= tokenFlagSentByAcceptor
	}
	if sealed {
		flags |= tokenFlagSealed
	}
	seq := c.sendSeq
	c.sendSeq++
	usage := uint32(24)
	if !c.initiator {
		usage = 22
	}
	payload := append([]byte(nil), data...)
	if sealed {
		payload, err = etype.Encrypt(c.key.KeyValue, usage, payload)
		if err != nil {
			return nil, fmt.Errorf("GSS wrap encryption: %w", err)
		}
	}
	ec := 0
	if !sealed {
		ec = etype.ChecksumSize()
	}
	header := messageHeader([]byte{0x05, 0x04}, flags, ec, 0, seq)
	if !sealed {
		signUsage := uint32(25)
		if !c.initiator {
			signUsage = 23
		}
		mac, err := etype.Checksum(c.key.KeyValue, signUsage, append(header, data...))
		if err != nil {
			return nil, fmt.Errorf("GSS wrap checksum: %w", err)
		}
		payload = append(payload, mac...)
	}
	return append(header, payload...), nil
}

func (c *Context) unwrap(token []byte) ([]byte, error) {
	header, payload, err := parseMessage(token, []byte{0x05, 0x04})
	if err != nil {
		return nil, err
	}
	if err := c.validateIncoming(header); err != nil {
		return nil, err
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return nil, err
	}
	rrc := int(binary.BigEndian.Uint16(header[6:8]))
	payload, err = rotateLeft(payload, rrc)
	if err != nil {
		return nil, err
	}
	sealed := header[2]&tokenFlagSealed != 0
	if sealed {
		usage := uint32(24)
		if c.initiator {
			usage = 22
		}
		plain, err := etype.Decrypt(c.key.KeyValue, usage, payload)
		if err != nil {
			return nil, fmt.Errorf("GSS unwrap: %w", err)
		}
		c.recvSeq++
		return plain, nil
	}
	ec := int(binary.BigEndian.Uint16(header[4:6]))
	if ec != etype.ChecksumSize() || len(payload) < ec {
		return nil, fmt.Errorf("GSS unwrap: %w", krberrors.ErrIntegrity)
	}
	data, mac := payload[:len(payload)-ec], payload[len(payload)-ec:]
	canonical := messageHeader(header[:2], header[2], ec, 0, binary.BigEndian.Uint64(header[8:]))
	signUsage := uint32(25)
	if c.initiator {
		signUsage = 23
	}
	if err := etype.VerifyChecksum(c.key.KeyValue, signUsage, append(canonical, data...), mac); err != nil {
		return nil, fmt.Errorf("GSS unwrap: %w", err)
	}
	c.recvSeq++
	return data, nil
}

func (c *Context) mic(data []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("GSS MIC: nil context")
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return nil, err
	}
	flags := byte(0)
	if !c.initiator {
		flags |= tokenFlagSentByAcceptor
	}
	seq := c.sendSeq
	c.sendSeq++
	ec := etype.ChecksumSize()
	header := messageHeader([]byte{0x04, 0x04}, flags, ec, 0, seq)
	usage := uint32(25)
	if !c.initiator {
		usage = 23
	}
	mac, err := etype.Checksum(c.key.KeyValue, usage, append(header, data...))
	if err != nil {
		return nil, fmt.Errorf("GSS MIC: %w", err)
	}
	return append(header, mac...), nil
}

func (c *Context) verifyMIC(data, token []byte) error {
	header, payload, err := parseMessage(token, []byte{0x04, 0x04})
	if err != nil {
		return err
	}
	if err := c.validateIncoming(header); err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return err
	}
	rrc := int(binary.BigEndian.Uint16(header[6:8]))
	payload, err = rotateLeft(payload, rrc)
	if err != nil {
		return err
	}
	ec := int(binary.BigEndian.Uint16(header[4:6]))
	if ec != etype.ChecksumSize() || len(payload) != ec {
		return fmt.Errorf("GSS MIC: %w", krberrors.ErrIntegrity)
	}
	canonical := messageHeader(header[:2], header[2], ec, 0, binary.BigEndian.Uint64(header[8:]))
	usage := uint32(25)
	if c.initiator {
		usage = 23
	}
	if err := etype.VerifyChecksum(c.key.KeyValue, usage, append(canonical, data...), payload); err != nil {
		return fmt.Errorf("GSS MIC: %w", err)
	}
	c.recvSeq++
	return nil
}

func (c *Context) validateIncoming(header []byte) error {
	if c == nil || len(header) != 16 {
		return fmt.Errorf("GSS token: invalid context")
	}
	expectedDirection := byte(0)
	if c.initiator {
		expectedDirection = tokenFlagSentByAcceptor
	}
	if header[2]&tokenFlagSentByAcceptor != expectedDirection {
		return fmt.Errorf("GSS token: wrong direction")
	}
	if header[3] != 0xff {
		return fmt.Errorf("GSS token: invalid filler")
	}
	if binary.BigEndian.Uint64(header[8:]) != c.recvSeq {
		return fmt.Errorf("GSS token: unexpected sequence number")
	}
	return nil
}

func contextKey(session protocol.EncryptionKey, subkey *protocol.EncryptionKey) protocol.EncryptionKey {
	if subkey != nil && len(subkey.KeyValue) != 0 {
		return protocol.EncryptionKey{KeyType: subkey.KeyType, KeyValue: append([]byte(nil), subkey.KeyValue...)}
	}
	return protocol.EncryptionKey{KeyType: session.KeyType, KeyValue: append([]byte(nil), session.KeyValue...)}
}

func checksumFlags(checksum *protocol.Checksum) (uint32, error) {
	if checksum == nil || checksum.ChecksumType != 0x8003 || len(checksum.Checksum) < 20 {
		return 0, fmt.Errorf("GSS authenticator: missing RFC 4121 checksum")
	}
	return binary.LittleEndian.Uint32(checksum.Checksum[16:20]), nil
}

func sequenceValue(value *uint32) uint64 {
	if value == nil {
		return 0
	}
	return uint64(*value)
}

func frameToken(tokenID, inner []byte) []byte {
	content := append(append([]byte(nil), kerberosOID...), tokenID...)
	content = append(content, inner...)
	return append([]byte{0x60}, appendDERLength(content)...)
}

func appendDERLength(content []byte) []byte {
	length := len(content)
	if length < 128 {
		return append([]byte{byte(length)}, content...)
	}
	if length < 256 {
		return append([]byte{0x81, byte(length)}, content...)
	}
	return append([]byte{0x82, byte(length >> 8), byte(length)}, content...)
}

func unframeToken(token, tokenID []byte) ([]byte, error) {
	if len(token) < 2+len(kerberosOID)+len(tokenID) || token[0] != 0x60 {
		return nil, fmt.Errorf("GSS token: invalid framing")
	}
	offset, err := derLength(token[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if contentStart > len(token) || len(token)-contentStart < len(kerberosOID)+len(tokenID) ||
		len(token)-contentStart != derLengthValue(token[1:]) {
		return nil, fmt.Errorf("GSS token: invalid framing")
	}
	content := token[contentStart:]
	if string(content[:len(kerberosOID)]) != string(kerberosOID) {
		return nil, fmt.Errorf("GSS token: unexpected mechanism")
	}
	content = content[len(kerberosOID):]
	if string(content[:len(tokenID)]) != string(tokenID) {
		return nil, fmt.Errorf("GSS token: unexpected token id")
	}
	return append([]byte(nil), content[len(tokenID):]...), nil
}

func derLength(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("GSS token: truncated length")
	}
	if data[0] < 128 {
		return 1, nil
	}
	n := int(data[0] & 0x7f)
	if n == 0 || n > 2 || len(data) < n+1 {
		return 0, fmt.Errorf("GSS token: invalid length")
	}
	return n + 1, nil
}

func derLengthValue(data []byte) int {
	if data[0] < 128 {
		return int(data[0])
	}
	n := int(data[0] & 0x7f)
	value := 0
	for _, b := range data[1 : n+1] {
		value = value<<8 | int(b)
	}
	return value
}

func messageHeader(tokenID []byte, flags byte, ec, rrc int, seq uint64) []byte {
	header := make([]byte, 16)
	copy(header, tokenID)
	header[2], header[3] = flags, 0xff
	binary.BigEndian.PutUint16(header[4:6], uint16(ec))
	binary.BigEndian.PutUint16(header[6:8], uint16(rrc))
	binary.BigEndian.PutUint64(header[8:], seq)
	return header
}

func parseMessage(token, tokenID []byte) ([]byte, []byte, error) {
	if len(token) < 16 || string(token[:2]) != string(tokenID) {
		return nil, nil, fmt.Errorf("GSS token: invalid message token")
	}
	if token[3] != 0xff {
		return nil, nil, fmt.Errorf("GSS token: invalid filler")
	}
	return append([]byte(nil), token[:16]...), append([]byte(nil), token[16:]...), nil
}

func rotateLeft(data []byte, count int) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	count %= len(data)
	return append(append([]byte(nil), data[count:]...), data[:count]...), nil
}

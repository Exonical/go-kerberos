package gssapi

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
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
var kerberosOldOID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}

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
	key            protocol.EncryptionKey
	initiator      bool
	flags          uint32
	acceptorSubkey bool
	sendSeq        uint64
	recvSeq        uint64
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
	return i.initialToken(now, false, nil)
}

// InitialTokenWithChannelBindings creates an initial token bound to the
// supplied initiator and acceptor IPv4 address bytes.
func (i *Initiator) InitialTokenWithChannelBindings(now time.Time, initiatorAddress, acceptorAddress []byte) ([]byte, error) {
	var binding bytes.Buffer
	var addressType [4]byte
	binary.LittleEndian.PutUint32(addressType[:], 2)
	binding.Write(addressType[:])
	writeAddress := func(address []byte) {
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(len(address)))
		binding.Write(length[:])
		binding.Write(address)
	}
	writeAddress(initiatorAddress)
	binding.Write(addressType[:])
	writeAddress(acceptorAddress)
	var zero [4]byte
	binding.Write(zero[:])
	sum := md5.Sum(binding.Bytes())
	return i.initialToken(now, false, sum[:])
}

func (i *Initiator) initialToken(now time.Time, legacy bool, channelBindings []byte) ([]byte, error) {
	if i == nil || i.creds == nil {
		return nil, fmt.Errorf("GSS initiator: incomplete context")
	}
	checksumData := make([]byte, 24)
	binary.LittleEndian.PutUint32(checksumData, 16)
	if len(channelBindings) != 0 {
		if len(channelBindings) != 16 {
			return nil, fmt.Errorf("GSS initial token: invalid channel bindings")
		}
		copy(checksumData[4:], channelBindings)
	}
	binary.LittleEndian.PutUint32(checksumData[20:], i.flags)
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
	if legacy {
		return frameTokenWithOID(kerberosOldOID, []byte{0x01, 0x00}, apDER), nil
	}
	return frameToken([]byte{0x01, 0x00}, apDER), nil
}

// VerifyToken verifies the AP-REP returned for a mutually authenticated context.
func (i *Initiator) VerifyToken(token []byte) error {
	if i == nil || i.state == nil {
		return fmt.Errorf("GSS initiator: context is not established")
	}
	inner, err := unframeTokenAnyOID(token, []byte{0x02, 0x00})
	if err != nil {
		return err
	}
	details, err := ap.VerifyAPRepWithDetails(i.state, inner)
	if err != nil {
		return fmt.Errorf("GSS AP-REP: %w", err)
	}
	if details.SubKey != nil {
		i.ctx.key = contextKey(i.state.SessionKey, details.SubKey)
		i.ctx.acceptorSubkey = true
	}
	if details.SeqNumber != nil {
		i.ctx.recvSeq = sequenceValue(details.SeqNumber)
	}
	return nil
}

// Accept verifies an initial context token and optionally returns an AP-REP.
func (a *Acceptor) Accept(token []byte, now time.Time) (*Context, []byte, error) {
	ctx, _, reply, err := a.accept(token, now)
	return ctx, reply, err
}

// AcceptWithPrincipal accepts a context and returns the authenticated
// initiator principal for applications that need authorization decisions.
func (a *Acceptor) AcceptWithPrincipal(token []byte, now time.Time) (*Context, principal.Principal, []byte, error) {
	return a.accept(token, now)
}

func (a *Acceptor) accept(token []byte, now time.Time) (*Context, principal.Principal, []byte, error) {
	if a == nil || a.keytab == nil {
		return nil, principal.Principal{}, nil, fmt.Errorf("GSS acceptor: incomplete keytab")
	}
	inner, err := unframeToken(token, []byte{0x01, 0x00})
	if err != nil {
		return nil, principal.Principal{}, nil, err
	}
	verified, err := ap.VerifyAPReq(a.keytab, inner, now, 5*time.Minute)
	if err != nil {
		return nil, principal.Principal{}, nil, fmt.Errorf("GSS AP-REQ: %w", err)
	}
	flags, err := checksumFlags(verified.Checksum)
	if err != nil {
		return nil, principal.Principal{}, nil, err
	}
	ctx := &Context{
		key:     contextKey(verified.SessionKey, verified.SubKey),
		flags:   flags,
		recvSeq: sequenceValue(verified.SeqNumber),
	}
	if flags&GSSMutualFlag != 0 {
		reply, err := ap.BuildAPRep(verified)
		if err != nil {
			return nil, principal.Principal{}, nil, fmt.Errorf("GSS AP-REP: %w", err)
		}
		return ctx, verified.Client, frameToken([]byte{0x02, 0x00}, reply), nil
	}
	return ctx, verified.Client, nil, nil
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

// Context returns the established security context for protocol adapters that
// need to use the underlying GSS per-message tokens.
func (i *Initiator) Context() (*Context, error) {
	if i == nil || i.ctx == nil {
		return nil, fmt.Errorf("GSS initiator: context is not established")
	}
	return i.ctx, nil
}

// SequenceNumber returns the authenticator sequence used by the initial
// AP-REQ, for protocol adapters sharing the GSS per-message sequence space.
func (i *Initiator) SequenceNumber() (uint32, bool) {
	if i == nil || i.state == nil || i.state.SeqNumber == nil {
		return 0, false
	}
	return *i.state.SeqNumber, true
}

// Wrap protects a message with an RFC 4121 MIC or encrypted token.
func (c *Context) Wrap(data []byte, sealed bool) ([]byte, error) {
	return c.wrap(data, sealed)
}

// Unwrap verifies and decodes a message from the peer.
func (c *Context) Unwrap(token []byte) ([]byte, error) {
	return c.unwrap(token)
}

// UnwrapInitial verifies the first peer message when its sequence number is
// established by the protocol rather than by the AP exchange.
func (c *Context) UnwrapInitial(token []byte) ([]byte, error) {
	header, _, err := parseMessage(token, []byte{0x05, 0x04})
	if err != nil {
		return nil, err
	}
	c.recvSeq = binary.BigEndian.Uint64(header[8:])
	plain, err := c.unwrap(token)
	if err != nil {
		return nil, err
	}
	c.recvSeq++
	return plain, nil
}

// SetSendSequence synchronizes the outgoing token sequence with protocols
// which establish their own sequence number after the GSS context handshake.
func (c *Context) SetSendSequence(sequence uint64) {
	if c != nil {
		c.sendSeq = sequence
	}
}

// SetReceiveSequence synchronizes the expected incoming token sequence with
// protocols that carry their own sequence space.
func (c *Context) SetReceiveSequence(sequence uint64) {
	if c != nil {
		c.recvSeq = sequence
	}
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
	if c.acceptorSubkey {
		flags |= tokenFlagAcceptorSubkey
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
		header := messageHeader([]byte{0x05, 0x04}, flags, 0, 0, seq)
		encryptedInput := append(append([]byte(nil), payload...), header...)
		payload, err = etype.Encrypt(c.key.KeyValue, usage, encryptedInput)
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
		signUsage := uint32(24)
		if !c.initiator {
			signUsage = 22
		}
		checksumHeader := append([]byte(nil), header...)
		checksumHeader[4], checksumHeader[5] = 0, 0
		checksumHeader[6], checksumHeader[7] = 0, 0
		signed := append(append([]byte(nil), data...), checksumHeader...)
		mac, err := etype.Checksum(c.key.KeyValue, signUsage, signed)
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
		if len(plain) < 16 {
			return nil, fmt.Errorf("GSS unwrap: %w", krberrors.ErrIntegrity)
		}
		ec := int(binary.BigEndian.Uint16(header[4:6]))
		expectedHeader := messageHeader(header[:2], header[2], ec, 0, binary.BigEndian.Uint64(header[8:]))
		if !equalBytes(plain[len(plain)-16:], expectedHeader) {
			return nil, fmt.Errorf("GSS unwrap: %w", krberrors.ErrIntegrity)
		}
		body := plain[:len(plain)-16]
		if ec > len(body) {
			return nil, fmt.Errorf("GSS unwrap: %w", krberrors.ErrIntegrity)
		}
		c.recvSeq++
		return body[:len(body)-ec], nil
	}
	ec := int(binary.BigEndian.Uint16(header[4:6]))
	if ec != etype.ChecksumSize() || len(payload) < ec {
		return nil, fmt.Errorf("GSS unwrap: %w", krberrors.ErrIntegrity)
	}
	data, mac := payload[:len(payload)-ec], payload[len(payload)-ec:]
	signUsage := uint32(24)
	if c.initiator {
		signUsage = 22
	} else {
		signUsage = 24
	}
	checksumHeader := append([]byte(nil), header...)
	checksumHeader[4], checksumHeader[5] = 0, 0
	checksumHeader[6], checksumHeader[7] = 0, 0
	signed := append(append([]byte(nil), data...), checksumHeader...)
	if err := etype.VerifyChecksum(c.key.KeyValue, signUsage, signed, mac); err != nil {
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
	if c.acceptorSubkey {
		flags |= tokenFlagAcceptorSubkey
	}
	seq := c.sendSeq
	c.sendSeq++
	header := micHeader(flags, seq)
	usage := uint32(25)
	if !c.initiator {
		usage = 23
	}
	signed := append(append([]byte(nil), data...), header...)
	mac, err := etype.Checksum(c.key.KeyValue, usage, signed)
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
	for _, value := range header[3:8] {
		if value != 0xff {
			return fmt.Errorf("GSS MIC: %w", krberrors.ErrIntegrity)
		}
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return err
	}
	if len(payload) != etype.ChecksumSize() {
		return fmt.Errorf("GSS MIC: %w", krberrors.ErrIntegrity)
	}
	canonical := micHeader(header[2], binary.BigEndian.Uint64(header[8:]))
	usage := uint32(25)
	if c.initiator {
		usage = 23
	} else {
		usage = 25
	}
	signed := append(append([]byte(nil), data...), canonical...)
	if err := etype.VerifyChecksum(c.key.KeyValue, usage, signed, payload); err != nil {
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
		return fmt.Errorf("GSS token: unexpected sequence number (got %d, want %d)", binary.BigEndian.Uint64(header[8:]), c.recvSeq)
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
	if len(checksum.Checksum) >= 24 && binary.LittleEndian.Uint32(checksum.Checksum[:4]) == 16 {
		return binary.LittleEndian.Uint32(checksum.Checksum[20:24]), nil
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
	return frameTokenWithOID(kerberosOID, tokenID, inner)
}

func frameTokenWithOID(oid, tokenID, inner []byte) []byte {
	content := append(append([]byte(nil), oid...), tokenID...)
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
	return unframeTokenWithOIDs(token, tokenID, kerberosOID)
}

func unframeTokenAnyOID(token, tokenID []byte) ([]byte, error) {
	return unframeTokenWithOIDs(token, tokenID, kerberosOID, kerberosOldOID)
}

func unframeTokenWithOIDs(token, tokenID []byte, oids ...[]byte) ([]byte, error) {
	if len(token) < 2+len(tokenID) || token[0] != 0x60 {
		return nil, fmt.Errorf("GSS token: invalid framing")
	}
	offset, err := derLength(token[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if contentStart > len(token) || len(token)-contentStart < len(tokenID) ||
		len(token)-contentStart != derLengthValue(token[1:]) {
		return nil, fmt.Errorf("GSS token: invalid framing")
	}
	content := token[contentStart:]
	var oid []byte
	for _, candidate := range oids {
		if len(content) >= len(candidate) && string(content[:len(candidate)]) == string(candidate) {
			oid = candidate
			break
		}
	}
	if len(oid) == 0 {
		return nil, fmt.Errorf("GSS token: unexpected mechanism")
	}
	content = content[len(oid):]
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

func micHeader(flags byte, seq uint64) []byte {
	header := make([]byte, 16)
	header[0], header[1], header[2] = 0x04, 0x04, flags
	for index := 3; index < 8; index++ {
		header[index] = 0xff
	}
	binary.BigEndian.PutUint64(header[8:], seq)
	return header
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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

package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf16"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	Alignment  = 8
	headerLen  = 8
	bufferLen  = 16
	maxBuffers = 4096

	LogonInfo      uint32 = 1
	ServerChecksum uint32 = 6
	KDCChecksum    uint32 = 7
	ClientInfo     uint32 = 10
	UPNDNSInfo     uint32 = 12
	// TicketChecksum is the signature over the EncTicketPart for service
	// tickets.  MIT calls this KRB5_PAC_TICKET_CHECKSUM.
	TicketChecksum uint32 = 16
	// FullChecksum is the full KDC checksum over the PAC.
	FullChecksum  uint32 = 19
	checksumUsage        = 17
)

// Buffer is one PAC_INFO_BUFFER and its opaque payload.
type Buffer struct {
	Type uint32
	Data []byte
}

// PAC is a parsed MS-PAC.  Buffer ordering is retained by Parse and used by
// MarshalBinary; newly added buffers are appended in the same manner as MIT.
type PAC struct {
	Version uint32
	Buffers []Buffer
	raw     []byte
	dirty   bool
}

// Key supplies a Kerberos enctype and its raw key for PAC signatures.
type Key struct {
	EType crypto.EType
	Key   []byte
}

// Parse decodes a PAC header and all aligned buffers, rejecting offsets which
// point into the header, overlap the input, or overflow integer bounds.
func Parse(data []byte) (*PAC, error) {
	if len(data) < headerLen {
		return nil, fmt.Errorf("PAC: truncated header")
	}
	count := binary.LittleEndian.Uint32(data)
	if count == 0 || count > maxBuffers {
		return nil, fmt.Errorf("PAC: too many buffers: %d", count)
	}
	tableLen := uint64(headerLen) + uint64(count)*bufferLen
	if tableLen > uint64(len(data)) {
		return nil, fmt.Errorf("PAC: truncated buffer table")
	}
	p := &PAC{Version: binary.LittleEndian.Uint32(data[4:])}
	if p.Version != 0 {
		return nil, fmt.Errorf("PAC: unsupported version %d", p.Version)
	}
	p.raw = append([]byte(nil), data...)
	p.Buffers = make([]Buffer, count)
	type span struct{ start, end uint64 }
	spans := make([]span, 0, count)
	types := make(map[uint32]struct{}, count)
	for i := uint32(0); i < count; i++ {
		off := headerLen + int(i)*bufferLen
		typ := binary.LittleEndian.Uint32(data[off:])
		if _, exists := types[typ]; exists {
			return nil, fmt.Errorf("PAC: duplicate buffer type %d", typ)
		}
		types[typ] = struct{}{}
		size := uint64(binary.LittleEndian.Uint32(data[off+4:]))
		offset := binary.LittleEndian.Uint64(data[off+8:])
		if offset%Alignment != 0 || offset < tableLen {
			return nil, fmt.Errorf("PAC: invalid buffer %d offset %d", i, offset)
		}
		if size > uint64(len(data)) || offset > uint64(len(data))-size {
			return nil, fmt.Errorf("PAC: buffer %d exceeds input", i)
		}
		end := offset + size
		for _, prior := range spans {
			if offset < prior.end && prior.start < end {
				return nil, fmt.Errorf("PAC: buffer %d overlaps another buffer", i)
			}
		}
		spans = append(spans, span{start: offset, end: end})
		p.Buffers[i] = Buffer{Type: typ, Data: append([]byte(nil), data[offset:offset+size]...)}
	}
	return p, nil
}

// New returns an empty version-zero PAC.
func New() *PAC { return &PAC{} }

// MarshalBinary encodes the PAC with contiguous, eight-byte-aligned payloads.
func (p *PAC) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("PAC: nil value")
	}
	if len(p.Buffers) > maxBuffers {
		return nil, fmt.Errorf("PAC: too many buffers")
	}
	if p.raw != nil {
		if encoded, ok := marshalPreservingLayout(p); ok {
			return encoded, nil
		}
	}
	tableLen := headerLen + len(p.Buffers)*bufferLen
	total := tableLen
	for _, b := range p.Buffers {
		if len(b.Data) > int(^uint32(0)) {
			return nil, fmt.Errorf("PAC: buffer too large")
		}
		total += (len(b.Data) + Alignment - 1) &^ (Alignment - 1)
	}
	out := make([]byte, total)
	binary.LittleEndian.PutUint32(out, uint32(len(p.Buffers)))
	binary.LittleEndian.PutUint32(out[4:], p.Version)
	offset := tableLen
	for i, b := range p.Buffers {
		off := headerLen + i*bufferLen
		binary.LittleEndian.PutUint32(out[off:], b.Type)
		binary.LittleEndian.PutUint32(out[off+4:], uint32(len(b.Data)))
		binary.LittleEndian.PutUint64(out[off+8:], uint64(offset))
		copy(out[offset:], b.Data)
		offset += (len(b.Data) + Alignment - 1) &^ (Alignment - 1)
	}
	return out, nil
}

func marshalPreservingLayout(p *PAC) ([]byte, bool) {
	if len(p.raw) < headerLen {
		return nil, false
	}
	count := binary.LittleEndian.Uint32(p.raw)
	if int(count) != len(p.Buffers) ||
		binary.LittleEndian.Uint32(p.raw[4:]) != p.Version {
		return nil, false
	}
	tableLen := headerLen + int(count)*bufferLen
	if tableLen > len(p.raw) {
		return nil, false
	}
	out := append([]byte(nil), p.raw...)
	for i, b := range p.Buffers {
		off := headerLen + i*bufferLen
		if binary.LittleEndian.Uint32(out[off:]) != b.Type ||
			binary.LittleEndian.Uint32(out[off+4:]) != uint32(len(b.Data)) {
			return nil, false
		}
		size := uint64(binary.LittleEndian.Uint32(out[off+4:]))
		offset := binary.LittleEndian.Uint64(out[off+8:])
		if size > uint64(len(out)) || offset > uint64(len(out))-size {
			return nil, false
		}
		copy(out[offset:offset+size], b.Data)
	}
	return out, true
}

// Buffer returns a copy of the uniquely identified buffer.
func (p *PAC) Buffer(typ uint32) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	var found []byte
	for _, b := range p.Buffers {
		if b.Type == typ {
			if found != nil {
				return nil, false
			}
			found = b.Data
		}
	}
	if found == nil {
		return nil, false
	}
	return append([]byte(nil), found...), true
}

func (p *PAC) setBuffer(typ uint32, data []byte) {
	p.dirty = true
	for i := range p.Buffers {
		if p.Buffers[i].Type == typ {
			p.Buffers[i].Data = append([]byte(nil), data...)
			return
		}
	}
	p.Buffers = append(p.Buffers, Buffer{Type: typ, Data: append([]byte(nil), data...)})
}

func (p *PAC) signature(typ uint32) ([]byte, bool) {
	data, ok := p.Buffer(typ)
	if !ok || len(data) < 4 {
		return nil, false
	}
	return append([]byte(nil), data[4:]...), true
}

func checksumType(key Key) (int32, error) {
	if key.EType == nil || len(key.Key) == 0 {
		return 0, fmt.Errorf("PAC: missing signing key")
	}
	switch key.EType.ID() {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128, nil
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256, nil
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128, nil
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256, nil
	default:
		return 0, fmt.Errorf("PAC: unsupported signing enctype %d", key.EType.ID())
	}
}

func ensureSignature(p *PAC, typ uint32, key Key) error {
	cksumType, err := checksumType(key)
	if err != nil {
		return err
	}
	size := 4 + key.EType.ChecksumSize()
	data, ok := p.Buffer(typ)
	if ok && len(data) != size {
		return fmt.Errorf("PAC: signature buffer %d has length %d, want %d", typ, len(data), size)
	}
	if !ok {
		data = make([]byte, size)
	}
	binary.LittleEndian.PutUint32(data, uint32(cksumType))
	clear(data[4:])
	p.setBuffer(typ, data)
	return nil
}

func zeroSignature(p *PAC, typ uint32) error {
	for i := range p.Buffers {
		if p.Buffers[i].Type == typ {
			if len(p.Buffers[i].Data) < 4 {
				return fmt.Errorf("PAC: malformed signature buffer %d", typ)
			}
			p.dirty = true
			clear(p.Buffers[i].Data[4:])
			return nil
		}
	}
	return fmt.Errorf("PAC: missing signature buffer %d", typ)
}

func signatureValue(p *PAC, typ uint32) ([]byte, error) {
	for _, b := range p.Buffers {
		if b.Type == typ {
			if len(b.Data) < 4 {
				return nil, fmt.Errorf("PAC: malformed signature buffer %d", typ)
			}
			return append([]byte(nil), b.Data[4:]...), nil
		}
	}
	return nil, fmt.Errorf("PAC: missing signature buffer %d", typ)
}

func (p *PAC) addClientInfo(authtime time.Time, client principal.Principal) error {
	name, err := client.Format()
	if err != nil {
		return err
	}
	if _, ok := p.Buffer(ClientInfo); ok {
		return nil
	}
	encoded := utf16.Encode([]rune(name))
	if len(encoded)*2 > math.MaxUint16 {
		return fmt.Errorf("PAC: client-info name is too long")
	}
	data := make([]byte, 10+len(encoded)*2)
	filetime := uint64(authtime.Unix()+11644473600) * 10000000
	binary.LittleEndian.PutUint64(data, filetime)
	binary.LittleEndian.PutUint16(data[8:], uint16(len(encoded)*2))
	for i, r := range encoded {
		binary.LittleEndian.PutUint16(data[10+i*2:], r)
	}
	p.setBuffer(ClientInfo, data)
	return nil
}

// SetClientInfo replaces the client-info buffer with the supplied values.
// It is useful when a KDC substitutes an S4U client identity.
func (p *PAC) SetClientInfo(authtime time.Time, client principal.Principal) error {
	if p == nil {
		return fmt.Errorf("PAC: nil value")
	}
	name, err := client.Format()
	if err != nil {
		return err
	}
	encoded := utf16.Encode([]rune(name))
	if len(encoded)*2 > math.MaxUint16 {
		return fmt.Errorf("PAC: client-info name is too long")
	}
	data := make([]byte, 10+len(encoded)*2)
	filetime := uint64(authtime.Unix()+11644473600) * 10000000
	binary.LittleEndian.PutUint64(data, filetime)
	binary.LittleEndian.PutUint16(data[8:], uint16(len(encoded)*2))
	for i, r := range encoded {
		binary.LittleEndian.PutUint16(data[10+i*2:], r)
	}
	p.setBuffer(ClientInfo, data)
	return nil
}

// Sign adds or replaces PAC signature buffers and returns the encoded PAC.
// For a service ticket, use SignWithTicket when the encoded dummy ticket is
// available so the type-16 ticket checksum is included before the PAC
// checksums are calculated.
func (p *PAC) Sign(authtime time.Time, client *principal.Principal, serverKey, privsvrKey Key, serviceTicket bool) ([]byte, error) {
	return p.sign(authtime, client, serverKey, privsvrKey, serviceTicket, nil)
}

// SignWithTicket signs a PAC using MIT's ticket-signing order. ticket is the
// encoded EncTicketPart containing a one-byte dummy PAC authorization-data
// element.
func (p *PAC) SignWithTicket(authtime time.Time, client *principal.Principal,
	serverKey, privsvrKey Key, ticket []byte) ([]byte, error) {
	if len(ticket) == 0 {
		return nil, fmt.Errorf("PAC: missing encoded dummy ticket")
	}
	return p.sign(authtime, client, serverKey, privsvrKey, true, ticket)
}

func (p *PAC) sign(authtime time.Time, client *principal.Principal, serverKey, privsvrKey Key,
	serviceTicket bool, ticket []byte) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("PAC: nil value")
	}
	p.dirty = true
	if client != nil {
		if err := p.addClientInfo(authtime, *client); err != nil {
			return nil, err
		}
	}
	if err := ensureSignature(p, ServerChecksum, serverKey); err != nil {
		return nil, err
	}
	if err := ensureSignature(p, KDCChecksum, privsvrKey); err != nil {
		return nil, err
	}
	if serviceTicket {
		if err := ensureSignature(p, FullChecksum, privsvrKey); err != nil {
			return nil, err
		}
		if ticket != nil {
			if err := ensureSignature(p, TicketChecksum, privsvrKey); err != nil {
				return nil, err
			}
		}
	}
	if ticket != nil {
		value, err := privsvrKey.EType.Checksum(privsvrKey.Key, checksumUsage, ticket)
		if err != nil {
			return nil, err
		}
		p.setSignature(TicketChecksum, value)
	}
	if err := zeroSignature(p, ServerChecksum); err != nil {
		return nil, err
	}
	if err := zeroSignature(p, KDCChecksum); err != nil {
		return nil, err
	}
	if serviceTicket {
		if err := zeroSignature(p, FullChecksum); err != nil {
			return nil, err
		}
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if serviceTicket {
		value, err := privsvrKey.EType.Checksum(privsvrKey.Key, checksumUsage, encoded)
		if err != nil {
			return nil, err
		}
		p.setSignature(FullChecksum, value)
	}
	encoded, err = p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	serverValue, err := serverKey.EType.Checksum(serverKey.Key, checksumUsage, encoded)
	if err != nil {
		return nil, err
	}
	p.setSignature(ServerChecksum, serverValue)
	serverBuffer, ok := p.Buffer(ServerChecksum)
	if !ok {
		return nil, fmt.Errorf("PAC: missing server checksum")
	}
	privValue, err := privsvrKey.EType.Checksum(privsvrKey.Key, checksumUsage, serverBuffer)
	if err != nil {
		return nil, err
	}
	p.setSignature(KDCChecksum, privValue)
	return p.MarshalBinary()
}

// AddTicketSignature adds or replaces the type-16 checksum over an encoded
// EncTicketPart. MIT computes this after placing a dummy PAC authdata element
// in the ticket and before replacing that element with the signed PAC.
func (p *PAC) AddTicketSignature(encTicketPart []byte, privsvrKey Key) error {
	if p == nil {
		return fmt.Errorf("PAC: nil value")
	}
	p.dirty = true
	if err := ensureSignature(p, TicketChecksum, privsvrKey); err != nil {
		return err
	}
	value, err := privsvrKey.EType.Checksum(privsvrKey.Key, checksumUsage, encTicketPart)
	if err != nil {
		return err
	}
	p.setSignature(TicketChecksum, value)
	return nil
}

// VerifyTicketSignature verifies the type-16 checksum against an encoded
// EncTicketPart containing the dummy PAC authorization-data element used
// during signing.
func (p *PAC) VerifyTicketSignature(encTicketPart []byte, privsvrKey Key) error {
	if p == nil {
		return fmt.Errorf("PAC: nil value")
	}
	if privsvrKey.EType == nil || len(privsvrKey.Key) == 0 {
		return fmt.Errorf("PAC: missing ticket verification key")
	}
	expectedType, err := checksumType(privsvrKey)
	if err != nil {
		return err
	}
	gotType, ok := p.signatureType(TicketChecksum)
	if !ok || gotType != expectedType {
		return fmt.Errorf("PAC: ticket checksum type mismatch")
	}
	expected, ok := p.signature(TicketChecksum)
	if !ok {
		return fmt.Errorf("PAC: missing or malformed ticket checksum")
	}
	if err := privsvrKey.EType.VerifyChecksum(privsvrKey.Key, checksumUsage,
		encTicketPart, expected); err != nil {
		return fmt.Errorf("PAC ticket checksum: %w", err)
	}
	return nil
}

func (p *PAC) setSignature(typ uint32, value []byte) {
	p.dirty = true
	for i := range p.Buffers {
		if p.Buffers[i].Type == typ {
			p.Buffers[i].Data = append(p.Buffers[i].Data[:4], value...)
			return
		}
	}
}

// Verify verifies the server checksum and, when supplied, the KDC checksum.
// A nil privsvr key skips the KDC checksum, as MIT does for S4U PACs without
// an available TGT key.
func (p *PAC) Verify(serverKey, privsvrKey Key) error {
	if p == nil {
		return fmt.Errorf("PAC: nil value")
	}
	if serverKey.EType == nil || len(serverKey.Key) == 0 {
		return fmt.Errorf("PAC: missing server verification key")
	}
	serverType, err := checksumType(serverKey)
	if err != nil {
		return err
	}
	serverExpected, ok := p.signature(ServerChecksum)
	if !ok {
		return fmt.Errorf("PAC: missing or malformed server checksum")
	}
	if got, ok := p.signatureType(ServerChecksum); !ok || got != serverType {
		return fmt.Errorf("PAC: server checksum type mismatch")
	}
	var privExpected, fullExpected []byte
	if _, ok := p.Buffer(KDCChecksum); ok {
		privExpected, ok = p.signature(KDCChecksum)
		if !ok {
			return fmt.Errorf("PAC: missing or malformed KDC checksum")
		}
		if privsvrKey.EType != nil {
			privType, err := checksumType(privsvrKey)
			if err != nil {
				return err
			}
			if got, ok := p.signatureType(KDCChecksum); !ok || got != privType {
				return fmt.Errorf("PAC: KDC checksum type mismatch")
			}
		}
	}
	if _, ok := p.Buffer(FullChecksum); ok {
		fullExpected, ok = p.signature(FullChecksum)
		if !ok {
			return fmt.Errorf("PAC: missing or malformed full checksum")
		}
		if privsvrKey.EType != nil {
			privType, err := checksumType(privsvrKey)
			if err != nil {
				return err
			}
			if got, ok := p.signatureType(FullChecksum); !ok || got != privType {
				return fmt.Errorf("PAC: full checksum type mismatch")
			}
		}
	}
	if fullExpected != nil && privsvrKey.EType != nil {
		work := clone(p)
		if err := zeroSignature(work, ServerChecksum); err != nil {
			return err
		}
		if err := zeroSignature(work, KDCChecksum); err != nil {
			return err
		}
		if err := zeroSignature(work, FullChecksum); err != nil {
			return err
		}
		data, err := work.MarshalBinary()
		if err != nil {
			return err
		}
		// VerifyChecksum below performs the same calculation; retaining the
		// isolated work copy ensures signature verification never mutates p.
		if err := privsvrKey.EType.VerifyChecksum(privsvrKey.Key, checksumUsage, data, fullExpected); err != nil {
			return fmt.Errorf("PAC full checksum: %w", err)
		}
	}
	work := clone(p)
	if err := zeroSignature(work, ServerChecksum); err != nil {
		return err
	}
	if err := zeroSignature(work, KDCChecksum); err != nil {
		return err
	}
	data, err := work.MarshalBinary()
	if err != nil {
		return err
	}
	if err := serverKey.EType.VerifyChecksum(serverKey.Key, checksumUsage, data, serverExpected); err != nil {
		return fmt.Errorf("PAC server checksum: %w", err)
	}
	if privExpected != nil && privsvrKey.EType != nil {
		work = clone(p)
		if err := zeroSignature(work, KDCChecksum); err != nil {
			return err
		}
		serverBuffer, ok := work.Buffer(ServerChecksum)
		if !ok {
			return fmt.Errorf("PAC: missing server checksum")
		}
		if err := privsvrKey.EType.VerifyChecksum(privsvrKey.Key, checksumUsage, serverBuffer, privExpected); err != nil {
			return fmt.Errorf("PAC KDC checksum: %w", err)
		}
	}
	return nil
}

func (p *PAC) signatureType(typ uint32) (int32, bool) {
	data, ok := p.Buffer(typ)
	if !ok || len(data) < 4 {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(data)), true
}

func clone(p *PAC) *PAC {
	out := &PAC{Version: p.Version, Buffers: make([]Buffer, len(p.Buffers))}
	out.raw = append([]byte(nil), p.raw...)
	for i, b := range p.Buffers {
		out.Buffers[i] = Buffer{Type: b.Type, Data: append([]byte(nil), b.Data...)}
	}
	return out
}

// ClientInfo returns the NT authtime and UTF-16 client name from buffer 10.
func (p *PAC) ClientInfo() (time.Time, string, error) {
	data, ok := p.Buffer(ClientInfo)
	if !ok || len(data) < 10 {
		return time.Time{}, "", fmt.Errorf("PAC: missing or truncated client-info buffer")
	}
	n := int(binary.LittleEndian.Uint16(data[8:]))
	if n%2 != 0 || 10+n > len(data) {
		return time.Time{}, "", fmt.Errorf("PAC: invalid client-info name length")
	}
	units := make([]uint16, n/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[10+i*2:])
	}
	filetime := binary.LittleEndian.Uint64(data)
	seconds := int64(filetime/10000000) - 11644473600
	return time.Unix(seconds, 0).UTC(), string(utf16.Decode(units)), nil
}

// EqualEncoded reports whether two PACs have identical canonical encodings.
func EqualEncoded(a, b *PAC) bool {
	if a == nil || b == nil {
		return a == b
	}
	ab, aerr := a.MarshalBinary()
	bb, berr := b.MarshalBinary()
	return aerr == nil && berr == nil && bytes.Equal(ab, bb)
}

package gssapi

import (
	"encoding/binary"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

// IOVBufferType identifies the role of a buffer in an RFC 4121 IOV
// operation.  DATA buffers are encrypted (for WrapIOV with confidentiality);
// SIGN_ONLY buffers are authenticated but are not encrypted.
type IOVBufferType uint32

const (
	IOVBufferTypeHeader IOVBufferType = iota
	IOVBufferTypeData
	IOVBufferTypePadding
	IOVBufferTypeTrailer
	IOVBufferTypeSignOnly
	IOVBufferTypeStream
)

const (
	IOVHeader   = IOVBufferTypeHeader
	IOVData     = IOVBufferTypeData
	IOVPadding  = IOVBufferTypePadding
	IOVTrailer  = IOVBufferTypeTrailer
	IOVSignOnly = IOVBufferTypeSignOnly
	IOVStream   = IOVBufferTypeStream
)

// IOVBuffer contains one RFC 4121 IOV fragment.  Header, padding, and trailer
// buffers are populated by WrapIOV when they are nil or have sufficient
// capacity.  UnwrapIOV replaces DATA buffers with their plaintext.
type IOVBuffer struct {
	Type   IOVBufferType
	Buffer []byte
}

// IOVOptions controls optional per-message IOV behavior.
type IOVOptions struct {
	DCEStyle bool
}

// IOVLengths reports the sizes required for the generated IOV fragments.
type IOVLengths struct {
	Header  int
	Padding int
	Trailer int
}

// WrapIOVLength returns the RFC 4121 header, padding, and trailer sizes for
// the supplied message.  The DATA and SIGN_ONLY buffers are not modified.
func (c *Context) WrapIOVLength(iov []IOVBuffer, sealed bool) (IOVLengths, error) {
	if c == nil {
		return IOVLengths{}, fmt.Errorf("GSS IOV wrap length: nil context")
	}
	if _, err := parseIOV(iov, false); err != nil {
		return IOVLengths{}, err
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return IOVLengths{}, err
	}
	var lengths IOVLengths
	if sealed {
		ec := 0
		if c.dceStyle {
			ec = 16
		}
		lengths = IOVLengths{
			Header:  16 + 16,
			Padding: 0,
			Trailer: ec + 16 + etype.ChecksumSize(),
		}
	} else {
		lengths = IOVLengths{Header: 16, Padding: 0, Trailer: etype.ChecksumSize()}
	}
	if err := sizeIOVBuffer(&iov[parseHeaderIndex(iov)], lengths.Header); err != nil {
		return IOVLengths{}, err
	}
	if padding := parseBufferIndex(iov, IOVBufferTypePadding); padding >= 0 {
		iov[padding].Buffer = iov[padding].Buffer[:0]
	}
	if trailer := parseBufferIndex(iov, IOVBufferTypeTrailer); trailer >= 0 {
		if err := sizeIOVBuffer(&iov[trailer], lengths.Trailer); err != nil {
			return IOVLengths{}, err
		}
	}
	return lengths, nil
}

// WrapIOVSize is an alias for WrapIOVLength.
func (c *Context) WrapIOVSize(iov []IOVBuffer, sealed bool) (IOVLengths, error) {
	return c.WrapIOVLength(iov, sealed)
}

// WrapIOVWithOptions is equivalent to WrapIOV with optional DCE framing.
func (c *Context) WrapIOVWithOptions(iov []IOVBuffer, sealed bool, options IOVOptions) error {
	if c == nil {
		return fmt.Errorf("GSS IOV wrap: nil context")
	}
	previous := c.dceStyle
	c.dceStyle = options.DCEStyle
	defer func() { c.dceStyle = previous }()
	return c.WrapIOV(iov, sealed)
}

// WrapIOV emits an RFC 4121 wrap token into typed IOV buffers.  It supports
// both confidentiality and integrity-only tokens.  DATA is distributed back
// across the original DATA fragments, while HEADER and TRAILER receive the
// token framing and cryptographic trailer.
func (c *Context) WrapIOV(iov []IOVBuffer, sealed bool) error {
	if c == nil {
		return fmt.Errorf("GSS IOV wrap: nil context")
	}
	parts, err := parseIOV(iov, false)
	if err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return err
	}
	checksumSize := etype.ChecksumSize()
	lengths, err := c.WrapIOVLength(iov, sealed)
	if err != nil {
		return err
	}
	plain := concatBuffers(iov, parts.data)
	if len(parts.signOnly) != 0 {
		return c.wrapIOVWithAssociatedData(iov, parts, sealed)
	}
	var token []byte
	if sealed && c.dceStyle {
		token, err = c.wrapDCE(plain)
	} else {
		token, err = c.wrap(plain, sealed)
	}
	if err != nil {
		return err
	}
	if sealed {
		if len(token) < 16+checksumSize+32 ||
			len(token)-16-checksumSize-32 != len(plain) {
			return fmt.Errorf("GSS IOV wrap: invalid generated token length")
		}
	} else if len(token) != 16+len(plain)+lengths.Trailer {
		return fmt.Errorf("GSS IOV wrap: invalid generated token length")
	}
	if sealed {
		encrypted := token[16 : len(token)-checksumSize]
		if err := setIOVOutput(&iov[parts.header],
			append(append([]byte(nil), token[:16]...), encrypted[:16]...)); err != nil {
			return err
		}
		if err := distributeIOV(iov, parts.data, encrypted[16:len(encrypted)-16]); err != nil {
			return err
		}
		trailer := make([]byte, lengths.Trailer)
		if c.dceStyle {
			for index := range trailer[:16] {
				trailer[index] = 0xff
			}
		}
		copy(trailer[lengths.Trailer-16-checksumSize:], encrypted[len(encrypted)-16:])
		copy(trailer[lengths.Trailer-checksumSize:], token[len(token)-checksumSize:])
		if parts.trailer >= 0 {
			if err := setIOVOutput(&iov[parts.trailer], trailer); err != nil {
				return err
			}
		}
	} else {
		if err := setIOVOutput(&iov[parts.header], token[:lengths.Header]); err != nil {
			return err
		}
		if err := distributeIOV(iov, parts.data, token[lengths.Header:len(token)-lengths.Trailer]); err != nil {
			return err
		}
		if parts.trailer >= 0 {
			if err := setIOVOutput(&iov[parts.trailer], token[len(token)-lengths.Trailer:]); err != nil {
				return err
			}
		}
	}
	if parts.padding >= 0 {
		iov[parts.padding].Buffer = iov[parts.padding].Buffer[:0]
	}
	return nil
}

func (c *Context) wrapDCE(data []byte) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return nil, err
	}
	flags := byte(tokenFlagSealed)
	if !c.initiator {
		flags |= tokenFlagSentByAcceptor
	}
	if c.acceptorSubkey {
		flags |= tokenFlagAcceptorSubkey
	}
	seq := c.sendSeq
	c.sendSeq++
	header := messageHeader([]byte{0x05, 0x04}, flags, 16, 0, seq)
	input := append(append([]byte(nil), data...), header...)
	usage := uint32(24)
	if !c.initiator {
		usage = 22
	}
	encrypted, err := etype.Encrypt(c.key.KeyValue, usage, input)
	if err != nil {
		return nil, fmt.Errorf("GSS DCE wrap encryption: %w", err)
	}
	return append(header, encrypted...), nil
}

// UnwrapIOV verifies an RFC 4121 token represented by IOV buffers.  STREAM
// may be used instead of HEADER/DATA/TRAILER when a complete token is
// available in one buffer.
func (c *Context) UnwrapIOV(iov []IOVBuffer) error {
	if c == nil {
		return fmt.Errorf("GSS IOV unwrap: nil context")
	}
	parts, err := parseIOV(iov, true)
	if err != nil {
		return err
	}
	if parts.stream >= 0 {
		plain, err := c.unwrap(iov[parts.stream].Buffer)
		if err != nil {
			return err
		}
		iov[parts.stream].Buffer = plain
		return nil
	}
	if len(parts.signOnly) != 0 {
		if len(iov[parts.header].Buffer) < 16 {
			return fmt.Errorf("GSS IOV unwrap: invalid header")
		}
		header := append([]byte(nil), iov[parts.header].Buffer[:16]...)
		if err := c.validateIncoming(header); err != nil {
			return err
		}
		etype, err := crypto.NewRegistry().Get(c.key.KeyType)
		if err != nil {
			return err
		}
		ec := int(binary.BigEndian.Uint16(header[4:6]))
		sealed := header[2]&tokenFlagSealed != 0
		if sealed {
			body := append([]byte(nil), iov[parts.header].Buffer[16:]...)
			for _, index := range parts.data {
				body = append(body, iov[index].Buffer...)
			}
			if parts.padding >= 0 {
				body = append(body, iov[parts.padding].Buffer...)
			}
			ec := int(binary.BigEndian.Uint16(header[4:6]))
			if len(iov[parts.trailer].Buffer) < ec {
				return fmt.Errorf("GSS IOV unwrap: invalid trailer")
			}
			body = append(body, iov[parts.trailer].Buffer[ec:]...)
			associated := concatBuffers(iov, parts.signOnly)
			usage := uint32(24)
			if c.initiator {
				usage = 22
			}
			plain, err := crypto.DecryptWithAssociatedData(etype, c.key.KeyValue, usage, body, associated)
			if err != nil || len(plain) < 16 {
				return fmt.Errorf("GSS IOV unwrap: %w", krberrors.ErrIntegrity)
			}
			expected := plain[len(plain)-16:]
			if !equalBytes(expected, header) {
				return fmt.Errorf("GSS IOV unwrap: %w", krberrors.ErrIntegrity)
			}
			if err := distributeIOV(iov, parts.data, plain[:len(plain)-16]); err != nil {
				return err
			}
			c.recvSeq++
			return nil
		}
		if ec != etype.ChecksumSize() || len(iov[parts.trailer].Buffer) != ec {
			return fmt.Errorf("GSS IOV unwrap: %w", krberrors.ErrIntegrity)
		}
		canonical := append([]byte(nil), header...)
		canonical[4], canonical[5], canonical[6], canonical[7] = 0, 0, 0, 0
		signed := concatBuffers(iov, parts.data)
		signed = append(signed, concatBuffers(iov, parts.signOnly)...)
		signed = append(signed, canonical...)
		usage := uint32(24)
		if c.initiator {
			usage = 22
		}
		if err := etype.VerifyChecksum(c.key.KeyValue, usage, signed, iov[parts.trailer].Buffer); err != nil {
			return fmt.Errorf("GSS IOV unwrap: %w", err)
		}
		c.recvSeq++
		return nil
	}
	token := make([]byte, 0, 16+len(iov[parts.header].Buffer)-16+parts.dataLen+len(iov[parts.trailer].Buffer))
	token = append(token, iov[parts.header].Buffer[:16]...)
	if len(iov[parts.header].Buffer) > 16 {
		token = append(token, iov[parts.header].Buffer[16:]...)
	}
	for _, index := range parts.data {
		token = append(token, iov[index].Buffer...)
	}
	if parts.padding >= 0 {
		token = append(token, iov[parts.padding].Buffer...)
	}
	if parts.trailer >= 0 {
		if iov[parts.header].Buffer[2]&tokenFlagSealed != 0 {
			ec := int(binary.BigEndian.Uint16(iov[parts.header].Buffer[4:6]))
			if ec > len(iov[parts.trailer].Buffer) {
				return fmt.Errorf("GSS IOV unwrap: invalid trailer")
			}
			token = append(token, iov[parts.trailer].Buffer[ec:]...)
		} else {
			token = append(token, iov[parts.trailer].Buffer...)
		}
	}
	plain, err := c.unwrap(token)
	if err != nil {
		return err
	}
	if err := distributeIOV(iov, parts.data, plain); err != nil {
		return err
	}
	return nil
}

type iovLayout struct {
	header   int
	padding  int
	trailer  int
	stream   int
	data     []int
	signOnly []int
	dataLen  int
}

func parseIOV(iov []IOVBuffer, unwrap bool) (iovLayout, error) {
	parts := iovLayout{header: -1, padding: -1, trailer: -1, stream: -1}
	for index, buffer := range iov {
		switch buffer.Type {
		case IOVBufferTypeHeader:
			if parts.header >= 0 {
				return iovLayout{}, fmt.Errorf("GSS IOV: duplicate HEADER buffer")
			}
			parts.header = index
		case IOVBufferTypeData:
			parts.data = append(parts.data, index)
			parts.dataLen += len(buffer.Buffer)
		case IOVBufferTypePadding:
			if parts.padding >= 0 {
				return iovLayout{}, fmt.Errorf("GSS IOV: duplicate PADDING buffer")
			}
			parts.padding = index
		case IOVBufferTypeTrailer:
			if parts.trailer >= 0 {
				return iovLayout{}, fmt.Errorf("GSS IOV: duplicate TRAILER buffer")
			}
			parts.trailer = index
		case IOVBufferTypeSignOnly:
			parts.signOnly = append(parts.signOnly, index)
		case IOVBufferTypeStream:
			if parts.stream >= 0 {
				return iovLayout{}, fmt.Errorf("GSS IOV: duplicate STREAM buffer")
			}
			parts.stream = index
		default:
			return iovLayout{}, fmt.Errorf("GSS IOV: unknown buffer type %d", buffer.Type)
		}
	}
	if parts.stream >= 0 {
		if !unwrap || len(parts.data) != 0 || parts.header >= 0 || parts.trailer >= 0 ||
			parts.padding >= 0 || len(parts.signOnly) != 0 {
			return iovLayout{}, fmt.Errorf("GSS IOV: STREAM cannot be combined with other buffers")
		}
		return parts, nil
	}
	if parts.header < 0 {
		return iovLayout{}, fmt.Errorf("GSS IOV: missing HEADER buffer")
	}
	if len(parts.data) == 0 {
		return iovLayout{}, fmt.Errorf("GSS IOV: missing DATA buffer")
	}
	if unwrap && parts.trailer < 0 {
		return iovLayout{}, fmt.Errorf("GSS IOV: missing TRAILER buffer")
	}
	return parts, nil
}

func concatBuffers(iov []IOVBuffer, indices []int) []byte {
	var total int
	for _, index := range indices {
		total += len(iov[index].Buffer)
	}
	value := make([]byte, 0, total)
	for _, index := range indices {
		value = append(value, iov[index].Buffer...)
	}
	return value
}

func setIOVOutput(buffer *IOVBuffer, value []byte) error {
	if buffer.Buffer != nil && cap(buffer.Buffer) < len(value) {
		return fmt.Errorf("GSS IOV: buffer too small (have %d, need %d)", cap(buffer.Buffer), len(value))
	}
	if buffer.Buffer == nil {
		buffer.Buffer = append([]byte(nil), value...)
		return nil
	}
	buffer.Buffer = buffer.Buffer[:len(value)]
	copy(buffer.Buffer, value)
	return nil
}

func sizeIOVBuffer(buffer *IOVBuffer, length int) error {
	if buffer.Buffer != nil && cap(buffer.Buffer) < length {
		return fmt.Errorf("GSS IOV: buffer too small (have %d, need %d)", cap(buffer.Buffer), length)
	}
	if buffer.Buffer == nil {
		buffer.Buffer = make([]byte, length)
	} else {
		buffer.Buffer = buffer.Buffer[:length]
	}
	return nil
}

func parseHeaderIndex(iov []IOVBuffer) int {
	return parseBufferIndex(iov, IOVBufferTypeHeader)
}

func parseBufferIndex(iov []IOVBuffer, typ IOVBufferType) int {
	for index := range iov {
		if iov[index].Type == typ {
			return index
		}
	}
	return -1
}

func distributeIOV(iov []IOVBuffer, indices []int, value []byte) error {
	offset := 0
	unknown := -1
	for _, index := range indices {
		if iov[index].Buffer == nil {
			if unknown >= 0 {
				return fmt.Errorf("GSS IOV: multiple un-sized DATA buffers")
			}
			unknown = index
			continue
		}
		length := len(iov[index].Buffer)
		if offset+length > len(value) {
			return fmt.Errorf("GSS IOV: data length mismatch")
		}
		copy(iov[index].Buffer, value[offset:offset+length])
		offset += length
	}
	if unknown >= 0 {
		iov[unknown].Buffer = append([]byte(nil), value[offset:]...)
		offset = len(value)
	}
	if offset != len(value) {
		return fmt.Errorf("GSS IOV: data length mismatch")
	}
	return nil
}

func (c *Context) wrapIOVWithAssociatedData(iov []IOVBuffer, parts iovLayout, sealed bool) error {
	etype, err := crypto.NewRegistry().Get(c.key.KeyType)
	if err != nil {
		return err
	}
	flags := byte(0)
	if !c.initiator {
		flags |= tokenFlagSentByAcceptor
	}
	if c.acceptorSubkey {
		flags |= tokenFlagAcceptorSubkey
	}
	usage := uint32(24)
	if !c.initiator {
		usage = 22
	}
	plain := concatBuffers(iov, parts.data)
	var token []byte
	if sealed {
		ec := 0
		if c.dceStyle {
			ec = 16
		}
		header := messageHeader([]byte{0x05, 0x04}, flags|tokenFlagSealed, ec, 0, c.sendSeq)
		encrypted, err := crypto.EncryptWithAssociatedData(etype, c.key.KeyValue, usage,
			append(append([]byte(nil), plain...), header...), concatBuffers(iov, parts.signOnly))
		if err != nil {
			return err
		}
		token = append(header, encrypted...)
	} else {
		header := messageHeader([]byte{0x05, 0x04}, flags, etype.ChecksumSize(), 0, c.sendSeq)
		canonical := append([]byte(nil), header...)
		canonical[4], canonical[5], canonical[6], canonical[7] = 0, 0, 0, 0
		signed := append(append([]byte(nil), plain...), concatBuffers(iov, parts.signOnly)...)
		signed = append(signed, canonical...)
		mac, err := etype.Checksum(c.key.KeyValue, usage, signed)
		if err != nil {
			return err
		}
		token = append(append(header, plain...), mac...)
	}
	lengths, err := c.WrapIOVLength(iov, sealed)
	if err != nil {
		return err
	}
	if sealed {
		checksumSize := etype.ChecksumSize()
		encrypted := token[16 : len(token)-checksumSize]
		if len(encrypted) < 16 {
			return fmt.Errorf("GSS IOV wrap: invalid encrypted token length")
		}
		if err := setIOVOutput(&iov[parts.header],
			append(append([]byte(nil), token[:16]...), encrypted[:16]...)); err != nil {
			return err
		}
		if err := distributeIOV(iov, parts.data, encrypted[16:len(encrypted)-16]); err != nil {
			return err
		}
		trailer := make([]byte, lengths.Trailer)
		ec := lengths.Trailer - 16 - checksumSize
		for index := range trailer[:ec] {
			trailer[index] = 0xff
		}
		copy(trailer[ec:], encrypted[len(encrypted)-16:])
		copy(trailer[ec+16:], token[len(token)-checksumSize:])
		if parts.trailer >= 0 {
			if err := setIOVOutput(&iov[parts.trailer], trailer); err != nil {
				return err
			}
		}
	} else {
		if err := setIOVOutput(&iov[parts.header], token[:lengths.Header]); err != nil {
			return err
		}
		if err := distributeIOV(iov, parts.data, token[lengths.Header:len(token)-lengths.Trailer]); err != nil {
			return err
		}
		if parts.trailer >= 0 {
			if err := setIOVOutput(&iov[parts.trailer], token[len(token)-lengths.Trailer:]); err != nil {
				return err
			}
		}
	}
	if parts.padding >= 0 {
		iov[parts.padding].Buffer = iov[parts.padding].Buffer[:0]
	}
	c.sendSeq++
	return nil
}

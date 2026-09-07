package spnego

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
)

const NegoExOID = "1.3.6.1.4.1.311.2.2.30"

const negoExSignature uint64 = 0x535458454f47454e

const (
	NegoExInitiatorNego uint32 = iota
	NegoExAcceptorNego
	NegoExInitiatorMetaData
	NegoExAcceptorMetaData
	NegoExChallenge
	NegoExAPRequest
	NegoExVerify
	NegoExAlert

	negoExBaseHeaderSize     = 40
	negoExNegoHeaderSize     = 96
	negoExExchangeHeaderSize = 64
	negoExVerifyHeaderSize   = 80
	negoExAlertHeaderSize    = 72

	NegoExChecksumSchemeRFC3961  uint32 = 1
	NegoExInitiatorChecksumUsage        = 23
	NegoExAcceptorChecksumUsage         = 25
	NegoExAlertPulse                    = 1
	NegoExAlertVerifyNoKey              = 1
	negoExCriticalExtension      uint32 = 0x80000000
)

// NegoExAuthScheme is a little-endian GUID identifying an authentication
// mechanism in a NegoEx message.
type NegoExAuthScheme [16]byte

// NegoExExtension is an extension descriptor in a NEGO_MESSAGE.
type NegoExExtension struct {
	Type  uint32
	Value []byte
}

// NegoExMessage is one MS-NEGOEX message.
type NegoExMessage struct {
	Type           uint32
	Sequence       uint32
	ConversationID [16]byte
	Random         [32]byte
	AuthSchemes    []NegoExAuthScheme
	Extensions     []NegoExExtension
	AuthScheme     NegoExAuthScheme
	Token          []byte
	ChecksumType   uint32
	ChecksumScheme uint32
	Checksum       []byte
	AlertCode      uint32
	Alerts         []NegoExAlertEntry
	Raw            []byte
	Offset         int
}

// NegoExAlertEntry is an alert vector entry. Value is the alert payload.
type NegoExAlertEntry struct {
	Type  uint32
	Value []byte
}

// HasVerifyNoKeyAlert reports whether the message contains MIT's retry pulse.
func (m NegoExMessage) HasVerifyNoKeyAlert() bool {
	if m.Type != NegoExAlert {
		return false
	}
	for _, alert := range m.Alerts {
		if alert.Type != NegoExAlertPulse || len(alert.Value) < 8 {
			continue
		}
		if binary.LittleEndian.Uint32(alert.Value[4:]) == NegoExAlertVerifyNoKey {
			return true
		}
	}
	return false
}

// NewNegoExVerifyNoKeyAlert creates the retry pulse defined by MS-NEGOEX.
func NewNegoExVerifyNoKeyAlert(scheme NegoExAuthScheme) NegoExMessage {
	var pulse [8]byte
	binary.LittleEndian.PutUint32(pulse[:], 8)
	binary.LittleEndian.PutUint32(pulse[4:], NegoExAlertVerifyNoKey)
	return NegoExMessage{
		Type: NegoExAlert, AuthScheme: scheme,
		Alerts: []NegoExAlertEntry{{Type: NegoExAlertPulse, Value: pulse[:]}},
	}
}

// NegoExSchemeForOID derives the MIT-compatible auth-scheme GUID by copying
// the DER OID value into the beginning of a 16-byte scheme identifier.
func NegoExSchemeForOID(oid []byte) NegoExAuthScheme {
	var scheme NegoExAuthScheme
	copy(scheme[:], oid)
	return scheme
}

// EncodeNegoEx encodes one or more NegoEx messages.
func EncodeNegoEx(messages []NegoExMessage) ([]byte, error) {
	var out []byte
	for _, message := range messages {
		encoded, err := encodeNegoExMessage(message)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	return out, nil
}

// DecodeNegoEx decodes and validates a NegoEx token.
func DecodeNegoEx(data []byte) ([]NegoExMessage, error) {
	var messages []NegoExMessage
	var conversation [16]byte
	offset := 0
	expected := -1
	for len(data) != 0 {
		message, size, err := decodeNegoExMessage(data, expected, conversation)
		if err != nil {
			return nil, err
		}
		if len(messages) == 0 {
			conversation = message.ConversationID
		}
		expected = int(message.Sequence + 1)
		message.Offset = offset
		messages = append(messages, message)
		data = data[size:]
		offset += size
	}
	return messages, nil
}

func encodeNegoExMessage(message NegoExMessage) ([]byte, error) {
	if message.Type > NegoExAlert {
		return nil, fmt.Errorf("NegoEx: invalid message type %d", message.Type)
	}
	headerSize := negoExExchangeHeaderSize
	var payload []byte
	switch message.Type {
	case NegoExInitiatorNego, NegoExAcceptorNego:
		headerSize = negoExNegoHeaderSize
		for _, extension := range message.Extensions {
			if extension.Type&negoExCriticalExtension != 0 {
				return nil, fmt.Errorf("NegoEx: unsupported critical extension %#x", extension.Type)
			}
		}
		schemes := make([]byte, 0, len(message.AuthSchemes)*16)
		for _, scheme := range message.AuthSchemes {
			schemes = append(schemes, scheme[:]...)
		}
		extensions := make([]byte, 0, len(message.Extensions)*12)
		extensionPayload := make([]byte, 0)
		for _, extension := range message.Extensions {
			offset := headerSize + len(schemes) + len(message.Extensions)*12 + len(extensionPayload)
			put32(&extensions, extension.Type)
			put32(&extensions, uint32(offset))
			put32(&extensions, uint32(len(extension.Value)))
			extensionPayload = append(extensionPayload, extension.Value...)
		}
		if len(message.Random) == 0 {
			if _, err := rand.Read(message.Random[:]); err != nil {
				return nil, err
			}
		}
		body := make([]byte, 56)
		copy(body, message.Random[:])
		put32At(body, 40, uint32(headerSize))
		put16At(body, 44, uint16(len(message.AuthSchemes)))
		put32At(body, 46, uint32(headerSize+len(schemes)))
		put16At(body, 50, uint16(len(message.Extensions)))
		body = append(body, schemes...)
		body = append(body, extensions...)
		body = append(body, extensionPayload...)
		payload = body
	case NegoExInitiatorMetaData, NegoExAcceptorMetaData, NegoExChallenge, NegoExAPRequest:
		payload = append(make([]byte, 0, headerSize+len(message.Token)), message.AuthScheme[:]...)
		put32(&payload, uint32(headerSize))
		put32(&payload, uint32(len(message.Token)))
		payload = append(payload, make([]byte, headerSize-negoExBaseHeaderSize-len(payload))...)
		payload = append(payload, message.Token...)
	case NegoExVerify:
		headerSize = negoExVerifyHeaderSize
		payload = append(make([]byte, 0, headerSize+len(message.Checksum)), message.AuthScheme[:]...)
		put32(&payload, 20)
		put32(&payload, NegoExChecksumSchemeRFC3961)
		put32(&payload, message.ChecksumType)
		put32(&payload, uint32(headerSize))
		put32(&payload, uint32(len(message.Checksum)))
		payload = append(payload, make([]byte, headerSize-negoExBaseHeaderSize-len(payload))...)
		payload = append(payload, message.Checksum...)
	case NegoExAlert:
		headerSize = negoExAlertHeaderSize
		if len(message.Alerts) == 0 {
			return nil, fmt.Errorf("NegoEx: alert message has no alerts")
		}
		payload = append(make([]byte, 0, headerSize), message.AuthScheme[:]...)
		put32(&payload, message.AlertCode)
		put32(&payload, uint32(headerSize))
		put16(&payload, uint16(len(message.Alerts)))
		payload = append(payload, make([]byte, headerSize-negoExBaseHeaderSize-len(payload))...)
		alerts := make([]byte, 0, len(message.Alerts)*12)
		alertValues := make([]byte, 0)
		for _, alert := range message.Alerts {
			offset := headerSize + len(message.Alerts)*12 + len(alertValues)
			put32(&alerts, alert.Type)
			put32(&alerts, uint32(offset))
			put32(&alerts, uint32(len(alert.Value)))
			alertValues = append(alertValues, alert.Value...)
		}
		payload = append(payload, alerts...)
		payload = append(payload, alertValues...)
	}
	if len(payload)+negoExBaseHeaderSize < headerSize {
		return nil, fmt.Errorf("NegoEx: short message header")
	}
	header := make([]byte, 0, len(payload)+negoExBaseHeaderSize)
	put64(&header, negoExSignature)
	put32(&header, message.Type)
	put32(&header, message.Sequence)
	put32(&header, uint32(headerSize))
	put32(&header, uint32(len(payload)+negoExBaseHeaderSize))
	header = append(header, message.ConversationID[:]...)
	return append(header, payload...), nil
}

func decodeNegoExMessage(data []byte, sequence int, conversation [16]byte) (NegoExMessage, int, error) {
	if len(data) < negoExBaseHeaderSize {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: truncated message header")
	}
	signature := binary.LittleEndian.Uint64(data)
	if signature != negoExSignature {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid message signature")
	}
	message := NegoExMessage{
		Type:           binary.LittleEndian.Uint32(data[8:]),
		Sequence:       binary.LittleEndian.Uint32(data[12:]),
		ConversationID: asGUID(data[24:40]),
		Offset:         0,
	}
	headerSize := int(binary.LittleEndian.Uint32(data[16:]))
	messageSize := int(binary.LittleEndian.Uint32(data[20:]))
	if sequence >= 0 && message.Sequence != uint32(sequence) {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: message out of sequence")
	}
	if sequence > 0 && message.ConversationID != conversation {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid conversation ID")
	}
	if headerSize < negoExBaseHeaderSize || headerSize > messageSize ||
		messageSize < negoExBaseHeaderSize || messageSize > len(data) {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid message size")
	}
	if headerSize > len(data) {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: truncated message header")
	}
	if message.Type > NegoExAlert {
		return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid message type")
	}
	message.Raw = append([]byte(nil), data[:messageSize]...)
	body := data[negoExBaseHeaderSize:headerSize]
	switch message.Type {
	case NegoExInitiatorNego, NegoExAcceptorNego:
		if headerSize != negoExNegoHeaderSize || len(body) < 56 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid negotiation header")
		}
		copy(message.Random[:], body[:32])
		if binary.LittleEndian.Uint64(body[32:]) != 0 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: unsupported protocol version")
		}
		schemeOffset := int(binary.LittleEndian.Uint32(body[40:]))
		schemeCount := int(binary.LittleEndian.Uint16(body[44:]))
		extensionOffset := int(binary.LittleEndian.Uint32(body[46:]))
		extensionCount := int(binary.LittleEndian.Uint16(body[50:]))
		message.AuthSchemes, _ = readSchemes(data[:messageSize], schemeOffset, schemeCount)
		if message.AuthSchemes == nil && schemeCount != 0 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid auth schemes vector")
		}
		if extensionOffset < 0 || extensionOffset > messageSize ||
			extensionCount > (messageSize-extensionOffset)/12 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid extension vector")
		}
		for i := 0; i < extensionCount; i++ {
			offset := extensionOffset + i*12
			if offset < 0 || offset+12 > messageSize {
				return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid extension vector")
			}
			typ := binary.LittleEndian.Uint32(data[offset:])
			valueOffset := int(binary.LittleEndian.Uint32(data[offset+4:]))
			valueLen := int(binary.LittleEndian.Uint32(data[offset+8:]))
			if typ&negoExCriticalExtension != 0 {
				return NegoExMessage{}, 0, fmt.Errorf("NegoEx: unsupported critical extension")
			}
			if valueOffset < 0 || valueLen < 0 || valueOffset+valueLen > messageSize {
				return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid extension value")
			}
			message.Extensions = append(message.Extensions, NegoExExtension{
				Type: typ, Value: append([]byte(nil), data[valueOffset:valueOffset+valueLen]...),
			})
		}
	case NegoExInitiatorMetaData, NegoExAcceptorMetaData, NegoExChallenge, NegoExAPRequest:
		if headerSize != negoExExchangeHeaderSize {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid exchange header")
		}
		copy(message.AuthScheme[:], body[:16])
		offset := int(binary.LittleEndian.Uint32(body[16:]))
		length := int(binary.LittleEndian.Uint32(body[20:]))
		message.Token, _ = vector(data[:messageSize], offset, length)
		if message.Token == nil && length != 0 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid exchange vector")
		}
	case NegoExVerify:
		if headerSize != negoExVerifyHeaderSize {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid verify header")
		}
		copy(message.AuthScheme[:], body[:16])
		if binary.LittleEndian.Uint32(body[16:]) != 20 ||
			binary.LittleEndian.Uint32(body[20:]) != NegoExChecksumSchemeRFC3961 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: unsupported checksum scheme")
		}
		message.ChecksumScheme = NegoExChecksumSchemeRFC3961
		message.ChecksumType = binary.LittleEndian.Uint32(body[24:])
		offset := int(binary.LittleEndian.Uint32(body[28:]))
		length := int(binary.LittleEndian.Uint32(body[32:]))
		message.Checksum, _ = vector(data[:messageSize], offset, length)
		if message.Checksum == nil && length != 0 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid checksum vector")
		}
	case NegoExAlert:
		if headerSize != negoExAlertHeaderSize {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid alert header")
		}
		copy(message.AuthScheme[:], body[:16])
		message.AlertCode = binary.LittleEndian.Uint32(body[16:])
		offset := int(binary.LittleEndian.Uint32(body[20:]))
		count := int(binary.LittleEndian.Uint16(body[24:]))
		if offset < 0 || offset > messageSize || count > (messageSize-offset)/12 {
			return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid alert vector")
		}
		for i := 0; i < count; i++ {
			entry := offset + i*12
			if entry < 0 || entry+12 > messageSize {
				return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid alert vector")
			}
			valueOffset := int(binary.LittleEndian.Uint32(data[entry+4:]))
			valueLen := int(binary.LittleEndian.Uint32(data[entry+8:]))
			value, ok := vector(data[:messageSize], valueOffset, valueLen)
			if !ok {
				return NegoExMessage{}, 0, fmt.Errorf("NegoEx: invalid alert value")
			}
			message.Alerts = append(message.Alerts, NegoExAlertEntry{
				Type: binary.LittleEndian.Uint32(data[entry:]), Value: value,
			})
		}
	}
	return message, messageSize, nil
}

func readSchemes(data []byte, offset, count int) ([]NegoExAuthScheme, bool) {
	if offset < 0 || count < 0 || offset+count*16 > len(data) {
		return nil, false
	}
	schemes := make([]NegoExAuthScheme, count)
	for i := range schemes {
		copy(schemes[i][:], data[offset+i*16:])
	}
	return schemes, true
}

func vector(data []byte, offset, length int) ([]byte, bool) {
	if offset < 0 || length < 0 || offset > len(data) || length > len(data)-offset {
		return nil, false
	}
	return append([]byte(nil), data[offset:offset+length]...), true
}

func asGUID(data []byte) (guid [16]byte) {
	copy(guid[:], data)
	return guid
}

func put16(dst *[]byte, value uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], value)
	*dst = append(*dst, b[:]...)
}

func put32(dst *[]byte, value uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], value)
	*dst = append(*dst, b[:]...)
}

func put64(dst *[]byte, value uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], value)
	*dst = append(*dst, b[:]...)
}

func put16At(dst []byte, offset int, value uint16) {
	binary.LittleEndian.PutUint16(dst[offset:], value)
}

func put32At(dst []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(dst[offset:], value)
}

type negoExState struct {
	initiator    bool
	conversation [16]byte
	sequence     uint32
	transcript   []byte
	scheme       NegoExAuthScheme
}

func newNegoExState(initiator bool, scheme NegoExAuthScheme) (*negoExState, error) {
	state := &negoExState{initiator: initiator, scheme: scheme}
	if _, err := rand.Read(state.conversation[:]); err != nil {
		return nil, err
	}
	return state, nil
}

func (s *negoExState) append(messages ...NegoExMessage) ([]byte, error) {
	for i := range messages {
		messages[i].Sequence = s.sequence
		messages[i].ConversationID = s.conversation
		s.sequence++
	}
	encoded, err := EncodeNegoEx(messages)
	if err != nil {
		return nil, err
	}
	s.transcript = append(s.transcript, encoded...)
	return encoded, nil
}

func (s *negoExState) receive(token []byte) ([]NegoExMessage, error) {
	messages, err := DecodeNegoEx(token)
	if err != nil {
		return nil, err
	}
	if err := s.validate(messages); err != nil {
		return nil, err
	}
	if s.sequence == 0 && len(messages) != 0 {
		s.conversation = messages[0].ConversationID
	}
	s.transcript = append(s.transcript, token...)
	s.sequence += uint32(len(messages))
	return messages, nil
}

func (s *negoExState) validate(messages []NegoExMessage) error {
	expected := s.sequence
	conversation := s.conversation
	for _, message := range messages {
		if message.Sequence != expected ||
			(expected != 0 && message.ConversationID != conversation) {
			return fmt.Errorf("NegoEx: unexpected sequence or conversation ID")
		}
		if expected == 0 {
			conversation = message.ConversationID
		}
		expected++
	}
	return nil
}

func (s *negoExState) checksum(ctx *gssapi.Context, prefix []byte) ([]byte, uint32, error) {
	lucid, err := ctx.Lucid(1)
	if err != nil {
		return nil, 0, err
	}
	etype, err := crypto.NewRegistry().Get(lucid.Key.Type)
	if err != nil {
		return nil, 0, err
	}
	usage := uint32(NegoExInitiatorChecksumUsage)
	if !s.initiator {
		usage = NegoExAcceptorChecksumUsage
	}
	checksum, err := etype.Checksum(lucid.Key.Value, usage, append(append([]byte(nil), s.transcript...), prefix...))
	if err != nil {
		return nil, 0, err
	}
	return checksum, checksumType(lucid.Key.Type), nil
}

func checksumType(enctype int32) uint32 {
	switch enctype {
	case crypto.EnctypeAES128SHA1:
		return uint32(crypto.ChecksumHMACSHA196AES128)
	case crypto.EnctypeAES256SHA1:
		return uint32(crypto.ChecksumHMACSHA196AES256)
	case crypto.EnctypeAES128SHA256:
		return uint32(crypto.ChecksumHMACSHA256128AES128)
	case crypto.EnctypeAES256SHA384:
		return uint32(crypto.ChecksumHMACSHA384192AES256)
	case crypto.EnctypeCamellia128:
		return uint32(crypto.ChecksumCMACCamellia128)
	case crypto.EnctypeCamellia256:
		return uint32(crypto.ChecksumCMACCamellia256)
	default:
		return 0
	}
}

func (s *negoExState) verify(ctx *gssapi.Context, message NegoExMessage, prefix []byte) error {
	lucid, err := ctx.Lucid(1)
	if err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(lucid.Key.Type)
	if err != nil {
		return err
	}
	usage := uint32(NegoExAcceptorChecksumUsage)
	if !s.initiator {
		usage = NegoExInitiatorChecksumUsage
	}
	data := append(append([]byte(nil), s.transcript...), prefix...)
	return etype.VerifyChecksum(lucid.Key.Value, usage, data, message.Checksum)
}

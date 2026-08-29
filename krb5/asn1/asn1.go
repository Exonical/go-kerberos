package asn1

import (
	"fmt"
	"reflect"
	"time"

	"github.com/Exonical/go-kerberos/krb5/types"
)

const maxDepth = 32

const (
	tagBoolean         = 0x01
	tagInteger         = 0x02
	tagBitString       = 0x03
	tagOctetString     = 0x04
	tagUTF8String      = 0x0c
	tagSequence        = 0x30
	tagGeneralizedTime = 0x18
	tagGeneralString   = 0x1b
)

type applicationTagger interface {
	ApplicationTag() int
}

type fieldTag struct {
	number   int
	optional bool
	choice   bool
}

// Marshal encodes a Kerberos ASN.1 value using canonical DER.
func Marshal(value any) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("marshal kerberos ASN.1: nil value")
	}
	encoded, err := encodeValue(reflect.ValueOf(value), 0)
	if err != nil {
		return nil, fmt.Errorf("marshal kerberos ASN.1: %w", err)
	}
	return encoded, nil
}

// WrapContext wraps an already encoded value in an explicit context tag.
func WrapContext(tag int, encoded []byte) ([]byte, error) {
	if tag < 0 || tag > 30 {
		return nil, fmt.Errorf("context tag out of range")
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("empty context value")
	}
	return encodeTLV(0xa0|byte(tag), encoded), nil
}

// UnwrapContext removes an explicit context tag and returns its encoded value.
func UnwrapContext(data []byte, tag int) ([]byte, error) {
	if tag < 0 || tag > 30 {
		return nil, fmt.Errorf("context tag out of range")
	}
	actual, content, end, err := readTLV(data)
	if err != nil {
		return nil, err
	}
	if end != len(data) || actual != 0xa0|byte(tag) {
		return nil, fmt.Errorf("unexpected context tag")
	}
	return append([]byte(nil), content...), nil
}

// Unmarshal decodes a Kerberos ASN.1 value from canonical DER.
func Unmarshal(data []byte, value any) error {
	if value == nil {
		return fmt.Errorf("unmarshal kerberos ASN.1: nil destination")
	}
	destination := reflect.ValueOf(value)
	if destination.Kind() != reflect.Pointer || destination.IsNil() {
		return fmt.Errorf("unmarshal kerberos ASN.1: destination must be a non-nil pointer")
	}
	if _, _, end, err := readTLV(data); err != nil {
		return fmt.Errorf("unmarshal kerberos ASN.1: %w", err)
	} else if end != len(data) {
		return fmt.Errorf("unmarshal kerberos ASN.1: trailing data")
	}
	if err := decodeValue(data, destination.Elem(), 0); err != nil {
		return fmt.Errorf("unmarshal kerberos ASN.1: %w", err)
	}
	return nil
}

// Field returns the raw DER encoding of a nested context or application
// element. Path values are tag numbers, not encoded tag bytes. A path may
// begin with an application element; when the current value is a constructed
// element, the next path value is searched among its direct children.
func Field(data []byte, path ...int) ([]byte, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("read kerberos ASN.1 field: empty path")
	}
	for _, tag := range path {
		if tag < 0 || tag > 30 {
			return nil, fmt.Errorf("read kerberos ASN.1 field: tag %d out of range", tag)
		}
	}
	current := data
	for position, tagNumber := range path {
		tag, content, end, err := readTLV(current)
		if err != nil {
			return nil, fmt.Errorf("read kerberos ASN.1 field: %w", err)
		}
		if end != len(current) {
			return nil, fmt.Errorf("read kerberos ASN.1 field: trailing data")
		}
		if position == 0 && matchesTag(tag, tagNumber) {
			if len(path) == 1 {
				return append([]byte(nil), current...), nil
			}
			current = content
			continue
		}
		found, err := findChild(content, tagNumber)
		if err != nil {
			return nil, fmt.Errorf("read kerberos ASN.1 field: %w", err)
		}
		if found == nil {
			return nil, fmt.Errorf("read kerberos ASN.1 field: tag %d not found", tagNumber)
		}
		if position == len(path)-1 {
			return append([]byte(nil), found...), nil
		}
		current = found
	}
	return append([]byte(nil), current...), nil
}

// FieldContent returns the contents of the raw DER element selected by Field.
func FieldContent(data []byte, path ...int) ([]byte, error) {
	element, err := Field(data, path...)
	if err != nil {
		return nil, err
	}
	_, content, end, err := readTLV(element)
	if err != nil {
		return nil, fmt.Errorf("read kerberos ASN.1 field contents: %w", err)
	}
	if end != len(element) {
		return nil, fmt.Errorf("read kerberos ASN.1 field contents: trailing data")
	}
	return append([]byte(nil), content...), nil
}

func matchesTag(tag byte, tagNumber int) bool {
	return tag == byte(0x60|tagNumber) || tag == byte(0xa0|tagNumber)
}

func findChild(data []byte, tagNumber int) ([]byte, error) {
	for len(data) > 0 {
		tag, _, end, err := readTLV(data)
		if err != nil {
			return nil, err
		}
		if matchesTag(tag, tagNumber) {
			return data[:end], nil
		}
		data = data[end:]
	}
	return nil, nil
}

func encodeValue(value reflect.Value, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("maximum nesting depth exceeded")
	}
	if !value.IsValid() {
		return nil, fmt.Errorf("invalid value")
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, fmt.Errorf("nil pointer")
		}
		return encodeValue(value.Elem(), depth+1)
	}
	if tag, ok := applicationTag(value); ok {
		inner, err := encodeBare(value, depth+1)
		if err != nil {
			return nil, err
		}
		return encodeTLV(0x60|byte(tag), inner), nil
	}
	if tag, field, ok := choiceField(value); ok {
		encoded, err := encodeValue(value.Field(field), depth+1)
		if err != nil {
			return nil, err
		}
		return encodeTLV(0xa0|byte(tag), encoded), nil
	}
	return encodeBare(value, depth)
}

func encodeBare(value reflect.Value, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("maximum nesting depth exceeded")
	}
	if isKerberosTime(value.Type()) {
		encoded, err := kerberosTimeString(value)
		if err != nil {
			return nil, err
		}
		return encodeTLV(tagGeneralizedTime, []byte(encoded)), nil
	}
	if isFlagType(value.Type()) {
		flags := uint32(value.Uint())
		encoded, err := types.EncodeFlags(flags)
		if err != nil {
			return nil, err
		}
		return encoded, nil
	}
	if value.Type() == reflect.TypeOf(types.UTF8String("")) {
		return encodeTLV(tagUTF8String, []byte(value.String())), nil
	}
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			return encodeTLV(tagBoolean, []byte{0xff}), nil
		}
		return encodeTLV(tagBoolean, []byte{0}), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return encodeTLV(tagInteger, encodeInteger(value.Int())), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return encodeTLV(tagInteger, encodeUnsignedInteger(value.Uint())), nil
	case reflect.String:
		return encodeTLV(tagGeneralString, []byte(value.String())), nil
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return encodeTLV(tagOctetString, value.Bytes()), nil
		}
		var content []byte
		for i := 0; i < value.Len(); i++ {
			item, err := encodeValue(value.Index(i), depth+1)
			if err != nil {
				return nil, err
			}
			content = append(content, item...)
		}
		return encodeTLV(tagSequence, content), nil
	case reflect.Struct:
		return encodeStruct(value, depth)
	default:
		return nil, fmt.Errorf("unsupported kind %s", value.Kind())
	}
}

func encodeStruct(value reflect.Value, depth int) ([]byte, error) {
	var content []byte
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag, hasTag, err := parseFieldTag(field)
		if err != nil {
			return nil, err
		}
		fieldValue := value.Field(i)
		if tag.optional && isAbsent(fieldValue) {
			continue
		}
		encoded, err := encodeValue(fieldValue, depth+1)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", field.Name, err)
		}
		if hasTag {
			encoded = encodeTLV(0xa0|byte(tag.number), encoded)
		}
		content = append(content, encoded...)
	}
	return encodeTLV(tagSequence, content), nil
}

func decodeValue(data []byte, destination reflect.Value, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("maximum nesting depth exceeded")
	}
	tag, content, end, err := readTLV(data)
	if err != nil {
		return err
	}
	if end != len(data) {
		return fmt.Errorf("trailing data in value")
	}
	if destination.Kind() == reflect.Pointer {
		if destination.IsNil() {
			destination.Set(reflect.New(destination.Type().Elem()))
		}
		return decodeValue(data, destination.Elem(), depth+1)
	}
	if application, ok := applicationTag(destination); ok {
		if tag != 0x60|byte(application) {
			return fmt.Errorf("unexpected application tag 0x%x, want 0x%x", tag, 0x60|byte(application))
		}
		innerTag, innerContent, innerEnd, err := readTLV(content)
		if err != nil {
			return err
		}
		if innerTag != tagSequence || innerEnd != len(content) {
			return fmt.Errorf("application value is not a complete SEQUENCE")
		}
		return decodeBare(innerTag, innerContent, destination, depth+1)
	}
	if tagNumber, field, ok := choiceFieldForTag(destination, tag); ok {
		if tag != 0xa0|byte(tagNumber) {
			return fmt.Errorf("unexpected choice tag 0x%x", tag)
		}
		return decodeValue(content, destination.Field(field), depth+1)
	}
	return decodeBare(tag, content, destination, depth)
}

func decodeBare(tag byte, content []byte, destination reflect.Value, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("maximum nesting depth exceeded")
	}
	if isKerberosTime(destination.Type()) {
		if tag != tagGeneralizedTime {
			return fmt.Errorf("unexpected GeneralizedTime tag 0x%x", tag)
		}
		if len(content) == 0 {
			return fmt.Errorf("empty GeneralizedTime")
		}
		parsed, err := types.ParseKerberosTime(string(content))
		if err != nil {
			return err
		}
		if destination.Type() == reflect.TypeOf(time.Time{}) {
			destination.Set(reflect.ValueOf(parsed.Time))
		} else {
			destination.Set(reflect.ValueOf(parsed))
		}
		return nil
	}
	if isFlagType(destination.Type()) {
		if tag != tagBitString {
			return fmt.Errorf("unexpected BIT STRING tag 0x%x", tag)
		}
		der := append([]byte{tag, byte(len(content))}, content...)
		flags, err := types.DecodeFlags(der)
		if err != nil {
			return err
		}
		destination.SetUint(uint64(flags))
		return nil
	}
	if destination.Type() == reflect.TypeOf(types.UTF8String("")) {
		if tag != tagUTF8String {
			return fmt.Errorf("unexpected UTF8String tag 0x%x", tag)
		}
		destination.SetString(string(content))
		return nil
	}
	switch destination.Kind() {
	case reflect.Bool:
		if tag != tagBoolean || len(content) != 1 || (content[0] != 0 && content[0] != 0xff) {
			return fmt.Errorf("invalid BOOLEAN")
		}
		destination.SetBool(content[0] != 0)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if tag != tagInteger {
			return fmt.Errorf("unexpected INTEGER tag 0x%x", tag)
		}
		value, err := decodeInteger(content)
		if err != nil {
			return err
		}
		if destination.OverflowInt(value) {
			return fmt.Errorf("INTEGER overflows %s", destination.Type())
		}
		destination.SetInt(value)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if tag != tagInteger {
			return fmt.Errorf("unexpected INTEGER tag 0x%x", tag)
		}
		value, err := decodeUnsignedInteger(content)
		if err != nil {
			return err
		}
		if destination.OverflowUint(value) {
			return fmt.Errorf("INTEGER overflows %s", destination.Type())
		}
		destination.SetUint(value)
		return nil
	case reflect.String:
		if tag != tagGeneralString {
			return fmt.Errorf("unexpected GeneralString tag 0x%x", tag)
		}
		destination.SetString(string(content))
		return nil
	case reflect.Slice:
		if destination.Type().Elem().Kind() == reflect.Uint8 {
			if tag != tagOctetString {
				return fmt.Errorf("unexpected OCTET STRING tag 0x%x", tag)
			}
			destination.SetBytes(append([]byte(nil), content...))
			return nil
		}
		if tag != tagSequence {
			return fmt.Errorf("unexpected SEQUENCE tag 0x%x", tag)
		}
		destination.Set(reflect.MakeSlice(destination.Type(), 0, 0))
		for len(content) != 0 {
			_, _, end, err := readTLV(content)
			if err != nil {
				return err
			}
			item := reflect.New(destination.Type().Elem()).Elem()
			if err := decodeValue(content[:end], item, depth+1); err != nil {
				return err
			}
			destination.Set(reflect.Append(destination, item))
			content = content[end:]
		}
		return nil
	case reflect.Struct:
		if tag != tagSequence {
			return fmt.Errorf("unexpected SEQUENCE tag 0x%x", tag)
		}
		return decodeStruct(content, destination, depth+1)
	default:
		return fmt.Errorf("unsupported destination kind %s", destination.Kind())
	}
}

func decodeStruct(content []byte, destination reflect.Value, depth int) error {
	position := 0
	for i := 0; i < destination.NumField(); i++ {
		field := destination.Type().Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag, hasTag, err := parseFieldTag(field)
		if err != nil {
			return err
		}
		if !hasTag {
			return fmt.Errorf("field %s has no krb5 tag", field.Name)
		}
		if position == len(content) {
			if tag.optional {
				continue
			}
			return fmt.Errorf("missing mandatory field %s", field.Name)
		}
		nextTag, _, end, err := readTLV(content[position:])
		if err != nil {
			return err
		}
		expectedTag := byte(0xa0 | tag.number)
		if nextTag != expectedTag {
			if tag.optional && nextTag > expectedTag {
				continue
			}
			return fmt.Errorf("unexpected or out-of-order field tag 0x%x, want 0x%x", nextTag, expectedTag)
		}
		_, inner, innerEnd, err := readTLV(content[position : position+end])
		if err != nil {
			return err
		}
		if innerEnd != end {
			return fmt.Errorf("invalid explicit field")
		}
		if err := decodeValue(inner, destination.Field(i), depth+1); err != nil {
			return fmt.Errorf("field %s: %w", field.Name, err)
		}
		position += end
	}
	if position != len(content) {
		return fmt.Errorf("unknown trailing field")
	}
	return nil
}

func readTLV(data []byte) (tag byte, content []byte, end int, err error) {
	if len(data) < 2 {
		return 0, nil, 0, fmt.Errorf("truncated TLV")
	}
	tag = data[0]
	length, header, err := readLength(data[1:])
	if err != nil {
		return 0, nil, 0, err
	}
	if length > len(data)-header-1 {
		return 0, nil, 0, fmt.Errorf("length %d exceeds remaining input", length)
	}
	start := 1 + header
	end = start + length
	return tag, data[start:end], end, nil
}

func readLength(data []byte) (length, header int, err error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("truncated length")
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), 1, nil
	}
	count := int(data[0] & 0x7f)
	if count == 0 {
		return 0, 0, fmt.Errorf("indefinite length is forbidden")
	}
	if count > 4 || len(data) < count+1 || data[1] == 0 {
		return 0, 0, fmt.Errorf("invalid DER length")
	}
	length = 0
	for i := 0; i < count; i++ {
		length = length<<8 | int(data[i+1])
	}
	if length < 128 {
		return 0, 0, fmt.Errorf("non-minimal DER length")
	}
	return length, count + 1, nil
}

func encodeTLV(tag byte, content []byte) []byte {
	length := encodeLength(len(content))
	out := make([]byte, 1+len(length)+len(content))
	out[0] = tag
	copy(out[1:], length)
	copy(out[1+len(length):], content)
	return out
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var buffer [4]byte
	position := len(buffer)
	for length != 0 {
		position--
		buffer[position] = byte(length)
		length >>= 8
	}
	out := []byte{0x80 | byte(len(buffer)-position)}
	return append(out, buffer[position:]...)
}

func encodeInteger(value int64) []byte {
	var buffer [8]byte
	for i := 7; i >= 0; i-- {
		buffer[i] = byte(value)
		value >>= 8
	}
	start := 0
	for start < len(buffer)-1 {
		if buffer[start] == 0 && buffer[start+1]&0x80 == 0 {
			start++
			continue
		}
		if buffer[start] == 0xff && buffer[start+1]&0x80 != 0 {
			start++
			continue
		}
		break
	}
	return append([]byte(nil), buffer[start:]...)
}

func encodeUnsignedInteger(value uint64) []byte {
	var buffer [8]byte
	for i := 7; i >= 0; i-- {
		buffer[i] = byte(value)
		value >>= 8
	}
	start := 0
	for start < len(buffer)-1 && buffer[start] == 0 {
		start++
	}
	if buffer[start]&0x80 != 0 {
		start--
		buffer[start] = 0
	}
	return append([]byte(nil), buffer[start:]...)
}

func decodeInteger(data []byte) (int64, error) {
	if len(data) == 0 || len(data) > 8 {
		return 0, fmt.Errorf("invalid INTEGER length")
	}
	if len(data) > 1 && ((data[0] == 0 && data[1]&0x80 == 0) ||
		(data[0] == 0xff && data[1]&0x80 != 0)) {
		return 0, fmt.Errorf("non-minimal INTEGER")
	}
	var value int64
	for _, b := range data {
		value = value<<8 | int64(b)
	}
	if data[0]&0x80 != 0 && len(data) < 8 {
		value |= -1 << (len(data) * 8)
	}
	return value, nil
}

func decodeUnsignedInteger(data []byte) (uint64, error) {
	if len(data) == 0 || len(data) > 9 {
		return 0, fmt.Errorf("invalid unsigned INTEGER length")
	}
	if len(data) > 1 && data[0] == 0 && data[1]&0x80 == 0 {
		return 0, fmt.Errorf("non-minimal INTEGER")
	}
	if data[0]&0x80 != 0 {
		return 0, fmt.Errorf("negative unsigned INTEGER")
	}
	if len(data) > 5 || (len(data) == 5 && data[0] != 0) {
		return 0, fmt.Errorf("unsigned INTEGER overflow")
	}
	var value uint64
	for _, b := range data {
		value = value<<8 | uint64(b)
	}
	return value, nil
}

func parseFieldTag(field reflect.StructField) (fieldTag, bool, error) {
	raw, present := field.Tag.Lookup("krb5")
	if !present {
		return fieldTag{}, false, nil
	}
	var result fieldTag
	for position := 0; position < len(raw); {
		end := position
		for end < len(raw) && raw[end] != ',' {
			end++
		}
		part := raw[position:end]
		switch {
		case len(part) > len("tag:") && part[:4] == "tag:":
			number := 0
			for _, character := range part[4:] {
				if character < '0' || character > '9' {
					return fieldTag{}, false, fmt.Errorf("invalid field tag %q", raw)
				}
				number = number*10 + int(character-'0')
			}
			if number > 30 {
				return fieldTag{}, false, fmt.Errorf("field tag out of range")
			}
			result.number = number
		case part == "optional":
			result.optional = true
		case part == "choice":
			result.choice = true
		default:
			return fieldTag{}, false, fmt.Errorf("unknown krb5 field option %q", part)
		}
		position = end + 1
	}
	return result, true, nil
}

func choiceField(value reflect.Value) (int, int, bool) {
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, 0, false
	}
	found, tagNumber := -1, 0
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag, hasTag, err := parseFieldTag(field)
		if err != nil || !hasTag || !tag.choice {
			continue
		}
		// A CHOICE has exactly one selected alternative.  Pointer
		// alternatives make that selection explicit and also allow the
		// decoder to allocate the selected value.
		fieldValue := value.Field(i)
		if fieldValue.Kind() == reflect.Pointer && fieldValue.IsNil() {
			continue
		}
		if found >= 0 {
			return 0, 0, false
		}
		found, tagNumber = i, tag.number
	}
	if found < 0 {
		return 0, 0, false
	}
	return tagNumber, found, true
}

func choiceFieldForTag(value reflect.Value, tag byte) (int, int, bool) {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, 0, false
	}
	found, tagNumber := -1, 0
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		if field.PkgPath != "" {
			continue
		}
		parsed, hasTag, err := parseFieldTag(field)
		if err != nil || !hasTag || !parsed.choice || tag != 0xa0|byte(parsed.number) {
			continue
		}
		if found >= 0 {
			return 0, 0, false
		}
		found, tagNumber = i, parsed.number
	}
	if found < 0 {
		return 0, 0, false
	}
	return tagNumber, found, true
}

func isAbsent(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
		return value.IsNil()
	default:
		return false
	}
}

func applicationTag(value reflect.Value) (int, bool) {
	if value.CanInterface() {
		if tagger, ok := value.Interface().(applicationTagger); ok {
			return tagger.ApplicationTag(), true
		}
	}
	if value.Kind() != reflect.Pointer && value.CanAddr() && value.Addr().CanInterface() {
		if tagger, ok := value.Addr().Interface().(applicationTagger); ok {
			return tagger.ApplicationTag(), true
		}
	}
	return 0, false
}

func isFlagType(typ reflect.Type) bool {
	return typ == reflect.TypeOf(types.KDCOptions(0)) ||
		typ == reflect.TypeOf(types.TicketFlags(0)) ||
		typ == reflect.TypeOf(types.APOptions(0))
}

func isKerberosTime(typ reflect.Type) bool {
	return typ == reflect.TypeOf(types.KerberosTime{}) || typ == reflect.TypeOf(time.Time{})
}

func kerberosTimeString(value reflect.Value) (string, error) {
	if value.Type() == reflect.TypeOf(time.Time{}) {
		return value.Interface().(time.Time).UTC().Truncate(time.Second).Format("20060102150405Z"), nil
	}
	timeValue := value.Interface().(types.KerberosTime)
	return timeValue.EncodeGeneralizedTime()
}

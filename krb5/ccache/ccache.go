package ccache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

const Version uint16 = 0x0504

type Header struct {
	TimeOffset int32
	Usec       int32
}

type Credential struct {
	Client       principal.Principal
	Server       principal.Principal
	Enctype      int32
	Key          []byte
	TicketFlags  uint32
	AuthTime     uint32
	StartTime    uint32
	EndTime      uint32
	RenewTill    uint32
	IsSKey       bool
	Addresses    []Address
	AuthData     []AuthData
	Ticket       []byte
	SecondTicket []byte
}

type Address struct {
	Type uint16
	Data []byte
}

type AuthData struct {
	Type uint16
	Data []byte
}

type Cache struct {
	Header           Header
	DefaultPrincipal principal.Principal
	Credentials      []Credential
}

func Read(r io.Reader) (*Cache, error) {
	if r == nil {
		return nil, fmt.Errorf("read ccache: nil reader")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read ccache: %w", err)
	}
	d := ccacheDecoder{data: data}
	version, err := d.u16()
	if err != nil {
		return nil, fmt.Errorf("read ccache version: %w", err)
	}
	if version != Version {
		return nil, fmt.Errorf("read ccache: unsupported version")
	}
	headerLength, err := d.u16()
	if err != nil {
		return nil, fmt.Errorf("read ccache header length: %w", err)
	}
	header, err := d.bytes(int(headerLength))
	if err != nil {
		return nil, fmt.Errorf("read ccache header: %w", err)
	}
	result := &Cache{}
	if err := parseHeader(header, &result.Header); err != nil {
		return nil, fmt.Errorf("read ccache header: %w", err)
	}
	result.DefaultPrincipal, err = d.principal()
	if err != nil {
		return nil, fmt.Errorf("read ccache default principal: %w", err)
	}
	for d.remaining() > 0 {
		credential, err := d.credential()
		if err != nil {
			return nil, fmt.Errorf("read ccache credential: %w", err)
		}
		result.Credentials = append(result.Credentials, credential)
	}
	return result, nil
}

func Write(w io.Writer, cache *Cache) error {
	if w == nil {
		return fmt.Errorf("write ccache: nil writer")
	}
	if cache == nil {
		return fmt.Errorf("write ccache: nil cache")
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.BigEndian, Version); err != nil {
		return fmt.Errorf("write ccache version: %w", err)
	}
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 1)
	binary.BigEndian.PutUint16(header[2:4], 8)
	binary.BigEndian.PutUint32(header[4:8], uint32(cache.Header.TimeOffset))
	binary.BigEndian.PutUint32(header[8:12], uint32(cache.Header.Usec))
	if err := binary.Write(&data, binary.BigEndian, uint16(len(header))); err != nil {
		return fmt.Errorf("write ccache header length: %w", err)
	}
	if _, err := data.Write(header); err != nil {
		return fmt.Errorf("write ccache header: %w", err)
	}
	if err := encodePrincipal(&data, cache.DefaultPrincipal); err != nil {
		return fmt.Errorf("write ccache default principal: %w", err)
	}
	for _, credential := range cache.Credentials {
		if err := encodeCredential(&data, credential); err != nil {
			return fmt.Errorf("write ccache credential: %w", err)
		}
	}
	n, err := w.Write(data.Bytes())
	if err != nil {
		return fmt.Errorf("write ccache: %w", err)
	}
	if n != data.Len() {
		return fmt.Errorf("write ccache: %w", io.ErrShortWrite)
	}
	return nil
}

type ccacheDecoder struct {
	data []byte
	off  int
}

func (d *ccacheDecoder) remaining() int {
	return len(d.data) - d.off
}

func (d *ccacheDecoder) bytes(n int) ([]byte, error) {
	if n < 0 || n > d.remaining() {
		return nil, fmt.Errorf("truncated field")
	}
	value := d.data[d.off : d.off+n]
	d.off += n
	return value, nil
}

func (d *ccacheDecoder) u8() (uint8, error) {
	value, err := d.bytes(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (d *ccacheDecoder) u16() (uint16, error) {
	value, err := d.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

func (d *ccacheDecoder) u32() (uint32, error) {
	value, err := d.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

func (d *ccacheDecoder) counted32() ([]byte, error) {
	length, err := d.u32()
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(d.remaining()) {
		return nil, fmt.Errorf("truncated counted field")
	}
	value, err := d.bytes(int(length))
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (d *ccacheDecoder) principal() (principal.Principal, error) {
	nameType, err := d.u32()
	if err != nil {
		return principal.Principal{}, err
	}
	count, err := d.u32()
	if err != nil {
		return principal.Principal{}, err
	}
	realm, err := d.counted32()
	if err != nil {
		return principal.Principal{}, err
	}
	if uint64(count) > uint64(d.remaining()/4) {
		return principal.Principal{}, fmt.Errorf("invalid principal component count")
	}
	components := make([]string, 0, int(count))
	for i := uint32(0); i < count; i++ {
		component, err := d.counted32()
		if err != nil {
			return principal.Principal{}, err
		}
		components = append(components, string(component))
	}
	return principal.Principal{
		Realm:      string(realm),
		NameType:   principal.NameType(int32(nameType)),
		Components: components,
	}, nil
}

func (d *ccacheDecoder) credential() (Credential, error) {
	client, err := d.principal()
	if err != nil {
		return Credential{}, err
	}
	server, err := d.principal()
	if err != nil {
		return Credential{}, err
	}
	enctype, err := d.u16()
	if err != nil {
		return Credential{}, err
	}
	key, err := d.counted32()
	if err != nil {
		return Credential{}, err
	}
	times := make([]uint32, 4)
	for i := range times {
		times[i], err = d.u32()
		if err != nil {
			return Credential{}, err
		}
	}
	isSKey, err := d.u8()
	if err != nil {
		return Credential{}, err
	}
	if isSKey > 1 {
		return Credential{}, fmt.Errorf("invalid is_skey value")
	}
	flags, err := d.u32()
	if err != nil {
		return Credential{}, err
	}
	addresses, err := d.addresses()
	if err != nil {
		return Credential{}, err
	}
	authData, err := d.authData()
	if err != nil {
		return Credential{}, err
	}
	ticket, err := d.counted32()
	if err != nil {
		return Credential{}, err
	}
	secondTicket, err := d.counted32()
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		Client:       client,
		Server:       server,
		Key:          append([]byte(nil), key...),
		Enctype:      int32(enctype),
		TicketFlags:  flags,
		AuthTime:     times[0],
		StartTime:    times[1],
		EndTime:      times[2],
		RenewTill:    times[3],
		IsSKey:       isSKey != 0,
		Addresses:    addresses,
		AuthData:     authData,
		Ticket:       append([]byte(nil), ticket...),
		SecondTicket: append([]byte(nil), secondTicket...),
	}, nil
}

func (d *ccacheDecoder) addresses() ([]Address, error) {
	count, err := d.u32()
	if err != nil {
		return nil, err
	}
	if uint64(count) > uint64(d.remaining()/6) {
		return nil, fmt.Errorf("invalid address count")
	}
	addresses := make([]Address, 0, int(count))
	for i := uint32(0); i < count; i++ {
		addressType, err := d.u16()
		if err != nil {
			return nil, err
		}
		data, err := d.counted32()
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, Address{Type: addressType, Data: append([]byte(nil), data...)})
	}
	return addresses, nil
}

func (d *ccacheDecoder) authData() ([]AuthData, error) {
	count, err := d.u32()
	if err != nil {
		return nil, err
	}
	if uint64(count) > uint64(d.remaining()/6) {
		return nil, fmt.Errorf("invalid authdata count")
	}
	authData := make([]AuthData, 0, int(count))
	for i := uint32(0); i < count; i++ {
		authType, err := d.u16()
		if err != nil {
			return nil, err
		}
		data, err := d.counted32()
		if err != nil {
			return nil, err
		}
		authData = append(authData, AuthData{Type: authType, Data: append([]byte(nil), data...)})
	}
	return authData, nil
}

func parseHeader(data []byte, header *Header) error {
	d := ccacheDecoder{data: data}
	for d.remaining() > 0 {
		tag, err := d.u16()
		if err != nil {
			return err
		}
		length, err := d.u16()
		if err != nil {
			return err
		}
		value, err := d.bytes(int(length))
		if err != nil {
			return err
		}
		if tag == 1 {
			if len(value) != 8 {
				return fmt.Errorf("invalid time offset field length")
			}
			header.TimeOffset = int32(binary.BigEndian.Uint32(value[:4]))
			header.Usec = int32(binary.BigEndian.Uint32(value[4:]))
		}
	}
	return nil
}

func encodePrincipal(w io.Writer, p principal.Principal) error {
	if len(p.Realm) > int(^uint32(0)) {
		return fmt.Errorf("realm is too long")
	}
	if uint64(len(p.Components)) > uint64(^uint32(0)) {
		return fmt.Errorf("too many principal components")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(p.NameType)); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(p.Components))); err != nil {
		return err
	}
	if err := writeCounted32(w, []byte(p.Realm)); err != nil {
		return err
	}
	for _, component := range p.Components {
		if err := writeCounted32(w, []byte(component)); err != nil {
			return err
		}
	}
	return nil
}

func writeCounted32(w io.Writer, value []byte) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return fmt.Errorf("field is too long")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}

func encodeCredential(w io.Writer, credential Credential) error {
	if err := encodePrincipal(w, credential.Client); err != nil {
		return err
	}
	if err := encodePrincipal(w, credential.Server); err != nil {
		return err
	}
	if credential.Enctype < 0 || credential.Enctype > int32(^uint16(0)) {
		return fmt.Errorf("enctype out of range")
	}
	if err := binary.Write(w, binary.BigEndian, uint16(credential.Enctype)); err != nil {
		return err
	}
	if err := writeCounted32(w, credential.Key); err != nil {
		return err
	}
	for _, timestamp := range []uint32{credential.AuthTime, credential.StartTime, credential.EndTime, credential.RenewTill} {
		if err := binary.Write(w, binary.BigEndian, timestamp); err != nil {
			return err
		}
	}
	var isSKey byte
	if credential.IsSKey {
		isSKey = 1
	}
	if err := binary.Write(w, binary.BigEndian, isSKey); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, credential.TicketFlags); err != nil {
		return err
	}
	if err := writeAddresses(w, credential.Addresses); err != nil {
		return err
	}
	if err := writeAuthData(w, credential.AuthData); err != nil {
		return err
	}
	if err := writeCounted32(w, credential.Ticket); err != nil {
		return err
	}
	return writeCounted32(w, credential.SecondTicket)
}

func writeAddresses(w io.Writer, addresses []Address) error {
	if uint64(len(addresses)) > uint64(^uint32(0)) {
		return fmt.Errorf("too many addresses")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(addresses))); err != nil {
		return err
	}
	for _, address := range addresses {
		if err := binary.Write(w, binary.BigEndian, address.Type); err != nil {
			return err
		}
		if err := writeCounted32(w, address.Data); err != nil {
			return err
		}
	}
	return nil
}

func writeAuthData(w io.Writer, values []AuthData) error {
	if uint64(len(values)) > uint64(^uint32(0)) {
		return fmt.Errorf("too many authdata entries")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(values))); err != nil {
		return err
	}
	for _, value := range values {
		if err := binary.Write(w, binary.BigEndian, value.Type); err != nil {
			return err
		}
		if err := writeCounted32(w, value.Data); err != nil {
			return err
		}
	}
	return nil
}

package ccache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Exonical/go-kerberos/krb5/internal/binfmt"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// DefaultKCMSocketPath is the Linux Heimdal/MIT KCM socket path.
var DefaultKCMSocketPath = "/var/run/.heim_org.h5l.kcm-socket"

const (
	kcmMajor    byte = 2
	kcmMinor    byte = 0
	kcmMaxReply      = 10 << 20
	kcmUUIDLen       = 16

	kcmOpGenNew           uint16 = 3
	kcmOpInitialize       uint16 = 4
	kcmOpDestroy          uint16 = 5
	kcmOpStore            uint16 = 6
	kcmOpRetrieve         uint16 = 7
	kcmOpGetPrincipal     uint16 = 8
	kcmOpGetCredUUIDList  uint16 = 9
	kcmOpGetCredByUUID    uint16 = 10
	kcmOpRemoveCred       uint16 = 11
	kcmOpGetCacheUUIDList uint16 = 18
	kcmOpGetCacheByUUID   uint16 = 19
	kcmOpGetDefaultCache  uint16 = 20
	kcmOpSetDefaultCache  uint16 = 21
	kcmOpGetKDCOffset     uint16 = 22
	kcmOpSetKDCOffset     uint16 = 23
	kcmOpGetCredList      uint16 = 13001
	kcmOpReplace          uint16 = 13002

	kcmGCCached uint32 = 1

	kcmTCDontMatchRealm  uint32 = 1 << 31
	kcmTCMatchKeyType    uint32 = 1 << 30
	kcmTCMatchSrvName    uint32 = 1 << 29
	kcmTCMatchFlagsExact uint32 = 1 << 28
	kcmTCMatchFlags      uint32 = 1 << 27
	kcmTCMatchTimesExact uint32 = 1 << 26
	kcmTCMatchTimes      uint32 = 1 << 25
	kcmTCMatchAuthData   uint32 = 1 << 24
	kcmTCMatchSecond     uint32 = 1 << 23
	kcmTCMatchSKey       uint32 = 1 << 22
)

// KCM retrieval and removal matching flags, using the Heimdal wire values.
const (
	// MIT credential-cache matching flags.
	MITMatchTimes           uint32 = 0x00000001
	MITMatchIsSKey          uint32 = 0x00000002
	MITMatchFlags           uint32 = 0x00000004
	MITMatchTimesExact      uint32 = 0x00000008
	MITMatchFlagsExact      uint32 = 0x00000010
	MITMatchAuthData        uint32 = 0x00000020
	MITMatchServerName      uint32 = 0x00000040
	MITMatchSecondTicket    uint32 = 0x00000080
	MITMatchKeyType         uint32 = 0x00000100
	MITMatchSupportedKTypes uint32 = 0x00000200
)

const (
	KCMMatchKeyType      uint32 = kcmTCMatchKeyType
	KCMMatchServerName   uint32 = kcmTCMatchSrvName
	KCMMatchFlagsExact   uint32 = kcmTCMatchFlagsExact
	KCMMatchFlags        uint32 = kcmTCMatchFlags
	KCMMatchTimesExact   uint32 = kcmTCMatchTimesExact
	KCMMatchTimes        uint32 = kcmTCMatchTimes
	KCMMatchAuthData     uint32 = kcmTCMatchAuthData
	KCMMatchSecondTicket uint32 = kcmTCMatchSecond
	KCMMatchIsSKey       uint32 = kcmTCMatchSKey
	KCMDontMatchRealm    uint32 = kcmTCDontMatchRealm
)

const (
	scClientPrincipal uint32 = 0x0001
	scServerPrincipal uint32 = 0x0002
	scSessionKey      uint32 = 0x0004
	scTicket          uint32 = 0x0008
	scSecondTicket    uint32 = 0x0010
	scAuthData        uint32 = 0x0020
	scAddresses       uint32 = 0x0040
	scKnown                  = scClientPrincipal | scServerPrincipal | scSessionKey |
		scTicket | scSecondTicket | scAuthData | scAddresses
)

// MapTCFlags translates MIT krb5 credential-cache matching flags to the
// Heimdal KCM wire flags.
func MapTCFlags(flags uint32) uint32 {
	var mapped uint32
	if flags&MITMatchTimes != 0 {
		mapped |= kcmTCMatchTimes
	}
	if flags&MITMatchIsSKey != 0 {
		mapped |= kcmTCMatchSKey
	}
	if flags&MITMatchFlags != 0 {
		mapped |= kcmTCMatchFlags
	}
	if flags&MITMatchTimesExact != 0 {
		mapped |= kcmTCMatchTimesExact
	}
	if flags&MITMatchFlagsExact != 0 {
		mapped |= kcmTCMatchFlagsExact
	}
	if flags&MITMatchAuthData != 0 {
		mapped |= kcmTCMatchAuthData
	}
	if flags&MITMatchServerName != 0 {
		mapped |= kcmTCMatchSrvName
	}
	if flags&MITMatchSecondTicket != 0 {
		mapped |= kcmTCMatchSecond
	}
	if flags&MITMatchKeyType != 0 {
		mapped |= kcmTCMatchKeyType
	}
	return mapped
}

const (
	kcmErrNotFound int32 = -1765328243
	kcmErrEnd      int32 = -1765328242
	kcmErrNoSupp   int32 = -1765328137
	kcmErrNoFile   int32 = -1765328189
	kcmErrInternal int32 = -1765328188
	kcmErrIO       int32 = -1765328248
)

// KCMError is a status returned by a KCM daemon.
type KCMError struct {
	Code int32
}

func (e *KCMError) Error() string { return fmt.Sprintf("kcm: status %d", e.Code) }

func writeFrame(w io.Writer, payload []byte) error {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, err := w.Write(length[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > kcmMaxReply || n < 4 {
		return nil, errors.New("kcm: invalid reply length")
	}
	var outerStatus [4]byte
	if _, err := io.ReadFull(r, outerStatus[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(outerStatus[:]) != 0 {
		return nil, errors.New("kcm: nonzero IPC status")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func cstring(value string) []byte { return append([]byte(value), 0) }

func marshalPrincipalBytes(value principal.Principal) ([]byte, error) {
	var b bytes.Buffer
	if err := encodePrincipal(&b, value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func marshalCredentialBytes(value Credential) ([]byte, error) {
	var b bytes.Buffer
	if err := encodeCredential(&b, value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func unmarshalPrincipalBytes(data []byte) (principal.Principal, int, error) {
	d := ccacheDecoder{Reader: binfmt.NewReader(data)}
	value, err := d.principal()
	return value, d.Offset(), err
}

func unmarshalCredentialBytes(data []byte) (Credential, error) {
	d := ccacheDecoder{Reader: binfmt.NewReader(data)}
	value, err := d.credential()
	if err != nil {
		return Credential{}, err
	}
	if d.Remaining() != 0 {
		return Credential{}, errors.New("kcm: trailing credential data")
	}
	return value, nil
}

func parseCString(value []byte) (string, error) {
	pos := bytes.IndexByte(value, 0)
	if pos < 0 {
		return "", errors.New("kcm: unterminated name")
	}
	return string(value[:pos]), nil
}

func marshalMatchCredential(value Credential) ([]byte, error) {
	var b bytes.Buffer
	var header uint32
	principalSet := func(p principal.Principal) bool {
		return p.Realm != "" || p.NameType != 0 || len(p.Components) != 0
	}
	if principalSet(value.Client) {
		header |= scClientPrincipal
	}
	if principalSet(value.Server) {
		header |= scServerPrincipal
	}
	if value.Enctype != 0 {
		header |= scSessionKey
	}
	if len(value.Ticket) != 0 {
		header |= scTicket
	}
	if len(value.SecondTicket) != 0 {
		header |= scSecondTicket
	}
	if len(value.AuthData) != 0 {
		header |= scAuthData
	}
	if len(value.Addresses) != 0 {
		header |= scAddresses
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(4)); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, header); err != nil {
		return nil, err
	}
	if header&scClientPrincipal != 0 {
		if err := encodePrincipal(&b, value.Client); err != nil {
			return nil, err
		}
	}
	if header&scServerPrincipal != 0 {
		if err := encodePrincipal(&b, value.Server); err != nil {
			return nil, err
		}
	}
	if header&scSessionKey != 0 {
		if value.Enctype < 0 || value.Enctype > int32(^uint16(0)) {
			return nil, errors.New("kcm: match enctype out of range")
		}
		if err := binary.Write(&b, binary.BigEndian, uint16(value.Enctype)); err != nil {
			return nil, err
		}
		if err := binfmt.WriteCounted32(&b, value.Key); err != nil {
			return nil, err
		}
	}
	for _, timestamp := range []uint32{value.AuthTime, value.StartTime, value.EndTime, value.RenewTill} {
		if err := binary.Write(&b, binary.BigEndian, timestamp); err != nil {
			return nil, err
		}
	}
	var isSKey byte
	if value.IsSKey {
		isSKey = 1
	}
	if err := b.WriteByte(isSKey); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, value.TicketFlags); err != nil {
		return nil, err
	}
	if header&scAddresses != 0 {
		if err := writeAddresses(&b, value.Addresses); err != nil {
			return nil, err
		}
	}
	if header&scAuthData != 0 {
		if err := writeAuthData(&b, value.AuthData); err != nil {
			return nil, err
		}
	}
	if header&scTicket != 0 {
		if err := binfmt.WriteCounted32(&b, value.Ticket); err != nil {
			return nil, err
		}
	}
	if header&scSecondTicket != 0 {
		if err := binfmt.WriteCounted32(&b, value.SecondTicket); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func readRequestFrame(r io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n < 4 || n > kcmMaxReply {
		return nil, errors.New("kcm: invalid request length")
	}
	value := make([]byte, n)
	_, err := io.ReadFull(r, value)
	return value, err
}

func unmarshalMatchCredential(data []byte) (Credential, error) {
	if len(data) < 8 {
		return Credential{}, errors.New("kcm: malformed match credential")
	}
	version := binary.BigEndian.Uint32(data[:4])
	header := binary.BigEndian.Uint32(data[4:8])
	if version != 4 || header&^scKnown != 0 {
		return Credential{}, errors.New("kcm: malformed match credential")
	}
	d := ccacheDecoder{Reader: binfmt.NewReaderAt(data, 8)}
	var value Credential
	var err error
	if header&scClientPrincipal != 0 {
		value.Client, err = d.principal()
		if err != nil {
			return Credential{}, err
		}
	}
	if header&scServerPrincipal != 0 {
		value.Server, err = d.principal()
		if err != nil {
			return Credential{}, err
		}
	}
	if header&scSessionKey != 0 {
		enctype, err := d.U16()
		if err != nil {
			return Credential{}, err
		}
		key, err := d.Counted32()
		if err != nil {
			return Credential{}, err
		}
		value.Enctype = int32(enctype)
		value.Key = append([]byte(nil), key...)
	}
	var times [4]uint32
	for i := range times {
		times[i], err = d.U32()
		if err != nil {
			return Credential{}, err
		}
	}
	value.AuthTime, value.StartTime, value.EndTime, value.RenewTill =
		times[0], times[1], times[2], times[3]
	isSKey, err := d.U8()
	if err != nil {
		return Credential{}, err
	}
	if isSKey > 1 {
		return Credential{}, errors.New("kcm: invalid match is_skey")
	}
	value.IsSKey = isSKey != 0
	value.TicketFlags, err = d.U32()
	if err != nil {
		return Credential{}, err
	}
	if header&scAddresses != 0 {
		value.Addresses, err = d.addresses()
		if err != nil {
			return Credential{}, err
		}
	}
	if header&scAuthData != 0 {
		value.AuthData, err = d.authData()
		if err != nil {
			return Credential{}, err
		}
	}
	if header&scTicket != 0 {
		value.Ticket, err = d.Counted32()
		if err != nil {
			return Credential{}, err
		}
		value.Ticket = append([]byte(nil), value.Ticket...)
	}
	if header&scSecondTicket != 0 {
		value.SecondTicket, err = d.Counted32()
		if err != nil {
			return Credential{}, err
		}
		value.SecondTicket = append([]byte(nil), value.SecondTicket...)
	}
	if d.Remaining() != 0 {
		return Credential{}, errors.New("kcm: trailing match credential data")
	}
	return value, nil
}

func splitCString(value []byte) (string, []byte, error) {
	pos := bytes.IndexByte(value, 0)
	if pos < 0 {
		return "", nil, errors.New("kcm: unterminated name")
	}
	return string(value[:pos]), value[pos+1:], nil
}

func credentialMatches(value, tag Credential, flags uint32) bool {
	if value.Client.Realm != tag.Client.Realm || len(value.Client.Components) != len(tag.Client.Components) {
		if flags&kcmTCDontMatchRealm == 0 {
			return false
		}
	}
	if len(value.Client.Components) == len(tag.Client.Components) {
		for i := range value.Client.Components {
			if value.Client.Components[i] != tag.Client.Components[i] {
				return false
			}
		}
	} else {
		return false
	}
	if flags&kcmTCMatchSrvName != 0 {
		if len(value.Server.Components) != len(tag.Server.Components) {
			return false
		}
		for i := range value.Server.Components {
			if value.Server.Components[i] != tag.Server.Components[i] {
				return false
			}
		}
	} else if value.Server.Realm != tag.Server.Realm || len(value.Server.Components) != len(tag.Server.Components) {
		return false
	} else {
		for i := range value.Server.Components {
			if value.Server.Components[i] != tag.Server.Components[i] {
				return false
			}
		}
	}
	if flags&kcmTCMatchKeyType != 0 && value.Enctype != tag.Enctype {
		return false
	}
	if flags&kcmTCMatchFlagsExact != 0 && value.TicketFlags != tag.TicketFlags {
		return false
	}
	if flags&kcmTCMatchFlags != 0 && value.TicketFlags&tag.TicketFlags != tag.TicketFlags {
		return false
	}
	if flags&kcmTCMatchTimesExact != 0 &&
		(value.AuthTime != tag.AuthTime || value.StartTime != tag.StartTime ||
			value.EndTime != tag.EndTime || value.RenewTill != tag.RenewTill) {
		return false
	}
	if flags&kcmTCMatchTimes != 0 &&
		(value.AuthTime < tag.AuthTime || value.EndTime < tag.EndTime) {
		return false
	}
	if flags&kcmTCMatchSKey != 0 && value.IsSKey != tag.IsSKey {
		return false
	}
	if flags&kcmTCMatchSecond != 0 && !bytes.Equal(value.SecondTicket, tag.SecondTicket) {
		return false
	}
	if flags&kcmTCMatchAuthData != 0 {
		if len(value.AuthData) != len(tag.AuthData) {
			return false
		}
		for i := range value.AuthData {
			if value.AuthData[i].Type != tag.AuthData[i].Type ||
				!bytes.Equal(value.AuthData[i].Data, tag.AuthData[i].Data) {
				return false
			}
		}
	}
	return true
}

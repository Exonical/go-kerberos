package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	LogonInfoExtraSids      uint32 = 0x00000020
	LogonInfoResourceGroups uint32 = 0x00000200
	ndrPointerValue         uint32 = 0x20000
)

// GroupMembership is a relative group identifier and its attributes.
type GroupMembership struct {
	RelativeID uint32
	Attributes uint32
}

// SIDAndAttributes associates a SID with its group attributes.
type SIDAndAttributes struct {
	SID        SID
	Attributes uint32
}

// LogonInfo is the structured KERB_VALIDATION_INFO payload. FILETIME values
// are represented as their unsigned 100-nanosecond Windows epoch values.
type LogonInfo struct {
	LogonTime, LogoffTime, KickOffTime, PasswordLastSet uint64
	PasswordCanChange, PasswordMustChange               uint64
	EffectiveName, FullName, LogonScript, ProfilePath   string
	HomeDirectory, HomeDirectoryDrive                   string
	LogonCount, BadPasswordCount                        uint16
	UserID, PrimaryGroupID                              uint32
	GroupIDs                                            []GroupMembership
	UserFlags                                           uint32
	UserSessionKey                                      [16]byte
	LogonServer, LogonDomainName                        string
	LogonDomainID                                       *SID
	UserAccountControl, SubAuthStatus                   uint32
	LastSuccessfulILogon, LastFailedILogon              uint64
	FailedILogonCount, Reserved3                        uint32
	SidCount                                            uint32
	ExtraSIDs                                           []SIDAndAttributes
	ResourceGroupDomainSID                              *SID
	// ResourceGroupCount is retained for decoded compatibility. MarshalBinary
	// derives the wire count from ResourceGroupIDs when the resource-group
	// flag is set.
	ResourceGroupCount uint32
	ResourceGroupIDs   []GroupMembership
	Reserved1          [2]uint32
}

type ndrWriter struct {
	buf      bytes.Buffer
	nextRef  uint32
	deferred []func() error
}

func (w *ndrWriter) align(n int) {
	pad := (-w.buf.Len()) & (n - 1)
	if pad != 0 {
		_, _ = w.buf.Write(make([]byte, pad))
	}
}

func (w *ndrWriter) put(value any) error {
	return binary.Write(&w.buf, binary.LittleEndian, value)
}

func (w *ndrWriter) ref(present bool) (uint32, error) {
	if !present {
		return 0, w.put(uint32(0))
	}
	w.nextRef++
	if err := w.put(ndrPointerValue + w.nextRef); err != nil {
		return 0, err
	}
	return ndrPointerValue + w.nextRef, nil
}

func (w *ndrWriter) unicode(value string) error {
	encoded, err := encodeUTF16(value)
	if err != nil {
		return err
	}
	if len(encoded) > 0xffff {
		return fmt.Errorf("PAC: NDR unicode string is too long")
	}
	if err := w.put(uint16(len(encoded))); err != nil {
		return err
	}
	if err := w.put(uint16(len(encoded))); err != nil {
		return err
	}
	ref, err := w.ref(true)
	if err != nil {
		return err
	}
	if ref != 0 {
		data := append([]byte(nil), encoded...)
		w.deferred = append(w.deferred, func() error {
			w.align(4)
			if err := w.put(uint32(len(data) / 2)); err != nil {
				return err
			}
			if err := w.put(uint32(0)); err != nil {
				return err
			}
			if err := w.put(uint32(len(data) / 2)); err != nil {
				return err
			}
			_, err := w.buf.Write(data)
			return err
		})
	}
	return nil
}

func (w *ndrWriter) sidPointer(value *SID) error {
	ref, err := w.ref(value != nil)
	if err != nil {
		return err
	}
	if ref != 0 {
		copyValue := *value
		copyValue.SubAuthorities = append([]uint32(nil), value.SubAuthorities...)
		w.deferred = append(w.deferred, func() error { return w.sid(&copyValue) })
	}
	return nil
}

func (w *ndrWriter) sid(value *SID) error {
	data, err := value.MarshalBinary()
	if err != nil {
		return err
	}
	w.align(4)
	if err := w.put(uint32(len(value.SubAuthorities))); err != nil {
		return err
	}
	if _, err := w.buf.Write(data[:8]); err != nil {
		return err
	}
	for _, sub := range value.SubAuthorities {
		if err := w.put(sub); err != nil {
			return err
		}
	}
	return nil
}

func (w *ndrWriter) groups(values []GroupMembership) error {
	ref, err := w.ref(len(values) != 0)
	if err != nil {
		return err
	}
	if ref != 0 {
		copyValues := append([]GroupMembership(nil), values...)
		w.deferred = append(w.deferred, func() error {
			w.align(4)
			if err := w.put(uint32(len(copyValues))); err != nil {
				return err
			}
			for _, group := range copyValues {
				if err := w.put(group.RelativeID); err != nil {
					return err
				}
				if err := w.put(group.Attributes); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return nil
}

func (w *ndrWriter) extraSIDs(values []SIDAndAttributes) error {
	ref, err := w.ref(len(values) != 0)
	if err != nil {
		return err
	}
	if ref != 0 {
		copyValues := append([]SIDAndAttributes(nil), values...)
		w.deferred = append(w.deferred, func() error {
			w.align(4)
			if err := w.put(uint32(len(copyValues))); err != nil {
				return err
			}
			for i := range copyValues {
				if _, err := w.ref(true); err != nil {
					return err
				}
				if err := w.put(copyValues[i].Attributes); err != nil {
					return err
				}
			}
			for i := range copyValues {
				if err := w.sid(&copyValues[i].SID); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return nil
}

// MarshalLogonInfo encodes KERB_VALIDATION_INFO with the NDR32 common and
// private headers used by Windows PAC logon-info buffers.
func (l LogonInfo) MarshalBinary() ([]byte, error) {
	var w ndrWriter
	w.nextRef = 0
	_, _ = w.buf.Write([]byte{1, 0x10, 8, 0})
	_ = w.put(uint32(0xCCCCCCCC))
	_ = w.put(uint32(0))
	_ = w.put(uint32(0))
	if _, err := w.ref(true); err != nil {
		return nil, err
	}
	for _, value := range []uint64{l.LogonTime, l.LogoffTime, l.KickOffTime,
		l.PasswordLastSet, l.PasswordCanChange, l.PasswordMustChange} {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []string{l.EffectiveName, l.FullName, l.LogonScript,
		l.ProfilePath, l.HomeDirectory, l.HomeDirectoryDrive} {
		if err := w.unicode(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint16{l.LogonCount, l.BadPasswordCount} {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint32{l.UserID, l.PrimaryGroupID, uint32(len(l.GroupIDs))} {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	if err := w.groups(l.GroupIDs); err != nil {
		return nil, err
	}
	if err := w.put(l.UserFlags); err != nil {
		return nil, err
	}
	if _, err := w.buf.Write(l.UserSessionKey[:]); err != nil {
		return nil, err
	}
	for _, value := range []string{l.LogonServer, l.LogonDomainName} {
		if err := w.unicode(value); err != nil {
			return nil, err
		}
	}
	if err := w.sidPointer(l.LogonDomainID); err != nil {
		return nil, err
	}
	for _, value := range l.Reserved1 {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint32{l.UserAccountControl, l.SubAuthStatus} {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint64{l.LastSuccessfulILogon, l.LastFailedILogon} {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	extra := l.ExtraSIDs
	if l.UserFlags&LogonInfoExtraSids == 0 {
		extra = nil
	}
	for _, value := range []uint32{l.FailedILogonCount, l.Reserved3,
		uint32(len(extra))} {
		if err := w.put(value); err != nil {
			return nil, err
		}
	}
	if err := w.extraSIDs(extra); err != nil {
		return nil, err
	}
	resourceDomain := l.ResourceGroupDomainSID
	if l.UserFlags&LogonInfoResourceGroups == 0 {
		resourceDomain = nil
	}
	if err := w.sidPointer(resourceDomain); err != nil {
		return nil, err
	}
	resourceCount := uint32(0)
	if l.UserFlags&LogonInfoResourceGroups != 0 {
		resourceCount = uint32(len(l.ResourceGroupIDs))
	}
	if err := w.put(resourceCount); err != nil {
		return nil, err
	}
	resourceGroups := l.ResourceGroupIDs
	if l.UserFlags&LogonInfoResourceGroups == 0 {
		resourceGroups = nil
	}
	if err := w.groups(resourceGroups); err != nil {
		return nil, err
	}
	for i := 0; i < len(w.deferred); i++ {
		if err := w.deferred[i](); err != nil {
			return nil, err
		}
	}
	out := w.buf.Bytes()
	binary.LittleEndian.PutUint32(out[8:], uint32(len(out)-16))
	return append([]byte(nil), out...), nil
}

// Marshal encodes the NDR32 KERB_VALIDATION_INFO payload.
func (l LogonInfo) Marshal() ([]byte, error) { return l.MarshalBinary() }

type ndrReader struct {
	data []byte
	off  int
}

func (r *ndrReader) align(n int) error {
	next := (r.off + n - 1) &^ (n - 1)
	if next > len(r.data) {
		return fmt.Errorf("PAC: truncated NDR alignment")
	}
	r.off = next
	return nil
}
func (r *ndrReader) bytes(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.off {
		return nil, fmt.Errorf("PAC: truncated NDR data")
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}
func (r *ndrReader) u16() (uint16, error) {
	v, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(v), nil
}
func (r *ndrReader) u32() (uint32, error) {
	v, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(v), nil
}
func (r *ndrReader) u64() (uint64, error) {
	v, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(v), nil
}
func (r *ndrReader) pointer() (bool, error) {
	v, err := r.u32()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

type ndrUnicodeDescriptor struct {
	length  uint16
	present bool
}

func (r *ndrReader) unicodeDescriptor() (ndrUnicodeDescriptor, error) {
	length, err := r.u16()
	if err != nil {
		return ndrUnicodeDescriptor{}, err
	}
	if _, err = r.u16(); err != nil {
		return ndrUnicodeDescriptor{}, err
	}
	present, err := r.pointer()
	if err != nil {
		return ndrUnicodeDescriptor{}, err
	}
	return ndrUnicodeDescriptor{length: length, present: present}, nil
}

func (r *ndrReader) readUnicode(desc ndrUnicodeDescriptor) (string, error) {
	if !desc.present {
		return "", nil
	}
	if err := r.align(4); err != nil {
		return "", err
	}
	max, err := r.u32()
	if err != nil {
		return "", err
	}
	if _, err = r.u32(); err != nil {
		return "", err
	}
	actual, err := r.u32()
	if err != nil || max < actual || actual != uint32(desc.length/2) {
		return "", fmt.Errorf("PAC: invalid NDR unicode array length=%d max=%d actual=%d off=%d", desc.length, max, actual, r.off)
	}
	data, err := r.bytes(int(actual) * 2)
	if err != nil {
		return "", err
	}
	return decodeUTF16(data)
}

func (r *ndrReader) sid(present bool) (*SID, error) {
	if !present {
		return nil, nil
	}
	if err := r.align(4); err != nil {
		return nil, err
	}
	count, err := r.u32()
	if err != nil || count > 15 {
		return nil, fmt.Errorf("PAC: invalid NDR SID")
	}
	body, err := r.bytes(8)
	if err != nil {
		return nil, err
	}
	if int(body[1]) != int(count) {
		return nil, fmt.Errorf("PAC: SID count mismatch")
	}
	var authority uint64
	for i := 0; i < 6; i++ {
		authority = authority<<8 | uint64(body[2+i])
	}
	s := SID{Revision: body[0], IdentifierAuthority: authority,
		SubAuthorities: make([]uint32, count)}
	for i := range s.SubAuthorities {
		s.SubAuthorities[i], err = r.u32()
		if err != nil {
			return nil, err
		}
	}
	return &s, nil
}

func (r *ndrReader) groups(present bool) ([]GroupMembership, error) {
	if !present {
		return nil, nil
	}
	if err := r.align(4); err != nil {
		return nil, err
	}
	count, err := r.u32()
	if err != nil || count > uint32((len(r.data)-r.off)/8) {
		return nil, fmt.Errorf("PAC: invalid NDR group array")
	}
	out := make([]GroupMembership, count)
	for i := range out {
		out[i].RelativeID, err = r.u32()
		if err != nil {
			return nil, err
		}
		out[i].Attributes, err = r.u32()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ParseLogonInfo decodes a Windows NDR32 KERB_VALIDATION_INFO payload.
func ParseLogonInfo(data []byte) (LogonInfo, error) {
	if len(data) < 20 || data[0] != 1 || data[1] != 0x10 ||
		binary.LittleEndian.Uint16(data[2:]) != 8 ||
		binary.LittleEndian.Uint32(data[4:]) != 0xCCCCCCCC {
		return LogonInfo{}, fmt.Errorf("PAC: invalid NDR common header")
	}
	objectLen := binary.LittleEndian.Uint32(data[8:])
	if int(objectLen) != len(data)-16 || binary.LittleEndian.Uint32(data[12:]) != 0 {
		return LogonInfo{}, fmt.Errorf("PAC: invalid NDR private header")
	}
	r := ndrReader{data: data, off: 16}
	if present, err := r.pointer(); err != nil || !present {
		return LogonInfo{}, fmt.Errorf("PAC: missing KERB_VALIDATION_INFO pointer")
	}
	var l LogonInfo
	var err error
	for _, dst := range []*uint64{&l.LogonTime, &l.LogoffTime, &l.KickOffTime,
		&l.PasswordLastSet, &l.PasswordCanChange, &l.PasswordMustChange} {
		*dst, err = r.u64()
		if err != nil {
			return LogonInfo{}, err
		}
	}
	stringDescs := make([]ndrUnicodeDescriptor, 6)
	for i := range stringDescs {
		stringDescs[i], err = r.unicodeDescriptor()
		if err != nil {
			return LogonInfo{}, err
		}
	}
	l.LogonCount, err = r.u16()
	if err != nil {
		return LogonInfo{}, err
	}
	l.BadPasswordCount, err = r.u16()
	if err != nil {
		return LogonInfo{}, err
	}
	l.UserID, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	l.PrimaryGroupID, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	groupCount, err := r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	groupPresent, err := r.pointer()
	if err != nil {
		return LogonInfo{}, err
	}
	l.UserFlags, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	key, err := r.bytes(16)
	if err != nil {
		return LogonInfo{}, err
	}
	copy(l.UserSessionKey[:], key)
	logonServerDesc, err := r.unicodeDescriptor()
	if err != nil {
		return LogonInfo{}, err
	}
	logonDomainDesc, err := r.unicodeDescriptor()
	if err != nil {
		return LogonInfo{}, err
	}
	domainPresent, err := r.pointer()
	if err != nil {
		return LogonInfo{}, err
	}
	for i := range l.Reserved1 {
		l.Reserved1[i], err = r.u32()
		if err != nil {
			return LogonInfo{}, err
		}
	}
	l.UserAccountControl, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	l.SubAuthStatus, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	l.LastSuccessfulILogon, err = r.u64()
	if err != nil {
		return LogonInfo{}, err
	}
	l.LastFailedILogon, err = r.u64()
	if err != nil {
		return LogonInfo{}, err
	}
	l.FailedILogonCount, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	l.Reserved3, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	l.SidCount, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	extraPresent, err := r.pointer()
	if err != nil {
		return LogonInfo{}, err
	}
	resourceDomainPresent, err := r.pointer()
	if err != nil {
		return LogonInfo{}, err
	}
	l.ResourceGroupCount, err = r.u32()
	if err != nil {
		return LogonInfo{}, err
	}
	resourceGroupsPresent, err := r.pointer()
	if err != nil {
		return LogonInfo{}, err
	}
	// Deferred referents are emitted in the order their pointers occur in the
	// fixed representation: strings, arrays, then SIDs.
	stringValues := []*string{&l.EffectiveName, &l.FullName, &l.LogonScript,
		&l.ProfilePath, &l.HomeDirectory, &l.HomeDirectoryDrive}
	for i, dst := range stringValues {
		*dst, err = r.readUnicode(stringDescs[i])
		if err != nil {
			return LogonInfo{}, fmt.Errorf("PAC: effective string %d: %w", i, err)
		}
	}
	l.GroupIDs, err = r.groups(groupPresent)
	if err != nil {
		return LogonInfo{}, fmt.Errorf("PAC: group array: %w", err)
	}
	if uint32(len(l.GroupIDs)) != groupCount {
		return LogonInfo{}, fmt.Errorf("PAC: group count mismatch")
	}
	l.LogonServer, err = r.readUnicode(logonServerDesc)
	if err != nil {
		return LogonInfo{}, fmt.Errorf("PAC: logon server: %w", err)
	}
	l.LogonDomainName, err = r.readUnicode(logonDomainDesc)
	if err != nil {
		return LogonInfo{}, fmt.Errorf("PAC: logon domain: %w", err)
	}
	l.LogonDomainID, err = r.sid(domainPresent)
	if err != nil {
		return LogonInfo{}, fmt.Errorf("PAC: logon domain SID: %w", err)
	}
	if extraPresent {
		if err := r.align(4); err != nil {
			return LogonInfo{}, err
		}
		count, err := r.u32()
		if err != nil || count != l.SidCount {
			return LogonInfo{}, fmt.Errorf("PAC: extra SID count mismatch")
		}
		if count > uint32((len(r.data)-r.off)/8) {
			return LogonInfo{}, fmt.Errorf("PAC: extra SID array exceeds input")
		}
		l.ExtraSIDs = make([]SIDAndAttributes, count)
		sidPresent := make([]bool, count)
		for i := range l.ExtraSIDs {
			sidPresent[i], err = r.pointer()
			if err != nil {
				return LogonInfo{}, err
			}
			l.ExtraSIDs[i].Attributes, err = r.u32()
			if err != nil {
				return LogonInfo{}, err
			}
		}
		for i, present := range sidPresent {
			var sid *SID
			sid, err = r.sid(present)
			if err != nil {
				return LogonInfo{}, fmt.Errorf("PAC: extra SID %d: %w", i, err)
			}
			if sid == nil {
				return LogonInfo{}, fmt.Errorf("PAC: missing extra SID")
			}
			l.ExtraSIDs[i].SID = *sid
		}
	}
	l.ResourceGroupDomainSID, err = r.sid(resourceDomainPresent)
	if err != nil {
		return LogonInfo{}, fmt.Errorf("PAC: resource domain SID: %w", err)
	}
	l.ResourceGroupIDs, err = r.groups(resourceGroupsPresent)
	if err != nil || uint32(len(l.ResourceGroupIDs)) != l.ResourceGroupCount {
		return LogonInfo{}, fmt.Errorf("PAC: resource group count mismatch")
	}
	if r.off != len(r.data) {
		remaining := r.data[r.off:]
		padding := (-r.off) & 7
		if len(remaining) != padding {
			return LogonInfo{}, fmt.Errorf("PAC: trailing NDR data")
		}
		for _, value := range remaining {
			if value != 0 {
				return LogonInfo{}, fmt.Errorf("PAC: non-zero NDR trailing data")
			}
		}
	}
	return l, nil
}

// Unmarshal decodes an NDR32 KERB_VALIDATION_INFO payload.
func (l *LogonInfo) Unmarshal(data []byte) error {
	if l == nil {
		return fmt.Errorf("PAC: nil LogonInfo")
	}
	value, err := ParseLogonInfo(data)
	if err != nil {
		return err
	}
	*l = value
	return nil
}

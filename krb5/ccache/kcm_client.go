package ccache

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

type kcmHandle struct {
	name   string
	socket string
	mu     sync.Mutex
	conn   net.Conn
}

func resolveKCM(residual string) (*Handle, error) {
	return resolveKCMSocket(residual, DefaultKCMSocketPath)
}

// ResolveKCM resolves a KCM cache using an explicit Unix socket path.
// An empty socket uses DefaultKCMSocketPath; "-" disables KCM.
func ResolveKCM(residual, socket string) (*Handle, error) {
	if socket == "" {
		socket = DefaultKCMSocketPath
	}
	return resolveKCMSocket(residual, socket)
}

func resolveKCMSocket(residual, socket string) (*Handle, error) {
	if socket == "-" {
		return nil, errors.New("ccache: KCM disabled")
	}
	h := &Handle{typ: TypeKCM, name: "KCM:" + residual, kcm: &kcmHandle{name: residual, socket: socket}}
	if residual == "" {
		name, err := h.kcm.defaultName()
		if err != nil {
			_ = h.Close()
			return nil, err
		}
		h.kcm.name = name
		h.name = "KCM:" + name
	}
	return h, nil
}

func (h *kcmHandle) call(op uint16, args []byte) ([]byte, error) {
	request := make([]byte, 4+len(args))
	request[0], request[1] = kcmMajor, kcmMinor
	binary.BigEndian.PutUint16(request[2:4], op)
	copy(request[4:], args)
	h.mu.Lock()
	defer h.mu.Unlock()
	var err error
	if h.conn == nil {
		h.conn, err = net.DialTimeout("unix", h.socket, 5*time.Second)
		if err != nil {
			return nil, err
		}
	}
	if err := writeFrame(h.conn, request); err != nil {
		if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, syscall.EPIPE) {
			_ = h.conn.Close()
			h.conn = nil
			return nil, err
		}
		_ = h.conn.Close()
		h.conn, err = net.DialTimeout("unix", h.socket, 5*time.Second)
		if err != nil {
			return nil, err
		}
		if err := writeFrame(h.conn, request); err != nil {
			_ = h.conn.Close()
			h.conn = nil
			return nil, err
		}
	}
	payload, err := readFrame(h.conn)
	if err != nil {
		_ = h.conn.Close()
		h.conn = nil
		return nil, err
	}
	if len(payload) < 4 {
		return nil, errors.New("kcm: malformed reply")
	}
	code := int32(binary.BigEndian.Uint32(payload[:4]))
	if code != 0 {
		return nil, &KCMError{Code: code}
	}
	return payload[4:], nil
}

func (h *kcmHandle) defaultName() (string, error) {
	value, err := h.call(kcmOpGetDefaultCache, nil)
	if err != nil {
		return "", err
	}
	return parseCString(value)
}

func (h *kcmHandle) newCache() (*Handle, error) {
	value, err := h.call(kcmOpGenNew, nil)
	if err != nil {
		return nil, err
	}
	name, err := parseCString(value)
	if err != nil {
		return nil, err
	}
	return &Handle{typ: TypeKCM, name: "KCM:" + name,
		kcm: &kcmHandle{name: name, socket: h.socket}}, nil
}

func (h *kcmHandle) principal() (principal.Principal, error) {
	value, err := h.call(kcmOpGetPrincipal, cstring(h.name))
	if err != nil {
		return principal.Principal{}, err
	}
	p, used, err := unmarshalPrincipalBytes(value)
	if err != nil || (used != len(value) && (used+1 != len(value) || value[used] != 0)) {
		return principal.Principal{}, errors.New("kcm: malformed principal")
	}
	return p, nil
}

func (h *kcmHandle) read() (*Cache, error) {
	p, err := h.principal()
	if err != nil {
		return nil, err
	}
	cache := &Cache{DefaultPrincipal: p}
	if value, err := h.call(kcmOpGetKDCOffset, cstring(h.name)); err == nil && len(value) == 4 {
		cache.Header.TimeOffset = int32(binary.BigEndian.Uint32(value))
	}
	if value, err := h.call(kcmOpGetCredList, cstring(h.name)); err == nil {
		if len(value) < 4 {
			return nil, errors.New("kcm: malformed credential list")
		}
		count := binary.BigEndian.Uint32(value[:4])
		if uint64(count) > uint64(len(value)-4)/4 {
			return nil, errors.New("kcm: credential count exceeds payload")
		}
		off := 4
		for i := uint32(0); i < count; i++ {
			if off+4 > len(value) {
				return nil, errors.New("kcm: malformed credential list")
			}
			n := int(binary.BigEndian.Uint32(value[off : off+4]))
			off += 4
			if n < 0 || n > len(value)-off {
				return nil, errors.New("kcm: malformed credential list")
			}
			cred, err := unmarshalCredentialBytes(value[off : off+n])
			if err != nil {
				return nil, err
			}
			cache.Credentials = append(cache.Credentials, cred)
			off += n
		}
		return cache, nil
	} else if !unsupportedKCM(err) {
		return nil, err
	}
	uuids, err := h.call(kcmOpGetCredUUIDList, cstring(h.name))
	if err != nil {
		return nil, err
	}
	if len(uuids)%kcmUUIDLen != 0 {
		return nil, errors.New("kcm: malformed UUID list")
	}
	for off := 0; off < len(uuids); off += kcmUUIDLen {
		value, err := h.call(kcmOpGetCredByUUID, append(cstring(h.name), uuids[off:off+kcmUUIDLen]...))
		if err != nil {
			return nil, err
		}
		cred, err := unmarshalCredentialBytes(value)
		if err != nil {
			return nil, err
		}
		cache.Credentials = append(cache.Credentials, cred)
	}
	return cache, nil
}

func (h *kcmHandle) write(cache *Cache) error {
	if cache == nil {
		return errors.New("kcm: nil cache")
	}
	principalBytes, err := marshalPrincipalBytes(cache.DefaultPrincipal)
	if err != nil {
		return err
	}
	args := append(cstring(h.name), make([]byte, 4)...)
	binary.BigEndian.PutUint32(args[len(args)-4:], uint32(cache.Header.TimeOffset))
	args = append(args, principalBytes...)
	args = append(args, make([]byte, 4)...)
	binary.BigEndian.PutUint32(args[len(args)-4:], uint32(len(cache.Credentials)))
	for _, cred := range cache.Credentials {
		value, err := marshalCredentialBytes(cred)
		if err != nil {
			return err
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		args = append(args, length[:]...)
		args = append(args, value...)
	}
	if _, err := h.call(kcmOpReplace, args); err == nil {
		return nil
	} else if !unsupportedKCM(err) {
		return err
	}
	if _, err := h.call(kcmOpInitialize, append(cstring(h.name), principalBytes...)); err != nil {
		return err
	}
	for _, cred := range cache.Credentials {
		value, err := marshalCredentialBytes(cred)
		if err != nil {
			return err
		}
		if _, err := h.call(kcmOpStore, append(cstring(h.name), value...)); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handle) Initialize(p principal.Principal) error {
	if h != nil && h.typ == TypeKeyring {
		return h.keyring.initialize(p)
	}
	if h != nil && h.typ == TypeMSLSA {
		return ErrMSLSAReadOnly
	}
	if h == nil || h.typ != TypeKCM {
		return errors.New("ccache: initialize requires a KCM cache")
	}
	value, err := marshalPrincipalBytes(p)
	if err != nil {
		return err
	}
	_, err = h.kcm.call(kcmOpInitialize, append(cstring(h.kcm.name), value...))
	return err
}

// Store adds one credential to a FILE, DIR, MEMORY, KCM, or KEYRING cache.
func (h *Handle) Store(credential Credential) error {
	if h != nil && h.typ == TypeKeyring {
		return h.keyring.store(credential)
	}
	if h != nil && h.typ == TypeMSLSA {
		return ErrMSLSAReadOnly
	}
	if h == nil {
		return errors.New("ccache: store requires a cache")
	}
	if h.typ == TypeFile || h.typ == TypeDir || h.typ == TypeMemory {
		return h.modifyCache(func(cache *Cache) error {
			cache.Credentials = append(cache.Credentials, credential)
			return nil
		})
	}
	if h.typ != TypeKCM {
		cache, err := h.Read()
		if err != nil {
			return err
		}
		cache.Credentials = append(cache.Credentials, credential)
		return h.Write(cache)
	}
	value, err := marshalCredentialBytes(credential)
	if err != nil {
		return err
	}
	_, err = h.kcm.call(kcmOpStore, append(cstring(h.kcm.name), value...))
	return err
}

// Retrieve finds a credential using MIT matching flags from a FILE, DIR,
// MEMORY, KCM, or KEYRING cache. The KCM implementation first asks the daemon
// for cached credentials, then retries without the KCM_GC_CACHED bit for
// older daemons.
func (h *Handle) Retrieve(match Credential, flags uint32) (Credential, error) {
	if h != nil && h.typ == TypeKeyring {
		cache, err := h.Read()
		if err != nil {
			return Credential{}, err
		}
		credential, err := retrieveCredentialsWithOrder(
			cache.Credentials, match, flags, supportedEnctypeOrder(h))
		if errors.Is(err, errCredentialNotFound) {
			return Credential{}, errors.New("ccache: KEYRING credential not found")
		}
		return credential, err
	}
	if h != nil && h.typ == TypeMSLSA {
		cache, err := h.Read()
		if err != nil {
			return Credential{}, err
		}
		wireFlags := MapTCFlags(flags)
		for _, candidate := range cache.Credentials {
			if credentialMatches(candidate, match, wireFlags) {
				return candidate, nil
			}
		}
		return Credential{}, errors.New("ccache: MSLSA credential not found")
	}
	if h == nil {
		return Credential{}, errors.New("ccache: retrieve requires a cache")
	}
	if h.typ != TypeKCM {
		cache, err := h.Read()
		if err != nil {
			return Credential{}, err
		}
		return retrieveCredentialsWithOrder(cache.Credentials, match, flags, supportedEnctypeOrder(h))
	}
	if flags&MITMatchSupportedKTypes != 0 {
		cache, err := h.Read()
		if err != nil {
			return Credential{}, err
		}
		return retrieveCredentialsWithOrder(cache.Credentials, match, flags, supportedEnctypeOrder(h))
	}
	value, err := marshalMatchCredential(match)
	if err != nil {
		return Credential{}, err
	}
	args := append(cstring(h.kcm.name), make([]byte, 4)...)
	wireFlags := MapTCFlags(flags)
	binary.BigEndian.PutUint32(args[len(args)-4:], wireFlags|kcmGCCached)
	args = append(args, value...)
	reply, err := h.kcm.call(kcmOpRetrieve, args)
	if unsupportedKCM(err) {
		nameLen := len(h.kcm.name) + 1
		binary.BigEndian.PutUint32(args[nameLen:nameLen+4], wireFlags)
		reply, err = h.kcm.call(kcmOpRetrieve, args)
		if unsupportedKCM(err) {
			cache, listErr := h.kcm.read()
			if listErr != nil {
				return Credential{}, err
			}
			for _, candidate := range cache.Credentials {
				if credentialMatches(candidate, match, wireFlags) {
					return candidate, nil
				}
			}
			return Credential{}, &KCMError{Code: kcmErrNotFound}
		}
	}
	if err != nil {
		return Credential{}, err
	}
	credential, err := unmarshalCredentialBytes(reply)
	if err != nil {
		return Credential{}, err
	}
	return credential, nil
}

// Remove removes every credential matching match and flags.
func (h *Handle) Remove(match Credential, flags uint32) error {
	if h != nil && h.typ == TypeKeyring {
		if flags&MITMatchSupportedKTypes != 0 {
			cache, err := h.Read()
			if err != nil {
				return err
			}
			if err := removeCredentials(cache, match, flags); err != nil {
				return err
			}
			return h.Write(cache)
		}
		return h.keyring.remove(match, flags)
	}
	if h != nil && h.typ == TypeMSLSA {
		return ErrMSLSAReadOnly
	}
	if h == nil {
		return errors.New("ccache: remove requires a cache")
	}
	if h.typ == TypeFile || h.typ == TypeDir || h.typ == TypeMemory {
		return h.modifyCache(func(cache *Cache) error {
			return removeCredentials(cache, match, flags)
		})
	}
	if h.typ != TypeKCM {
		cache, err := h.Read()
		if err != nil {
			return err
		}
		if err := removeCredentials(cache, match, flags); err != nil {
			return err
		}
		return h.Write(cache)
	}
	if flags&MITMatchSupportedKTypes != 0 {
		cache, err := h.Read()
		if err != nil {
			return err
		}
		if err := removeCredentials(cache, match, flags); err != nil {
			return err
		}
		return h.Write(cache)
	}
	value, err := marshalMatchCredential(match)
	if err != nil {
		return err
	}
	args := append(cstring(h.kcm.name), make([]byte, 4)...)
	binary.BigEndian.PutUint32(args[len(args)-4:], MapTCFlags(flags))
	args = append(args, value...)
	_, err = h.kcm.call(kcmOpRemoveCred, args)
	return err
}

// Destroy deletes a KCM cache.
func (h *Handle) Destroy() error {
	if h != nil && h.typ == TypeKeyring {
		return h.keyring.destroy()
	}
	if h == nil {
		return errors.New("ccache: destroy requires a cache")
	}
	switch h.typ {
	case TypeFile, TypeDir:
		if err := os.Remove(h.path); err != nil {
			return err
		}
		return nil
	case TypeMemory:
		residual := strings.TrimPrefix(h.name, "MEMORY:")
		memoryMu.Lock()
		h.memoryHandleMu.RLock()
		memory := h.memory
		h.memoryHandleMu.RUnlock()
		if current := memoryCaches[residual]; current == memory {
			memory.mu.Lock()
			memory.cache = nil
			memory.destroyed = true
			memory.mu.Unlock()
			delete(memoryCaches, residual)
		}
		memoryMu.Unlock()
		return nil
	case TypeKCM:
		_, err := h.kcm.call(kcmOpDestroy, cstring(h.kcm.name))
		return err
	case TypeMSLSA:
		return ErrMSLSAReadOnly
	default:
		return errors.New("ccache: unsupported cache destruction")
	}
}

// SetDefault makes this KCM cache the collection default.
func (h *Handle) SetDefault() error {
	if h == nil || h.typ != TypeKCM {
		return errors.New("ccache: set default requires a KCM cache")
	}
	_, err := h.kcm.call(kcmOpSetDefaultCache, cstring(h.kcm.name))
	return err
}

// KDCOffset gets the signed KDC time offset in seconds.
func (h *Handle) KDCOffset() (int32, error) {
	if h == nil || h.typ != TypeKCM {
		return 0, errors.New("ccache: offset requires a KCM cache")
	}
	value, err := h.kcm.call(kcmOpGetKDCOffset, cstring(h.kcm.name))
	if err != nil {
		return 0, err
	}
	if len(value) != 4 {
		return 0, errors.New("kcm: malformed KDC offset")
	}
	return int32(binary.BigEndian.Uint32(value)), nil
}

// SetKDCOffset stores a signed KDC time offset in seconds.
func (h *Handle) SetKDCOffset(offset int32) error {
	if h == nil || h.typ != TypeKCM {
		return errors.New("ccache: offset requires a KCM cache")
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, uint32(offset))
	_, err := h.kcm.call(kcmOpSetKDCOffset, append(cstring(h.kcm.name), value...))
	return err
}

// Close releases a KCM connection. Other cache backends do not retain
// connection state and Close is a no-op for them.
func (h *Handle) Close() error {
	if h == nil || h.typ != TypeKCM || h.kcm == nil {
		return nil
	}
	h.kcm.mu.Lock()
	defer h.kcm.mu.Unlock()
	if h.kcm.conn == nil {
		return nil
	}
	err := h.kcm.conn.Close()
	h.kcm.conn = nil
	return err
}

func unsupportedKCM(err error) bool {
	var kerr *KCMError
	if !errors.As(err, &kerr) {
		return false
	}
	return kerr.Code == kcmErrInternal || kerr.Code == kcmErrIO || kerr.Code == kcmErrNoSupp
}

func (h *kcmHandle) collection() ([]*Handle, error) {
	value, err := h.call(kcmOpGetCacheUUIDList, nil)
	if err != nil {
		return nil, err
	}
	primary, err := h.defaultName()
	if err != nil {
		return nil, err
	}
	result := make([]*Handle, 0, len(value)/kcmUUIDLen+1)
	seen := map[string]bool{}
	appendName := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			result = append(result, &Handle{typ: TypeKCM, name: "KCM:" + name, kcm: &kcmHandle{name: name, socket: h.socket}})
		}
	}
	appendName(primary)
	for off := 0; off+kcmUUIDLen <= len(value); off += kcmUUIDLen {
		nameBytes, err := h.call(kcmOpGetCacheByUUID, value[off:off+kcmUUIDLen])
		if err == nil {
			name, parseErr := parseCString(nameBytes)
			if parseErr == nil {
				appendName(name)
			}
		}
	}
	return result, nil
}

// KCMServer serves the Heimdal KCM v2 protocol over a Unix socket.

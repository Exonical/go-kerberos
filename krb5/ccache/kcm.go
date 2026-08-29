package ccache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

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
	MITMatchTimes        uint32 = 0x00000001
	MITMatchIsSKey       uint32 = 0x00000002
	MITMatchFlags        uint32 = 0x00000004
	MITMatchTimesExact   uint32 = 0x00000008
	MITMatchFlagsExact   uint32 = 0x00000010
	MITMatchAuthData     uint32 = 0x00000020
	MITMatchServerName   uint32 = 0x00000040
	MITMatchSecondTicket uint32 = 0x00000080
	MITMatchKeyType      uint32 = 0x00000100
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
	d := ccacheDecoder{data: data}
	value, err := d.principal()
	return value, d.off, err
}

func unmarshalCredentialBytes(data []byte) (Credential, error) {
	d := ccacheDecoder{data: data}
	value, err := d.credential()
	if err != nil {
		return Credential{}, err
	}
	if d.remaining() != 0 {
		return Credential{}, errors.New("kcm: trailing credential data")
	}
	return value, nil
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

func parseCString(value []byte) (string, error) {
	pos := bytes.IndexByte(value, 0)
	if pos < 0 {
		return "", errors.New("kcm: unterminated name")
	}
	return string(value[:pos]), nil
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

func marshalMatchCredential(value Credential) ([]byte, error) {
	var b bytes.Buffer
	// k5_marshal_mcred uses a version and a presence header, followed by
	// only the fields selected by that header.  Client and server principals
	// are the fields needed by all KCM implementations.
	var version uint32 = 4
	var header uint32 = 0x0003
	if err := binary.Write(&b, binary.BigEndian, version); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, header); err != nil {
		return nil, err
	}
	if err := encodePrincipal(&b, value.Client); err != nil {
		return nil, err
	}
	if err := encodePrincipal(&b, value.Server); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
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

// Initialize replaces a KCM cache with a principal and no credentials.
func (h *Handle) Initialize(p principal.Principal) error {
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

// Store adds one credential to a KCM cache.
func (h *Handle) Store(credential Credential) error {
	if h == nil || h.typ != TypeKCM {
		return errors.New("ccache: store requires a KCM cache")
	}
	value, err := marshalCredentialBytes(credential)
	if err != nil {
		return err
	}
	_, err = h.kcm.call(kcmOpStore, append(cstring(h.kcm.name), value...))
	return err
}

// Retrieve finds a credential using KCM matching flags.  The implementation
// first asks the daemon for cached credentials, then retries without the
// KCM_GC_CACHED bit for older daemons.
func (h *Handle) Retrieve(match Credential, flags uint32) (Credential, error) {
	if h == nil || h.typ != TypeKCM {
		return Credential{}, errors.New("ccache: retrieve requires a KCM cache")
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

// Remove removes the first credential matching match and flags.
func (h *Handle) Remove(match Credential, flags uint32) error {
	if h == nil || h.typ != TypeKCM {
		return errors.New("ccache: remove requires a KCM cache")
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
	if h == nil || h.typ != TypeKCM {
		return errors.New("ccache: destroy requires a KCM cache")
	}
	_, err := h.kcm.call(kcmOpDestroy, cstring(h.kcm.name))
	return err
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
type KCMServer struct {
	Socket      string
	mu          sync.Mutex
	caches      map[string]*kcmServerCache
	uuids       map[[16]byte]string
	defaultName string
	next        uint64
	listener    net.Listener
}

type kcmServerCache struct {
	name      string
	uuid      [16]byte
	principal *principal.Principal
	creds     [][]byte
	offset    int32
}

// NewKCMServer creates an in-memory KCM server at socket.
func NewKCMServer(socket string) *KCMServer {
	return &KCMServer{Socket: socket, caches: make(map[string]*kcmServerCache), uuids: make(map[[16]byte]string), defaultName: "default"}
}

// Serve listens and serves KCM requests until the listener fails.
func (s *KCMServer) Serve() error {
	if s == nil || s.Socket == "" {
		return errors.New("kcm: invalid server socket")
	}
	_ = os.Remove(s.Socket)
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0700); err != nil {
		return err
	}
	listener, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	defer os.Remove(s.Socket)
	return s.ServeListener(listener)
}

// ServeListener serves KCM requests on an already-created Unix listener.
// This is useful when the caller needs an explicit lifecycle for a daemon.
func (s *KCMServer) ServeListener(listener net.Listener) error {
	if listener == nil {
		return errors.New("kcm: nil listener")
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.listener == listener {
			s.listener = nil
		}
		s.mu.Unlock()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

// Close stops a server started with Serve or ServeListener.
func (s *KCMServer) Close() error {
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *KCMServer) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		request, err := readRequestFrame(conn)
		if err != nil {
			return
		}
		payload, code := s.dispatch(request)
		reply := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(reply[:4], uint32(code))
		copy(reply[4:], payload)
		var outer bytes.Buffer
		var zero [4]byte
		_ = binary.Write(&outer, binary.BigEndian, uint32(len(reply)))
		_, _ = outer.Write(zero[:])
		_, _ = outer.Write(reply)
		if _, err := conn.Write(outer.Bytes()); err != nil {
			return
		}
	}
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

func (s *KCMServer) dispatch(request []byte) ([]byte, int32) {
	if len(request) < 4 || request[0] != kcmMajor || request[1] != kcmMinor {
		return nil, kcmErrInternal
	}
	op := binary.BigEndian.Uint16(request[2:4])
	args := request[4:]
	switch op {
	case kcmOpGetDefaultCache:
		s.mu.Lock()
		name := s.defaultName
		s.mu.Unlock()
		return cstring(name), 0
	case kcmOpGenNew:
		s.mu.Lock()
		s.next++
		name := fmt.Sprintf("unique%d", s.next)
		s.ensure(name)
		s.mu.Unlock()
		return cstring(name), 0
	case kcmOpGetCacheUUIDList:
		s.mu.Lock()
		defer s.mu.Unlock()
		value := make([]byte, 0, len(s.uuids)*kcmUUIDLen)
		for uuid := range s.uuids {
			value = append(value, uuid[:]...)
		}
		return value, 0
	case kcmOpGetCacheByUUID:
		if len(args) != kcmUUIDLen {
			return nil, kcmErrInternal
		}
		var uuid [16]byte
		copy(uuid[:], args)
		s.mu.Lock()
		name, ok := s.uuids[uuid]
		s.mu.Unlock()
		if !ok {
			return nil, kcmErrEnd
		}
		return cstring(name), 0
	}
	name, rest, err := splitCString(args)
	if err != nil {
		return nil, kcmErrInternal
	}
	s.mu.Lock()
	cache := s.ensure(name)
	s.mu.Unlock()
	switch op {
	case kcmOpInitialize:
		p, used, err := unmarshalPrincipalBytes(rest)
		if err != nil || used != len(rest) {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		cache.principal = &p
		cache.creds = nil
		cache.offset = 0
		s.mu.Unlock()
		return nil, 0
	case kcmOpDestroy:
		s.mu.Lock()
		delete(s.caches, name)
		delete(s.uuids, cache.uuid)
		if s.defaultName == name {
			s.defaultName = "default"
		}
		s.mu.Unlock()
		return nil, 0
	case kcmOpGetPrincipal:
		s.mu.Lock()
		p := cache.principal
		s.mu.Unlock()
		if p == nil {
			return nil, kcmErrNoFile
		}
		value, err := marshalPrincipalBytes(*p)
		if err != nil {
			return nil, kcmErrInternal
		}
		return value, 0
	case kcmOpStore:
		s.mu.Lock()
		cache.creds = append(cache.creds, append([]byte(nil), rest...))
		s.mu.Unlock()
		return nil, 0
	case kcmOpGetCredList:
		s.mu.Lock()
		defer s.mu.Unlock()
		var value bytes.Buffer
		_ = binary.Write(&value, binary.BigEndian, uint32(len(cache.creds)))
		for _, cred := range cache.creds {
			_ = binary.Write(&value, binary.BigEndian, uint32(len(cred)))
			_, _ = value.Write(cred)
		}
		return value.Bytes(), 0
	case kcmOpGetCredUUIDList:
		s.mu.Lock()
		defer s.mu.Unlock()
		value := make([]byte, 0, len(cache.creds)*kcmUUIDLen)
		for i := range cache.creds {
			value = append(value, serverCredUUID(cache.uuid, i)...)
		}
		return value, 0
	case kcmOpGetCredByUUID:
		if len(rest) != kcmUUIDLen {
			return nil, kcmErrInternal
		}
		index, ok := parseCredUUID(cache.uuid, rest)
		if !ok {
			return nil, kcmErrEnd
		}
		s.mu.Lock()
		if index >= len(cache.creds) {
			s.mu.Unlock()
			return nil, kcmErrEnd
		}
		value := append([]byte(nil), cache.creds[index]...)
		s.mu.Unlock()
		return value, 0
	case kcmOpRetrieve:
		if len(rest) < 4 {
			return nil, kcmErrInternal
		}
		flags := binary.BigEndian.Uint32(rest[:4])
		if len(rest) < 8 {
			return nil, kcmErrInternal
		}
		tag, err := unmarshalMatchCredential(rest[4:])
		if err != nil {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, raw := range cache.creds {
			cred, err := unmarshalCredentialBytes(raw)
			if err == nil && credentialMatches(cred, tag, flags) {
				return raw, 0
			}
		}
		return nil, kcmErrNotFound
	case kcmOpRemoveCred:
		if len(rest) < 4 {
			return nil, kcmErrInternal
		}
		flags := binary.BigEndian.Uint32(rest[:4])
		tag, err := unmarshalMatchCredential(rest[4:])
		if err != nil {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := 0; i < len(cache.creds); i++ {
			cred, err := unmarshalCredentialBytes(cache.creds[i])
			if err == nil && credentialMatches(cred, tag, flags) {
				cache.creds = append(cache.creds[:i], cache.creds[i+1:]...)
				return nil, 0
			}
		}
		return nil, kcmErrNotFound
	case kcmOpSetDefaultCache:
		s.mu.Lock()
		s.defaultName = name
		s.mu.Unlock()
		return nil, 0
	case kcmOpGetKDCOffset:
		s.mu.Lock()
		offset := cache.offset
		s.mu.Unlock()
		var value [4]byte
		binary.BigEndian.PutUint32(value[:], uint32(offset))
		return value[:], 0
	case kcmOpSetKDCOffset:
		if len(rest) != 4 {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		cache.offset = int32(binary.BigEndian.Uint32(rest))
		s.mu.Unlock()
		return nil, 0
	case kcmOpReplace:
		return s.replace(cache, rest)
	default:
		return nil, kcmErrInternal
	}
}

func unmarshalMatchCredential(data []byte) (Credential, error) {
	if len(data) < 8 {
		return Credential{}, errors.New("kcm: malformed match credential")
	}
	version := binary.BigEndian.Uint32(data[:4])
	header := binary.BigEndian.Uint32(data[4:8])
	if version != 4 || header&0x3 != 0x3 {
		return Credential{}, errors.New("kcm: malformed match credential")
	}
	off := 8
	client, used, err := unmarshalPrincipalBytes(data[off:])
	if err != nil {
		return Credential{}, err
	}
	off += used
	server, used, err := unmarshalPrincipalBytes(data[off:])
	if err != nil {
		return Credential{}, err
	}
	off += used
	return Credential{Client: client, Server: server}, nil
}

func splitCString(value []byte) (string, []byte, error) {
	pos := bytes.IndexByte(value, 0)
	if pos < 0 {
		return "", nil, errors.New("kcm: unterminated name")
	}
	return string(value[:pos]), value[pos+1:], nil
}

func (s *KCMServer) ensure(name string) *kcmServerCache {
	cache := s.caches[name]
	if cache != nil {
		return cache
	}
	s.next++
	var uuid [16]byte
	binary.BigEndian.PutUint64(uuid[8:], s.next)
	cache = &kcmServerCache{name: name, uuid: uuid}
	s.caches[name] = cache
	s.uuids[uuid] = name
	return cache
}

func (s *KCMServer) replace(cache *kcmServerCache, rest []byte) ([]byte, int32) {
	if len(rest) < 8 {
		return nil, kcmErrInternal
	}
	offset := int32(binary.BigEndian.Uint32(rest[:4]))
	p, used, err := unmarshalPrincipalBytes(rest[4:])
	if err != nil {
		return nil, kcmErrInternal
	}
	rest = rest[4+used:]
	if len(rest) < 4 {
		return nil, kcmErrInternal
	}
	count := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	creds := make([][]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(rest) < 4 {
			return nil, kcmErrInternal
		}
		n := int(binary.BigEndian.Uint32(rest[:4]))
		rest = rest[4:]
		if n < 0 || n > len(rest) {
			return nil, kcmErrInternal
		}
		creds = append(creds, append([]byte(nil), rest[:n]...))
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, kcmErrInternal
	}
	s.mu.Lock()
	cache.principal = &p
	cache.offset = offset
	cache.creds = creds
	s.mu.Unlock()
	return nil, 0
}

func serverCredUUID(cache [16]byte, index int) []byte {
	var value [16]byte
	copy(value[:], cache[:])
	binary.BigEndian.PutUint32(value[12:], uint32(index+1))
	return value[:]
}

func parseCredUUID(cache [16]byte, value []byte) (int, bool) {
	if len(value) != 16 || !bytes.Equal(value[:12], cache[:12]) {
		return 0, false
	}
	index := binary.BigEndian.Uint32(value[12:])
	if index == 0 {
		return 0, false
	}
	return int(index - 1), true
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
		if len(value.Server.Components) > 0 && value.Server.Components[0] != tag.Server.Components[0] {
			return false
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
	if flags&kcmTCMatchAuthData != 0 && len(value.AuthData) != len(tag.AuthData) {
		return false
	}
	return true
}

package ccache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

type KCMServer struct {
	Socket string
	// IsolatePeers scopes all cache state to the Unix peer UID. When false,
	// the server retains the shared namespace used by the test daemon and
	// existing callers.
	IsolatePeers bool
	mu           sync.Mutex
	shared       *kcmNamespace
	namespaces   map[uint32]*kcmNamespace
	peerUID      func(net.Conn) (uint32, error)
	listener     net.Listener
	conns        map[net.Conn]struct{}
}

type kcmNamespace struct {
	caches      map[string]*kcmServerCache
	uuids       map[[16]byte]string
	defaultName string
	next        uint64
}

type kcmServerCache struct {
	name      string
	uuid      [16]byte
	principal *principal.Principal
	creds     [][]byte
	credUUIDs [][16]byte
	offset    int32
}

// NewKCMServer creates an in-memory KCM server at socket.
func NewKCMServer(socket string) *KCMServer {
	shared := &kcmNamespace{
		caches:      make(map[string]*kcmServerCache),
		uuids:       make(map[[16]byte]string),
		defaultName: "default",
	}
	return &KCMServer{
		Socket: socket, shared: shared,
		namespaces: make(map[uint32]*kcmNamespace),
		peerUID:    kcmPeerUID, conns: make(map[net.Conn]struct{}),
	}
}

// Serve listens and serves KCM requests until the listener fails.
func (s *KCMServer) Serve() error {
	if s == nil || s.Socket == "" {
		return errors.New("kcm: invalid server socket")
	}
	_ = os.Remove(s.Socket)
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
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
		s.mu.Lock()
		if s.conns == nil {
			s.conns = make(map[net.Conn]struct{})
		}
		uid := uint32(0)
		if s.IsolatePeers {
			lookup := s.peerUID
			if lookup == nil {
				lookup = kcmPeerUID
			}
			var uidErr error
			uid, uidErr = lookup(conn)
			if uidErr != nil {
				_ = conn.Close()
				s.mu.Unlock()
				continue
			}
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.serveConn(conn, uid)
	}
}

// Close stops a server started with Serve or ServeListener.
func (s *KCMServer) Close() error {
	s.mu.Lock()
	listener := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	var firstErr error
	if listener != nil {
		firstErr = listener.Close()
	}
	for _, conn := range conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *KCMServer) serveConn(conn net.Conn, uid uint32) {
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	for {
		request, err := readRequestFrame(conn)
		if err != nil {
			return
		}
		payload, code := s.dispatchPeer(request, uid)
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

func (s *KCMServer) namespace(uid uint32) *kcmNamespace {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shared == nil {
		s.shared = &kcmNamespace{
			caches:      make(map[string]*kcmServerCache),
			uuids:       make(map[[16]byte]string),
			defaultName: "default",
		}
	}
	if !s.IsolatePeers {
		return s.shared
	}
	if s.namespaces == nil {
		s.namespaces = make(map[uint32]*kcmNamespace)
	}
	ns := s.namespaces[uid]
	if ns == nil {
		ns = &kcmNamespace{
			caches:      make(map[string]*kcmServerCache),
			uuids:       make(map[[16]byte]string),
			defaultName: "default",
		}
		s.namespaces[uid] = ns
	}
	return ns
}

func (s *KCMServer) dispatchPeer(request []byte, uid uint32) ([]byte, int32) {
	if len(request) < 4 || request[0] != kcmMajor || request[1] != kcmMinor {
		return nil, kcmErrInternal
	}
	op := binary.BigEndian.Uint16(request[2:4])
	args := request[4:]
	ns := s.namespace(uid)
	switch op {
	case kcmOpGetDefaultCache:
		s.mu.Lock()
		name := ns.defaultName
		s.mu.Unlock()
		return cstring(name), 0
	case kcmOpGenNew:
		s.mu.Lock()
		ns.next++
		name := fmt.Sprintf("unique%d", ns.next)
		s.ensure(ns, name)
		s.mu.Unlock()
		return cstring(name), 0
	case kcmOpGetCacheUUIDList:
		s.mu.Lock()
		defer s.mu.Unlock()
		value := make([]byte, 0, len(ns.uuids)*kcmUUIDLen)
		for uuid := range ns.uuids {
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
		name, ok := ns.uuids[uuid]
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
	requiresExisting := op == kcmOpGetPrincipal || op == kcmOpGetCredList ||
		op == kcmOpGetCredUUIDList || op == kcmOpGetCredByUUID ||
		op == kcmOpRetrieve || op == kcmOpRemoveCred || op == kcmOpGetKDCOffset ||
		op == kcmOpDestroy || op == kcmOpSetDefaultCache || op == kcmOpSetKDCOffset ||
		op == kcmOpStore
	s.mu.Lock()
	cache := ns.caches[name]
	if cache == nil && !requiresExisting {
		cache = s.ensure(ns, name)
	}
	s.mu.Unlock()
	if cache == nil {
		return nil, kcmErrNoFile
	}
	switch op {
	case kcmOpInitialize:
		p, used, err := unmarshalPrincipalBytes(rest)
		if err != nil || used != len(rest) {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		cache.principal = &p
		cache.creds = nil
		cache.credUUIDs = nil
		cache.offset = 0
		s.mu.Unlock()
		return nil, 0
	case kcmOpDestroy:
		s.mu.Lock()
		delete(ns.caches, name)
		delete(ns.uuids, cache.uuid)
		if ns.defaultName == name {
			ns.defaultName = "default"
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
		if _, err := unmarshalCredentialBytes(rest); err != nil {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		cache.creds = append(cache.creds, append([]byte(nil), rest...))
		cache.credUUIDs = append(cache.credUUIDs, s.nextCredentialUUID(ns, cache.uuid))
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
		for _, uuid := range cache.credUUIDs {
			value = append(value, uuid[:]...)
		}
		return value, 0
	case kcmOpGetCredByUUID:
		if len(rest) != kcmUUIDLen {
			return nil, kcmErrInternal
		}
		s.mu.Lock()
		index := -1
		for i, uuid := range cache.credUUIDs {
			if bytes.Equal(uuid[:], rest) {
				index = i
				break
			}
		}
		if index < 0 || index >= len(cache.creds) {
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
		removed := false
		writeIndex := 0
		for i := 0; i < len(cache.creds); i++ {
			cred, err := unmarshalCredentialBytes(cache.creds[i])
			if err == nil && credentialMatches(cred, tag, flags) {
				removed = true
				continue
			}
			cache.creds[writeIndex] = cache.creds[i]
			cache.credUUIDs[writeIndex] = cache.credUUIDs[i]
			writeIndex++
		}
		if removed {
			cache.creds = cache.creds[:writeIndex]
			cache.credUUIDs = cache.credUUIDs[:writeIndex]
			return nil, 0
		}
		return nil, kcmErrNotFound
	case kcmOpSetDefaultCache:
		s.mu.Lock()
		ns.defaultName = name
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
		return s.replace(ns, cache, rest)
	default:
		return nil, kcmErrInternal
	}
}

func (s *KCMServer) ensure(ns *kcmNamespace, name string) *kcmServerCache {
	cache := ns.caches[name]
	if cache != nil {
		return cache
	}
	ns.next++
	var uuid [16]byte
	binary.BigEndian.PutUint64(uuid[8:], ns.next)
	cache = &kcmServerCache{name: name, uuid: uuid}
	ns.caches[name] = cache
	ns.uuids[uuid] = name
	return cache
}

func (s *KCMServer) replace(ns *kcmNamespace, cache *kcmServerCache, rest []byte) ([]byte, int32) {
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
		raw := append([]byte(nil), rest[:n]...)
		if _, err := unmarshalCredentialBytes(raw); err != nil {
			return nil, kcmErrInternal
		}
		creds = append(creds, raw)
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, kcmErrInternal
	}
	s.mu.Lock()
	credUUIDs := make([][16]byte, 0, len(creds))
	for range creds {
		credUUIDs = append(credUUIDs, s.nextCredentialUUID(ns, cache.uuid))
	}
	cache.principal = &p
	cache.offset = offset
	cache.creds = creds
	cache.credUUIDs = credUUIDs
	s.mu.Unlock()
	return nil, 0
}

func (s *KCMServer) nextCredentialUUID(ns *kcmNamespace, cache [16]byte) [16]byte {
	ns.next++
	var value [16]byte
	copy(value[:8], cache[:8])
	binary.BigEndian.PutUint64(value[8:], ns.next)
	return value
}

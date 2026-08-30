//go:build linux

package ccache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/Exonical/go-kerberos/krb5/principal"
	"golang.org/x/sys/unix"
)

const (
	keyctlList          = unix.KEYCTL_READ
	keyctlRead          = unix.KEYCTL_READ
	keyctlClear         = unix.KEYCTL_CLEAR
	keyctlGetPersistent = unix.KEYCTL_GET_PERSISTENT
)

type keyringHandle struct {
	name           string
	ring           int
	anchor         int
	collection     int
	anchorName     string
	collectionName string
	residual       string
}

const keyringDescriptionLimit = 4095

var keyringAddMu sync.Mutex

func resolveKeyring(residual string) (*Handle, error) {
	parts := strings.Split(residual, ":")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" ||
		parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
		return nil, fmt.Errorf("ccache: invalid KEYRING residual %q", residual)
	}
	anchorName := strings.ToLower(parts[0])
	if err := validateKeyringName("anchor", anchorName); err != nil {
		return nil, err
	}
	anchor, err := keyringAnchor(anchorName)
	if err != nil && anchorName != "persistent" {
		return nil, err
	}
	collectionName := parts[1]
	if err := validateKeyringName("collection", collectionName); err != nil {
		return nil, err
	}
	cacheName := ""
	if len(parts) == 3 {
		cacheName = parts[2]
		if err := validateKeyringName("subsidiary", cacheName); err != nil {
			return nil, err
		}
	}
	if anchorName == "persistent" {
		uid, parseErr := strconv.ParseInt(collectionName, 10, 32)
		if parseErr != nil || uid < 0 {
			return nil, fmt.Errorf("ccache: invalid KEYRING persistent UID %q", collectionName)
		}
		anchor, err = persistentKeyring(int(uid))
		if err != nil {
			return nil, fmt.Errorf("ccache: resolve KEYRING persistent anchor: %w", err)
		}
		collectionName = "_krb"
	} else {
		collectionName = "_krb_" + collectionName
	}
	collection, err := findOrCreateKeyring(anchor, collectionName)
	if err != nil {
		return nil, fmt.Errorf("ccache: resolve KEYRING collection: %w", err)
	}
	if cacheName == "" {
		cacheName, err = primaryName(collection, parts[1])
		if err != nil {
			return nil, fmt.Errorf("ccache: resolve KEYRING primary: %w", err)
		}
	}
	cache, err := findOrCreateKeyring(collection, cacheName)
	if err != nil {
		return nil, fmt.Errorf("ccache: resolve KEYRING cache: %w", err)
	}
	return &Handle{
		typ: TypeKeyring, name: "KEYRING:" + residual,
		keyring: &keyringHandle{
			name: cacheName, ring: cache, anchor: anchor, collection: collection,
			anchorName: anchorName, collectionName: parts[1], residual: residual,
		},
	}, nil
}

func primaryName(collection int, fallback string) (string, error) {
	id, err := unix.KeyctlSearch(collection, "user", "krb_ccache:primary", 0)
	if errors.Is(err, unix.ENOKEY) {
		payload := make([]byte, 8+len(fallback))
		binary.BigEndian.PutUint32(payload, 1)
		binary.BigEndian.PutUint32(payload[4:], uint32(len(fallback)))
		copy(payload[8:], fallback)
		if err := putKey(collection, "user", "krb_ccache:primary", payload); err != nil {
			return "", err
		}
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	payload, err := keyringRead(id)
	if err != nil {
		return "", err
	}
	if len(payload) < 8 || binary.BigEndian.Uint32(payload[:4]) != 1 {
		return "", errors.New("ccache: invalid KEYRING primary metadata")
	}
	length := binary.BigEndian.Uint32(payload[4:8])
	if uint64(length) > uint64(len(payload)-8) {
		return "", errors.New("ccache: truncated KEYRING primary metadata")
	}
	return string(payload[8 : 8+length]), nil
}

func keyringAnchor(kind string) (int, error) {
	switch strings.ToLower(kind) {
	case "session":
		return unix.KEY_SPEC_SESSION_KEYRING, nil
	case "user":
		return unix.KEY_SPEC_USER_KEYRING, nil
	case "process":
		return unix.KEY_SPEC_PROCESS_KEYRING, nil
	case "thread":
		return unix.KEY_SPEC_THREAD_KEYRING, nil
	default:
		return 0, fmt.Errorf("ccache: unsupported KEYRING anchor %q", kind)
	}
}

func persistentKeyring(uid int) (int, error) {
	id, err := unix.KeyctlInt(keyctlGetPersistent, uid, unix.KEY_SPEC_PROCESS_KEYRING, 0, 0)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func findOrCreateKeyring(parent int, description string) (int, error) {
	if err := validateKeyringName("keyring", description); err != nil {
		return 0, err
	}
	id, err := unix.KeyctlSearch(parent, "keyring", description, 0)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, unix.ENOKEY) {
		return 0, err
	}
	id, err = unix.AddKey("keyring", description, nil, parent)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return unix.KeyctlSearch(parent, "keyring", description, 0)
		}
		return 0, err
	}
	return id, nil
}

func putKey(ring int, kind, description string, payload []byte) error {
	if err := validateKeyringName("key", description); err != nil {
		return err
	}
	id, err := unix.KeyctlSearch(ring, kind, description, 0)
	if err == nil {
		_, err = unix.KeyctlBuffer(unix.KEYCTL_UPDATE, id, payload, 0)
		return err
	}
	if !errors.Is(err, unix.ENOKEY) {
		return err
	}
	_, err = unix.AddKey(kind, description, payload, ring)
	return err
}

func addKey(ring int, kind, description string, payload []byte) error {
	if err := validateKeyringName("key", description); err != nil {
		return err
	}
	_, err := unix.AddKey(kind, description, payload, ring)
	return err
}

func addCredentialKey(ring int, description string, payload []byte) error {
	if err := validateKeyringName("credential", description); err != nil {
		return err
	}
	// MIT prefers big_key because it permits duplicate descriptions; user is
	// the compatibility fallback on kernels without big_key support.
	keyringAddMu.Lock()
	defer keyringAddMu.Unlock()
	_, err := unix.AddKey("big_key", description, payload, ring)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("add big_key credential: %w", err)
	}
	if err := addKey(ring, "user", description, payload); err != nil {
		return fmt.Errorf("add user credential: %w", err)
	}
	return nil
}

func validateKeyringName(kind, name string) error {
	if strings.IndexByte(name, 0) >= 0 {
		return fmt.Errorf("ccache: KEYRING %s name contains NUL", kind)
	}
	if len(name) > keyringDescriptionLimit {
		return fmt.Errorf("ccache: KEYRING %s name exceeds %d bytes", kind, keyringDescriptionLimit)
	}
	return nil
}

func keyringRead(id int) ([]byte, error) {
	size, err := unix.KeyctlBuffer(keyctlRead, id, nil, 0)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	n, err := unix.KeyctlBuffer(keyctlRead, id, data, 0)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func keyringList(id int) ([]int, error) {
	size, err := unix.KeyctlBuffer(keyctlList, id, nil, 0)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	n, err := unix.KeyctlBuffer(keyctlList, id, data, 0)
	if err != nil {
		return nil, err
	}
	data = data[:n]
	if len(data)%4 != 0 {
		return nil, errors.New("ccache: malformed KEYRING key list")
	}
	result := make([]int, 0, len(data)/4)
	for len(data) > 0 {
		result = append(result, int(int32(binary.NativeEndian.Uint32(data))))
		data = data[4:]
	}
	return result, nil
}

func keyringDescription(id int) (string, error) {
	return unix.KeyctlString(unix.KEYCTL_DESCRIBE, id)
}

func parseKeyringDescription(description string) (string, string, bool) {
	fields := strings.SplitN(description, ";", 5)
	if len(fields) != 5 {
		return "", "", false
	}
	return fields[0], fields[4], true
}

func (h *keyringHandle) read() (*Cache, error) {
	if h == nil || h.ring == 0 {
		return nil, errors.New("ccache: invalid KEYRING handle")
	}
	ids, err := keyringList(h.ring)
	if err != nil {
		return nil, fmt.Errorf("ccache: list KEYRING cache: %w", err)
	}
	result := &Cache{}
	for _, id := range ids {
		description, err := keyringDescription(id)
		if err != nil {
			return nil, err
		}
		kind, name, ok := parseKeyringDescription(description)
		if !ok || (kind != "user" && kind != "big_key") {
			continue
		}
		payload, err := keyringRead(id)
		if err != nil {
			return nil, err
		}
		switch name {
		case "__krb5_princ__":
			result.DefaultPrincipal, _, err = unmarshalPrincipalBytes(payload)
			if err != nil {
				return nil, fmt.Errorf("ccache: decode KEYRING principal: %w", err)
			}
		default:
			credential, err := unmarshalCredentialBytes(payload)
			if err != nil {
				return nil, fmt.Errorf("ccache: decode KEYRING credential: %w", err)
			}
			result.Credentials = append(result.Credentials, credential)
		}
	}
	return result, nil
}

func (h *keyringHandle) write(cache *Cache) error {
	if h == nil || h.ring == 0 {
		return errors.New("ccache: invalid KEYRING handle")
	}
	if cache == nil {
		return errors.New("ccache: nil KEYRING cache")
	}
	principalBytes, err := marshalPrincipalBytes(cache.DefaultPrincipal)
	if err != nil {
		return err
	}
	type payload struct {
		description string
		value       []byte
	}
	credentials := make([]payload, 0, len(cache.Credentials))
	for _, credential := range cache.Credentials {
		value, err := marshalCredentialBytes(credential)
		if err != nil {
			return err
		}
		description := credential.Server.String()
		if err := validateKeyringName("credential", description); err != nil {
			return err
		}
		credentials = append(credentials, payload{description: description, value: value})
	}
	if _, err := unix.KeyctlInt(keyctlClear, h.ring, 0, 0, 0); err != nil {
		return fmt.Errorf("ccache: clear KEYRING cache: %w", err)
	}
	if err := putKey(h.ring, "user", "__krb5_princ__", principalBytes); err != nil {
		return fmt.Errorf("ccache: write KEYRING principal: %w", err)
	}
	for _, credential := range credentials {
		if err := addCredentialKey(h.ring, credential.description, credential.value); err != nil {
			return fmt.Errorf("ccache: write KEYRING credential: %w", err)
		}
	}
	return nil
}

func (h *keyringHandle) initialize(p principal.Principal) error {
	return h.write(&Cache{DefaultPrincipal: p})
}

func (h *keyringHandle) store(credential Credential) error {
	if h == nil || h.ring == 0 {
		return errors.New("ccache: invalid KEYRING handle")
	}
	payload, err := marshalCredentialBytes(credential)
	if err != nil {
		return err
	}
	description := credential.Server.String()
	if err := validateKeyringName("credential", description); err != nil {
		return err
	}
	if err := addCredentialKey(h.ring, description, payload); err != nil {
		return fmt.Errorf("ccache: store KEYRING credential: %w", err)
	}
	return nil
}

func (h *keyringHandle) remove(match Credential, flags uint32) error {
	if h == nil || h.ring == 0 {
		return errors.New("ccache: invalid KEYRING handle")
	}
	ids, err := keyringList(h.ring)
	if err != nil {
		return fmt.Errorf("ccache: list KEYRING cache: %w", err)
	}
	wireFlags := MapTCFlags(flags)
	found := false
	for _, id := range ids {
		description, err := keyringDescription(id)
		if err != nil {
			return err
		}
		kind, name, ok := parseKeyringDescription(description)
		if !ok || (kind != "user" && kind != "big_key") || name == "__krb5_princ__" {
			continue
		}
		payload, err := keyringRead(id)
		if err != nil {
			return err
		}
		credential, err := unmarshalCredentialBytes(payload)
		if err != nil {
			return fmt.Errorf("ccache: decode KEYRING credential: %w", err)
		}
		if !credentialMatches(credential, match, wireFlags) {
			continue
		}
		if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id, h.ring, 0, 0); err != nil {
			return fmt.Errorf("ccache: remove KEYRING credential: %w", err)
		}
		found = true
	}
	if !found {
		return errors.New("ccache: KEYRING credential not found")
	}
	return nil
}

func (h *keyringHandle) collectionHandles() ([]*Handle, error) {
	if h == nil || h.collection == 0 {
		return nil, errors.New("ccache: invalid KEYRING handle")
	}
	primary, err := primaryName(h.collection, h.collectionName)
	if err != nil {
		return nil, fmt.Errorf("ccache: resolve KEYRING primary: %w", err)
	}
	ids, err := keyringList(h.collection)
	if err != nil {
		return nil, fmt.Errorf("ccache: list KEYRING collection: %w", err)
	}
	childIDs := make(map[string]int)
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		description, err := keyringDescription(id)
		if err != nil {
			return nil, err
		}
		kind, name, ok := parseKeyringDescription(description)
		if ok && kind == "keyring" {
			if _, exists := childIDs[name]; !exists {
				names = append(names, name)
			}
			childIDs[name] = id
		}
	}
	result := make([]*Handle, 0, len(childIDs))
	appendName := func(name string) {
		id, ok := childIDs[name]
		if !ok {
			return
		}
		delete(childIDs, name)
		result = append(result, &Handle{
			typ:  TypeKeyring,
			name: "KEYRING:" + h.anchorName + ":" + h.collectionName + ":" + name,
			keyring: &keyringHandle{
				name: name, ring: id, anchor: h.anchor, collection: h.collection,
				anchorName: h.anchorName, collectionName: h.collectionName,
				residual: h.anchorName + ":" + h.collectionName + ":" + name,
			},
		})
	}
	appendName(primary)
	for _, name := range names {
		appendName(name)
	}
	return result, nil
}

func (h *keyringHandle) destroy() error {
	if h == nil || h.ring == 0 {
		return errors.New("ccache: invalid KEYRING handle")
	}
	if _, err := unix.KeyctlInt(keyctlClear, h.ring, 0, 0, 0); err != nil {
		return err
	}
	if h.collection != 0 {
		if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, h.ring, h.collection, 0, 0); err != nil {
			return err
		}
	}
	h.ring = 0
	h.collection = 0
	h.anchor = 0
	return nil
}

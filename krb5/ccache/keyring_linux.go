//go:build linux

package ccache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

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
	name   string
	ring   int
	anchor int
}

func resolveKeyring(residual string) (*Handle, error) {
	parts := strings.SplitN(residual, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("ccache: invalid KEYRING residual %q", residual)
	}
	anchorName := strings.ToLower(parts[0])
	anchor, err := keyringAnchor(anchorName)
	if err != nil && anchorName != "persistent" {
		return nil, err
	}
	collectionName := parts[1]
	cacheName := parts[1]
	if anchorName == "persistent" {
		uid, parseErr := strconv.ParseInt(parts[1], 10, 32)
		if parseErr != nil || uid < 0 {
			return nil, fmt.Errorf("ccache: invalid KEYRING persistent UID %q", parts[1])
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
	cache, err := findOrCreateKeyring(collection, cacheName)
	if err != nil {
		return nil, fmt.Errorf("ccache: resolve KEYRING cache: %w", err)
	}
	// MIT stores the primary subsidiary name in the collection keyring.
	primary := make([]byte, 8+len(cacheName))
	binary.BigEndian.PutUint32(primary, 1)
	binary.BigEndian.PutUint32(primary[4:], uint32(len(cacheName)))
	copy(primary[8:], cacheName)
	if err := putKey(collection, "user", "krb_ccache:primary", primary); err != nil {
		return nil, fmt.Errorf("ccache: initialize KEYRING primary: %w", err)
	}
	return &Handle{
		typ: TypeKeyring, name: "KEYRING:" + residual,
		keyring: &keyringHandle{name: cacheName, ring: cache, anchor: anchor},
	}, nil
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
		fields := strings.SplitN(description, ";", 5)
		if len(fields) != 5 {
			continue
		}
		payload, err := keyringRead(id)
		if err != nil {
			return nil, err
		}
		switch fields[4] {
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
	if _, err := unix.KeyctlInt(keyctlClear, h.ring, 0, 0, 0); err != nil {
		return fmt.Errorf("ccache: clear KEYRING cache: %w", err)
	}
	principalBytes, err := marshalPrincipalBytes(cache.DefaultPrincipal)
	if err != nil {
		return err
	}
	if err := putKey(h.ring, "user", "__krb5_princ__", principalBytes); err != nil {
		return fmt.Errorf("ccache: write KEYRING principal: %w", err)
	}
	for _, credential := range cache.Credentials {
		payload, err := marshalCredentialBytes(credential)
		if err != nil {
			return err
		}
		description := credential.Server.String()
		if err := putKey(h.ring, "user", description, payload); err != nil {
			return fmt.Errorf("ccache: write KEYRING credential: %w", err)
		}
	}
	return nil
}

func (h *keyringHandle) initialize(p principal.Principal) error {
	return h.write(&Cache{DefaultPrincipal: p})
}

func (h *keyringHandle) store(credential Credential) error {
	cache, err := h.read()
	if err != nil && !errors.Is(err, unix.ENOKEY) {
		return err
	}
	if cache == nil {
		cache = &Cache{}
	}
	cache.Credentials = append(cache.Credentials, credential)
	return h.write(cache)
}

func (h *keyringHandle) destroy() error {
	if h == nil || h.ring == 0 {
		return errors.New("ccache: invalid KEYRING handle")
	}
	_, err := unix.KeyctlInt(keyctlClear, h.ring, 0, 0, 0)
	return err
}

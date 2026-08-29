package ccache

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Type identifies a credential cache backend.
type Type string

const (
	TypeFile   Type = "FILE"
	TypeDir    Type = "DIR"
	TypeMemory Type = "MEMORY"
	TypeKCM    Type = "KCM"
)

// Handle is a resolved credential cache. DIR handles refer to either a
// collection (DIR:/path) or one of its subsidiary FILE caches (DIR::/path).
type Handle struct {
	typ    Type
	name   string
	path   string
	dir    string
	memory *memoryCache
	kcm    *kcmHandle
}

type memoryCache struct {
	mu    sync.RWMutex
	cache *Cache
}

var (
	memoryMu       sync.Mutex
	memoryCaches   = make(map[string]*memoryCache)
	memorySequence uint64
)

// Resolve resolves a FILE, DIR, or MEMORY credential cache name. A name
// without a type prefix is a FILE cache name, matching MIT's default FILE
// resolver behavior.
func Resolve(name string) (*Handle, error) {
	if name == "" {
		return nil, errors.New("ccache: empty cache name")
	}
	if !strings.Contains(name, ":") {
		return resolveFile(name)
	}
	switch {
	case strings.HasPrefix(name, "FILE:"):
		return resolveFile(strings.TrimPrefix(name, "FILE:"))
	case strings.HasPrefix(name, "DIR::"):
		return resolveDirSubsidiary(strings.TrimPrefix(name, "DIR::"))
	case strings.HasPrefix(name, "DIR:"):
		return resolveDirCollection(strings.TrimPrefix(name, "DIR:"))
	case strings.HasPrefix(name, "MEMORY:"):
		return resolveMemory(strings.TrimPrefix(name, "MEMORY:"))
	case strings.HasPrefix(name, "KCM:"):
		return resolveKCM(strings.TrimPrefix(name, "KCM:"))
	default:
		return nil, fmt.Errorf("ccache: unsupported cache type in %q", name)
	}
}

func resolveFile(path string) (*Handle, error) {
	if path == "" {
		return nil, errors.New("ccache: empty FILE cache path")
	}
	return &Handle{typ: TypeFile, name: "FILE:" + path, path: path}, nil
}

func resolveDirCollection(dir string) (*Handle, error) {
	if dir == "" {
		return nil, errors.New("ccache: empty DIR cache directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("ccache: create DIR directory: %w", err)
	}
	primary, err := dirPrimaryPath(dir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(primary); errors.Is(err, os.ErrNotExist) {
		if err := writePrimary(dir, "tkt"); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("ccache: stat DIR primary: %w", err)
	}
	name, err := readPrimaryName(dir)
	if err != nil {
		return nil, err
	}
	return &Handle{
		typ: TypeDir, name: "DIR:" + dir, path: filepath.Join(dir, name),
		dir: dir,
	}, nil
}

func resolveDirSubsidiary(path string) (*Handle, error) {
	if path == "" {
		return nil, errors.New("ccache: empty DIR subsidiary path")
	}
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "." || !strings.HasPrefix(base, "tkt") ||
		strings.Contains(base, string(filepath.Separator)) {
		return nil, fmt.Errorf("ccache: invalid DIR subsidiary %q", path)
	}
	dir := filepath.Dir(clean)
	if dir == "." {
		return nil, errors.New("ccache: DIR subsidiary has no parent directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("ccache: create DIR directory: %w", err)
	}
	return &Handle{typ: TypeDir, name: "DIR::" + clean, path: clean, dir: dir}, nil
}

func resolveMemory(residual string) (*Handle, error) {
	memoryMu.Lock()
	defer memoryMu.Unlock()
	if residual == "" {
		var suffix [12]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return nil, fmt.Errorf("ccache: generate MEMORY name: %w", err)
		}
		residual = fmt.Sprintf("%x", suffix)
		for {
			if _, exists := memoryCaches[residual]; !exists {
				break
			}
			memorySequence++
			residual = fmt.Sprintf("%x-%d", suffix, memorySequence)
		}
	}
	cache := memoryCaches[residual]
	if cache == nil {
		cache = &memoryCache{}
		memoryCaches[residual] = cache
	}
	return &Handle{typ: TypeMemory, name: "MEMORY:" + residual, memory: cache}, nil
}

// Name returns the canonical resolved cache name.
func (h *Handle) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

// Type returns the cache backend type.
func (h *Handle) Type() Type {
	if h == nil {
		return ""
	}
	return h.typ
}

// Read loads the cache contents. MEMORY reads return a snapshot.
func (h *Handle) Read() (*Cache, error) {
	if h == nil {
		return nil, errors.New("ccache: nil handle")
	}
	if h.typ == TypeMemory {
		h.memory.mu.RLock()
		defer h.memory.mu.RUnlock()
		if h.memory.cache == nil {
			return nil, os.ErrNotExist
		}
		return cloneCache(h.memory.cache), nil
	}
	if h.typ == TypeKCM {
		return h.kcm.read()
	}
	file, err := os.Open(h.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return Read(file)
}

// Write replaces the cache contents. MEMORY writes publish an isolated
// snapshot; file-backed caches use mode 0600.
func (h *Handle) Write(cache *Cache) error {
	if h == nil {
		return errors.New("ccache: nil handle")
	}
	if cache == nil {
		return errors.New("ccache: nil cache")
	}
	if h.typ == TypeMemory {
		h.memory.mu.Lock()
		h.memory.cache = cloneCache(cache)
		h.memory.mu.Unlock()
		return nil
	}
	if h.typ == TypeKCM {
		return h.kcm.write(cache)
	}
	file, err := os.OpenFile(h.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := Write(file, cache); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// Primary resolves the current primary subsidiary of a DIR collection.
func (h *Handle) Primary() (*Handle, error) {
	if h != nil && h.typ == TypeKCM {
		return ResolveKCM("", h.kcm.socket)
	}
	if h == nil || h.typ != TypeDir {
		return nil, errors.New("ccache: primary is only available for DIR caches")
	}
	name, err := readPrimaryName(h.dir)
	if err != nil {
		return nil, err
	}
	return &Handle{
		typ: TypeDir, name: "DIR::" + filepath.Join(h.dir, name),
		path: filepath.Join(h.dir, name), dir: h.dir,
	}, nil
}

// SetPrimary makes a DIR subsidiary the collection's primary cache.
func (h *Handle) SetPrimary() error {
	if h != nil && h.typ == TypeKCM {
		return h.SetDefault()
	}
	if h == nil || h.typ != TypeDir || h.dir == "" {
		return errors.New("ccache: primary is only available for DIR caches")
	}
	if !strings.HasPrefix(filepath.Base(h.path), "tkt") {
		return errors.New("ccache: invalid DIR subsidiary")
	}
	return writePrimary(h.dir, filepath.Base(h.path))
}

// New creates a unique tktXXXXXX subsidiary in a DIR collection.
func (h *Handle) New() (*Handle, error) {
	if h != nil && h.typ == TypeKCM {
		return h.kcm.newCache()
	}
	if h == nil || h.typ != TypeDir || h.dir == "" {
		return nil, errors.New("ccache: new cache requires a DIR collection")
	}
	file, err := os.CreateTemp(h.dir, "tkt")
	if err != nil {
		return nil, fmt.Errorf("ccache: create DIR subsidiary: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return &Handle{
		typ: TypeDir, name: "DIR::" + path, path: path, dir: h.dir,
	}, nil
}

// Collection lists all tkt* subsidiary caches, with the primary first.
func (h *Handle) Collection() ([]*Handle, error) {
	if h == nil {
		return nil, errors.New("ccache: nil handle")
	}
	if h.typ == TypeMemory {
		memoryMu.Lock()
		names := make([]string, 0, len(memoryCaches))
		for name := range memoryCaches {
			names = append(names, name)
		}
		memoryMu.Unlock()
		result := make([]*Handle, 0, len(names))
		for _, name := range names {
			cache, err := Resolve("MEMORY:" + name)
			if err != nil {
				return nil, err
			}
			result = append(result, cache)
		}
		return result, nil
	}
	if h.typ == TypeKCM {
		return h.kcm.collection()
	}
	if h.typ != TypeDir {
		return []*Handle{h}, nil
	}
	primary, err := h.Primary()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return nil, err
	}
	result := make([]*Handle, 0, len(entries))
	if _, err := os.Stat(primary.path); err == nil {
		result = append(result, primary)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), "tkt") ||
			entry.Name() == filepath.Base(primary.path) {
			continue
		}
		result = append(result, &Handle{
			typ: TypeDir, name: "DIR::" + filepath.Join(h.dir, entry.Name()),
			path: filepath.Join(h.dir, entry.Name()), dir: h.dir,
		})
	}
	return result, nil
}

// ReadName resolves and reads a named cache.
func ReadName(name string) (*Cache, error) {
	cache, err := Resolve(name)
	if err != nil {
		return nil, err
	}
	return cache.Read()
}

// WriteName resolves and writes a named cache.
func WriteName(name string, cache *Cache) error {
	resolved, err := Resolve(name)
	if err != nil {
		return err
	}
	return resolved.Write(cache)
}

// Collection resolves a cache name and lists its collection.
func Collection(name string) ([]*Handle, error) {
	resolved, err := Resolve(name)
	if err != nil {
		return nil, err
	}
	return resolved.Collection()
}

func dirPrimaryPath(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("ccache: empty DIR directory")
	}
	return filepath.Join(dir, "primary"), nil
}

func readPrimaryName(dir string) (string, error) {
	path, err := dirPrimaryPath(dir)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("ccache: read DIR primary: %w", err)
	}
	line := strings.TrimSuffix(string(data), "\n")
	if strings.Contains(line, "\n") || strings.ContainsAny(line, `/\`) ||
		!strings.HasPrefix(line, "tkt") || line == "tkt" && len(data) == 0 {
		return "", fmt.Errorf("ccache: invalid DIR primary file")
	}
	return line, nil
}

func writePrimary(dir, name string) error {
	if !strings.HasPrefix(name, "tkt") || strings.ContainsAny(name, `/\`) {
		return errors.New("ccache: invalid DIR primary name")
	}
	path, err := dirPrimaryPath(dir)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "primary.")
	if err != nil {
		return fmt.Errorf("ccache: create DIR primary: %w", err)
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := io.WriteString(file, name+"\n"); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("ccache: replace DIR primary: %w", err)
	}
	return nil
}

func cloneCache(cache *Cache) *Cache {
	if cache == nil {
		return nil
	}
	result := *cache
	result.DefaultPrincipal.Components = append([]string(nil), cache.DefaultPrincipal.Components...)
	result.Credentials = make([]Credential, len(cache.Credentials))
	for i, credential := range cache.Credentials {
		result.Credentials[i] = credential
		result.Credentials[i].Client.Components = append([]string(nil), credential.Client.Components...)
		result.Credentials[i].Server.Components = append([]string(nil), credential.Server.Components...)
		result.Credentials[i].Key = append([]byte(nil), credential.Key...)
		result.Credentials[i].Ticket = append([]byte(nil), credential.Ticket...)
		result.Credentials[i].SecondTicket = append([]byte(nil), credential.SecondTicket...)
		result.Credentials[i].Addresses = append([]Address(nil), credential.Addresses...)
		for j := range result.Credentials[i].Addresses {
			result.Credentials[i].Addresses[j].Data = append([]byte(nil), credential.Addresses[j].Data...)
		}
		result.Credentials[i].AuthData = append([]AuthData(nil), credential.AuthData...)
		for j := range result.Credentials[i].AuthData {
			result.Credentials[i].AuthData[j].Data = append([]byte(nil), credential.AuthData[j].Data...)
		}
	}
	return &result
}

// Package rcache implements Kerberos replay caches.
package rcache

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

const (
	hashSeedLen       = 16
	tagLen            = 12
	recordLen         = tagLen + 4
	firstTableRecords = 1023
	maxFileSize       = int64(1<<31 - 1)
)

var (
	// ErrReplay indicates that an authenticator tag was already stored.
	ErrReplay = krberrors.ErrReplay
	// ErrOverflow indicates that a replay-cache file cannot grow further.
	ErrOverflow = errors.New("replay cache file size overflow")
)

// Cache stores authenticator tags and reports replays.
type Cache interface {
	Store(tag []byte, now time.Time, skew time.Duration) error
}

// File2 is an MIT file2-format replay cache.
type File2 struct {
	Path   string
	secure bool
}

var _ Cache = (*File2)(nil)

// Resolve resolves a replay-cache name such as file2:/path, none:, or dfl:.
func Resolve(name string) (Cache, error) {
	kind, residual, ok := strings.Cut(name, ":")
	if !ok {
		return nil, fmt.Errorf("replay cache: invalid name %q", name)
	}
	switch strings.ToLower(kind) {
	case "file2":
		if residual == "" {
			return nil, errors.New("replay cache: file2 name has empty path")
		}
		return &File2{Path: residual}, nil
	case "none":
		return noneCache{}, nil
	case "dfl":
		return &File2{Path: defaultPath(), secure: true}, nil
	default:
		return nil, fmt.Errorf("replay cache: unsupported type %q", kind)
	}
}

// TagFromCiphertext returns the replay tag used by MIT's file2 cache. MIT
// takes the trailing checksum trailer from the encrypted authenticator, then
// file2 keeps the first 12 bytes of that value.
func TagFromCiphertext(ciphertext []byte, trailerLen int) []byte {
	if trailerLen < 0 {
		trailerLen = 0
	}
	if trailerLen > len(ciphertext) {
		trailerLen = len(ciphertext)
	}
	ciphertext = ciphertext[len(ciphertext)-trailerLen:]
	if len(ciphertext) > tagLen {
		ciphertext = ciphertext[:tagLen]
	}
	return append([]byte(nil), ciphertext...)
}

// Default resolves the MIT-style default replay cache name.
func Default(cfg *config.Config) (Cache, error) {
	if value, ok := os.LookupEnv("KRB5RCACHENAME"); ok {
		return Resolve(value)
	}
	if kind, ok := os.LookupEnv("KRB5RCACHETYPE"); ok {
		return Resolve(kind + ":")
	}
	if cfg != nil && cfg.DefaultRCacheName != "" {
		return Resolve(cfg.DefaultRCacheName)
	}
	return Resolve("dfl:")
}

// Store records a tag using the supplied timestamp and clock skew.
func (c *File2) Store(tag []byte, now time.Time, skew time.Duration) error {
	if c == nil || c.Path == "" {
		return errors.New("replay cache: empty file2 path")
	}
	file, err := openReplayFile(c.Path, c.secure)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := lockFile(file); err != nil {
		return err
	}
	defer unlockFile(file)

	var seed [hashSeedLen]byte
	n, err := file.ReadAt(seed[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n < len(seed) {
		if _, err := rand.Read(seed[:]); err != nil {
			return err
		}
		if _, err := file.WriteAt(seed[:], 0); err != nil {
			return err
		}
	}
	var normalized [tagLen]byte
	copy(normalized[:], tag)
	nowSeconds := uint32(now.Unix())
	skewSeconds := uint32(0)
	if skew > 0 {
		skewSeconds = uint32(skew / time.Second)
	}
	return store(file, seed, normalized, nowSeconds, skewSeconds)
}

func store(file *os.File, seed [hashSeedLen]byte, tag [tagLen]byte, now, skew uint32) error {
	var tableOffset int64 = -1
	var nrecords int64
	var available int64 = -1
	for {
		var err error
		tableOffset, nrecords, err = nextTable(tableOffset, nrecords)
		if err != nil {
			return err
		}
		index := int64(sipHash24(tag[:], seed[:]) % uint64(nrecords))
		recordOffset := tableOffset + index*recordLen
		records, err := readRecords(file, recordOffset)
		if err != nil {
			return err
		}
		for i, record := range records {
			if record.timestamp != 0 && record.tag == tag {
				return ErrReplay
			}
			if available == -1 && (record.timestamp == 0 || expired(record.timestamp, now, skew)) {
				available = recordOffset + int64(i*recordLen)
			}
		}
		if available == -1 && len(records) == 0 {
			available = recordOffset
		}
		if available == -1 && len(records) == 1 {
			available = recordOffset + recordLen
		}
		if len(records) < 2 || records[0].timestamp == 0 ||
			(len(records) == 2 && records[1].timestamp == 0) {
			if available == -1 {
				return ErrOverflow
			}
			return writeRecord(file, available, tag, now)
		}
		seed[0]++
	}
}

type record struct {
	tag       [tagLen]byte
	timestamp uint32
}

func readRecords(file *os.File, offset int64) ([]record, error) {
	var buf [recordLen * 2]byte
	n, err := file.ReadAt(buf[:], offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	count := n / recordLen
	records := make([]record, count)
	for i := range records {
		copy(records[i].tag[:], buf[i*recordLen:])
		records[i].timestamp = binary.BigEndian.Uint32(buf[i*recordLen+tagLen:])
	}
	return records, nil
}

func writeRecord(file *os.File, offset int64, tag [tagLen]byte, timestamp uint32) error {
	var buf [recordLen]byte
	copy(buf[:tagLen], tag[:])
	binary.BigEndian.PutUint32(buf[tagLen:], timestamp)
	n, err := file.WriteAt(buf[:], offset)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

func nextTable(offset, nrecords int64) (int64, int64, error) {
	switch offset {
	case -1:
		offset, nrecords = hashSeedLen, firstTableRecords
	case hashSeedLen:
		offset += nrecords * recordLen
		nrecords = (firstTableRecords + 1) * 2
	default:
		offset += nrecords * recordLen
		nrecords *= 2
	}
	if nrecords > maxFileSize/recordLen || offset > maxFileSize-nrecords*recordLen {
		return 0, 0, ErrOverflow
	}
	return offset, nrecords, nil
}

func expired(timestamp, now, skew uint32) bool {
	return tsAfter(now, timestamp+skew)
}

func tsAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

type noneCache struct{}

func (noneCache) Store([]byte, time.Time, time.Duration) error { return nil }

func defaultPath() string {
	dir := os.Getenv("KRB5RCACHEDIR")
	if dir == "" {
		for _, candidate := range []string{"/var/tmp", "/usr/tmp", "/var/usr/tmp", "/tmp"} {
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				dir = candidate
				break
			}
		}
		if dir == "" {
			dir = os.TempDir()
		}
	}
	return filepath.Join(dir, "krb5_"+strconv.FormatInt(int64(os.Geteuid()), 10)+".rcache2")
}

func sipHash24(data, seed []byte) uint64 {
	length := len(data)
	k0 := binary.LittleEndian.Uint64(seed)
	k1 := binary.LittleEndian.Uint64(seed[8:])
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = bitsRotate(v1, 13)
		v1 ^= v0
		v0 = bitsRotate(v0, 32)
		v2 += v3
		v3 = bitsRotate(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bitsRotate(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bitsRotate(v1, 17)
		v1 ^= v2
		v2 = bitsRotate(v2, 32)
	}
	for len(data) >= 8 {
		m := binary.LittleEndian.Uint64(data)
		v3 ^= m
		round()
		round()
		v0 ^= m
		data = data[8:]
	}
	var last [8]byte
	copy(last[:], data)
	last[7] = byte(length)
	m := binary.LittleEndian.Uint64(last[:])
	v3 ^= m
	round()
	round()
	v0 ^= m
	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		round()
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func bitsRotate(value uint64, count int) uint64 {
	return value<<count | value>>(64-count)
}

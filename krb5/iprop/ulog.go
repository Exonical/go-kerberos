package iprop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
)

const (
	ulogVersion     uint16 = 1
	ulogStable      uint16 = 1
	ulogUnstable    uint16 = 2
	ulogCorrupt     uint16 = 3
	ulogEntryMagic  uint32 = 0x06662323
	ulogHeaderMagic uint32 = 0x06661212
	ulogBlock       uint16 = 2048
	ulogEntries     uint32 = 1000
	ulogHeaderSize         = 40
	ulogEntrySize          = 24
)

// UlogHeader is the little-endian representation of MIT kdb_hlog_t.
type UlogHeader struct {
	Version    uint16
	NumEntries uint32
	FirstTime  Time
	LastTime   Time
	FirstSno   uint32
	LastSno    uint32
	State      uint16
	Block      uint16
}

// UlogEntry is one decoded update-log entry.
type UlogEntry struct {
	Serial uint32
	Time   Time
	Commit bool
	Update Update
	Dummy  bool
}

// Ulog stores an MIT-compatible fixed-block update log. MIT uses native
// endian mmap storage; this implementation uses little endian on supported
// platforms.
type Ulog struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	hdr      UlogHeader
	capacity uint32
}

func Create(path string, entries ...uint32) (*Ulog, error) {
	num := ulogEntries
	if len(entries) > 0 && entries[0] != 0 {
		num = entries[0]
	}
	if num == 0 || num > 1<<20 {
		return nil, errors.New("iprop: invalid ulog entry count")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	u := &Ulog{file: file, path: path, capacity: num, hdr: UlogHeader{
		Version: ulogVersion, NumEntries: 1, FirstSno: 1, LastSno: 1,
		State: ulogStable, Block: ulogBlock,
	}}
	if err := u.syncHeader(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Truncate(int64(ulogHeaderSize) + int64(num)*int64(ulogBlock)); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := u.writeDummy(1); err != nil {
		_ = file.Close()
		return nil, err
	}
	return u, nil
}

func Open(path string) (*Ulog, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	u := &Ulog{file: file, path: path}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := u.readHeader(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Size() < ulogHeaderSize || (info.Size()-ulogHeaderSize)%int64(u.hdr.Block) != 0 {
		_ = file.Close()
		return nil, errors.New("iprop: invalid ulog file size")
	}
	u.capacity = uint32((info.Size() - ulogHeaderSize) / int64(u.hdr.Block))
	if u.capacity == 0 {
		_ = file.Close()
		return nil, errors.New("iprop: invalid ulog capacity")
	}
	return u, nil
}

func (u *Ulog) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file == nil {
		return nil
	}
	err := u.file.Close()
	u.file = nil
	return err
}

func (u *Ulog) Header() UlogHeader {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hdr
}

func (u *Ulog) AddUpdate(update Update) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file == nil {
		return errors.New("iprop: closed ulog")
	}
	serial := update.EntrySno
	if serial == 0 {
		serial = u.hdr.LastSno + 1
		update.EntrySno = serial
	}
	payload := update.MarshalXDR()
	if len(payload) > int(u.hdr.Block)-ulogEntrySize {
		return fmt.Errorf("iprop: update exceeds ulog block size")
	}
	slot := (serial - 1) % u.capacity
	offset := int64(ulogHeaderSize) + int64(slot)*int64(u.hdr.Block)
	block := make([]byte, u.hdr.Block)
	binary.LittleEndian.PutUint32(block[0:4], ulogEntryMagic)
	binary.LittleEndian.PutUint32(block[4:8], serial)
	putTime(block[8:16], update.Time)
	if update.Commit {
		binary.LittleEndian.PutUint32(block[16:20], 1)
	}
	binary.LittleEndian.PutUint32(block[20:24], uint32(len(payload)))
	copy(block[24:], payload)
	if _, err := u.file.WriteAt(block, offset); err != nil {
		return err
	}
	if u.hdr.LastSno == 0 || serial >= u.hdr.LastSno {
		if u.hdr.FirstSno == 0 {
			u.hdr.FirstSno = serial
			u.hdr.FirstTime = update.Time
		} else if serial-u.hdr.FirstSno >= u.capacity {
			u.hdr.FirstSno = serial - u.capacity + 1
			first, err := u.readEntry(u.hdr.FirstSno)
			if err != nil {
				return err
			}
			u.hdr.FirstTime = first.Time
		}
		u.hdr.LastSno = serial
		u.hdr.LastTime = update.Time
		if !(serial == u.hdr.LastSno && u.hdr.NumEntries == 1) && u.hdr.NumEntries < u.capacity {
			u.hdr.NumEntries++
		}
	}
	return u.syncHeader()
}

func (u *Ulog) GetEntries(after uint32) ([]UlogEntry, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file == nil {
		return nil, errors.New("iprop: closed ulog")
	}
	if u.hdr.LastSno == 0 {
		return nil, nil
	}
	first := u.hdr.FirstSno
	if after >= first {
		first = after + 1
	}
	var out []UlogEntry
	for serial := first; serial <= u.hdr.LastSno; serial++ {
		entry, err := u.readEntry(serial)
		if err != nil {
			return nil, err
		}
		if !entry.Dummy {
			out = append(out, entry)
		}
	}
	return out, nil
}

func (u *Ulog) Last() (Last, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file == nil {
		return Last{}, errors.New("iprop: closed ulog")
	}
	return Last{LastSno: u.hdr.LastSno, LastTime: u.hdr.LastTime}, nil
}

func (u *Ulog) Reset() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.file == nil {
		return errors.New("iprop: closed ulog")
	}
	u.hdr = UlogHeader{
		Version: ulogVersion, NumEntries: 1, FirstSno: 1, LastSno: 1,
		State: ulogStable, Block: ulogBlock,
	}
	if err := u.file.Truncate(int64(ulogHeaderSize) + int64(u.capacity)*int64(u.hdr.Block)); err != nil {
		return err
	}
	if err := u.writeDummy(1); err != nil {
		return err
	}
	return u.syncHeader()
}

func (u *Ulog) writeDummy(serial uint32) error {
	block := make([]byte, u.hdr.Block)
	binary.LittleEndian.PutUint32(block[0:4], ulogEntryMagic)
	binary.LittleEndian.PutUint32(block[4:8], serial)
	offset := int64(ulogHeaderSize) + int64((serial-1)%u.capacity)*int64(u.hdr.Block)
	_, err := u.file.WriteAt(block, offset)
	return err
}

func (u *Ulog) readEntry(serial uint32) (UlogEntry, error) {
	block := make([]byte, u.hdr.Block)
	slot := (serial - 1) % u.capacity
	offset := int64(ulogHeaderSize) + int64(slot)*int64(u.hdr.Block)
	if _, err := u.file.ReadAt(block, offset); err != nil {
		return UlogEntry{}, err
	}
	if binary.LittleEndian.Uint32(block[:4]) != ulogEntryMagic {
		return UlogEntry{Dummy: true}, nil
	}
	if binary.LittleEndian.Uint32(block[4:8]) != serial {
		return UlogEntry{Dummy: true}, nil
	}
	size := binary.LittleEndian.Uint32(block[20:24])
	if size > uint32(len(block)-ulogEntrySize) {
		return UlogEntry{}, errors.New("iprop: invalid ulog entry size")
	}
	if size == 0 {
		return UlogEntry{Serial: serial, Time: getTime(block[8:16]), Dummy: true}, nil
	}
	update, err := UnmarshalUpdate(block[24 : 24+size])
	if err != nil {
		return UlogEntry{}, err
	}
	return UlogEntry{Serial: serial, Time: update.Time, Commit: binary.LittleEndian.Uint32(block[16:20]) != 0, Update: update}, nil
}

func (u *Ulog) readHeader() error {
	data := make([]byte, ulogHeaderSize)
	if _, err := u.file.ReadAt(data, 0); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(data[0:4]) != ulogHeaderMagic {
		return errors.New("iprop: invalid ulog header magic")
	}
	u.hdr.Version = binary.LittleEndian.Uint16(data[4:6])
	u.hdr.NumEntries = binary.LittleEndian.Uint32(data[8:12])
	u.hdr.FirstTime = getTime(data[12:20])
	u.hdr.LastTime = getTime(data[20:28])
	u.hdr.FirstSno = binary.LittleEndian.Uint32(data[28:32])
	u.hdr.LastSno = binary.LittleEndian.Uint32(data[32:36])
	u.hdr.State = binary.LittleEndian.Uint16(data[36:38])
	u.hdr.Block = binary.LittleEndian.Uint16(data[38:40])
	if u.hdr.Version != ulogVersion || u.hdr.NumEntries == 0 || u.hdr.Block < ulogEntrySize {
		return errors.New("iprop: invalid ulog header")
	}
	return nil
}

func (u *Ulog) syncHeader() error {
	data := make([]byte, ulogHeaderSize)
	binary.LittleEndian.PutUint32(data[0:4], ulogHeaderMagic)
	binary.LittleEndian.PutUint16(data[4:6], u.hdr.Version)
	binary.LittleEndian.PutUint32(data[8:12], u.hdr.NumEntries)
	putTime(data[12:20], u.hdr.FirstTime)
	putTime(data[20:28], u.hdr.LastTime)
	binary.LittleEndian.PutUint32(data[28:32], u.hdr.FirstSno)
	binary.LittleEndian.PutUint32(data[32:36], u.hdr.LastSno)
	binary.LittleEndian.PutUint16(data[36:38], u.hdr.State)
	binary.LittleEndian.PutUint16(data[38:40], u.hdr.Block)
	_, err := u.file.WriteAt(data, 0)
	return err
}

func putTime(dst []byte, value Time) {
	binary.LittleEndian.PutUint32(dst[0:4], value.Seconds)
	binary.LittleEndian.PutUint32(dst[4:8], value.Useconds)
}

func getTime(src []byte) Time {
	return Time{Seconds: binary.LittleEndian.Uint32(src[0:4]), Useconds: binary.LittleEndian.Uint32(src[4:8])}
}

// Package binfmt provides bounded big-endian binary cursors used by the
// Kerberos file formats.
package binfmt

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Reader reads bounded big-endian fields from a byte slice.
type Reader struct {
	data []byte
	off  int
}

// NewReader returns a reader positioned at the start of data.
func NewReader(data []byte) *Reader {
	return &Reader{data: data}
}

// NewReaderAt returns a reader positioned at offset in data.
func NewReaderAt(data []byte, offset int) *Reader {
	return &Reader{data: data, off: offset}
}

// Remaining reports the number of unread bytes.
func (r *Reader) Remaining() int {
	return len(r.data) - r.off
}

// Offset reports the current byte offset.
func (r *Reader) Offset() int {
	return r.off
}

// Bytes reads exactly n bytes.
func (r *Reader) Bytes(n int) ([]byte, error) {
	if n < 0 || n > r.Remaining() {
		return nil, fmt.Errorf("truncated field")
	}
	value := r.data[r.off : r.off+n]
	r.off += n
	return value, nil
}

// U8 reads an unsigned eight-bit integer.
func (r *Reader) U8() (uint8, error) {
	value, err := r.Bytes(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

// U16 reads an unsigned big-endian sixteen-bit integer.
func (r *Reader) U16() (uint16, error) {
	value, err := r.Bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

// U32 reads an unsigned big-endian thirty-two-bit integer.
func (r *Reader) U32() (uint32, error) {
	value, err := r.Bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

// Counted16 reads a sixteen-bit length followed by that many bytes.
func (r *Reader) Counted16() ([]byte, error) {
	length, err := r.U16()
	if err != nil {
		return nil, err
	}
	return r.Bytes(int(length))
}

// Counted32 reads a thirty-two-bit length followed by that many bytes.
func (r *Reader) Counted32() ([]byte, error) {
	length, err := r.U32()
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(r.Remaining()) {
		return nil, fmt.Errorf("truncated counted field")
	}
	return r.Bytes(int(length))
}

// WriteCounted16 writes a sixteen-bit length followed by value.
func WriteCounted16(w io.Writer, value []byte) error {
	if uint64(len(value)) > uint64(^uint16(0)) {
		return fmt.Errorf("field is too long")
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(value))); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}

// WriteCounted32 writes a thirty-two-bit length followed by value.
func WriteCounted32(w io.Writer, value []byte) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return fmt.Errorf("field is too long")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}

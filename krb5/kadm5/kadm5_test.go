package kadm5

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestWriteEmptyEntryUsesMITNullPointers(t *testing.T) {
	p, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	w := xdrWriter{}
	writeEmptyEntry(&w, *p)
	r := xdrReader{b: w.bytes()}
	if got, err := r.principal(); err != nil || got.String() != p.String() {
		t.Fatalf("principal = %v, %v", got, err)
	}
	for i := 0; i < 4; i++ {
		if _, err := r.i32(); err != nil {
			t.Fatal(err)
		}
	}
	modNil, err := r.boolean()
	if err != nil || !modNil {
		t.Fatalf("mod_name null marker = %v, %v", modNil, err)
	}
	for i := 0; i < 4; i++ {
		if _, err := r.i32(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.nullString(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := r.i32(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.i16(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.i16(); err != nil {
		t.Fatal(err)
	}
	tlNil, err := r.boolean()
	if err != nil || !tlNil {
		t.Fatalf("tl_data null marker = %v, %v", tlNil, err)
	}
	if n, err := r.u32(); err != nil || n != 0 {
		t.Fatalf("key_data count = %d, %v", n, err)
	}
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeEntrySynthetic(t *testing.T) {
	p, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	w := xdrWriter{}
	writeEmptyEntry(&w, *p)
	entry, err := decodeEntry(&xdrReader{b: w.bytes()}, APIv4)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Principal.String() != p.String() || entry.Attributes != 0 || entry.KVNO != 0 {
		t.Fatalf("entry = %+v", entry)
	}
}

func TestRPCPrefixLayout(t *testing.T) {
	c := &Client{}
	prefix := c.rpcPrefix(0x01020304, createPrincipal, rpcsecGSS, []byte{0xaa, 0xbb})
	r := xdrReader{b: prefix}
	for _, want := range []uint32{0x01020304, msgCall, rpcVersion, Program, Version, createPrincipal, rpcsecGSS, 2} {
		got, err := r.u32()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("u32 = %#x, want %#x", got, want)
		}
	}
	if !bytes.Equal(r.b[r.off:r.off+2], []byte{0xaa, 0xbb}) {
		t.Fatalf("credential bytes = %x", r.b[r.off:])
	}
}

func TestXDRRejectsNonZeroPadding(t *testing.T) {
	r := xdrReader{b: []byte{0, 0, 0, 1, 'x', 1, 0, 0}}
	if _, err := r.opaque(); err == nil {
		t.Fatal("opaque accepted non-zero padding")
	}
}

func TestRecordMarkingSupportsFragments(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &Client{Conn: left}
	want := []byte("fragmented record")
	go func() {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], 4)
		_, _ = right.Write(h[:])
		_, _ = right.Write(want[:4])
		binary.BigEndian.PutUint32(h[:], uint32(len(want)-4)|0x80000000)
		_, _ = right.Write(h[:])
		_, _ = right.Write(want[4:])
	}()
	got, err := c.readRecord(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("record = %q, want %q", got, want)
	}
}

func TestRecordMarkingRejectsOversizedContinuation(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c := &Client{Conn: left}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], 0)
		_, _ = right.Write(h[:])
		binary.BigEndian.PutUint32(h[:], 16<<20+1)
		_, _ = right.Write(h[:])
	}()
	if _, err := c.readRecord(context.Background()); err == nil {
		t.Fatal("readRecord accepted oversized continuation fragment")
	}
	<-done
}

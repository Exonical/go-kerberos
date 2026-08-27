package kadm5

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

func TestWriteEntryHonorsModifyMask(t *testing.T) {
	p, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	entry := PrincipalEntry{
		Principal:        *p,
		PrincExpireTime:  11,
		LastPwdChange:    12,
		PWExpiration:     13,
		MaxLife:          14,
		Attributes:       15,
		KVNO:             16,
		MKVNO:            17,
		Policy:           "default",
		AuxAttributes:    18,
		MaxRenewableLife: 19,
		LastSuccess:      20,
		LastFailed:       21,
		FailAuthCount:    22,
	}
	w := xdrWriter{}
	writeEntry(&w, entry, KADM5Policy|KADM5Attributes)
	got, err := decodeEntry(&xdrReader{b: w.bytes()}, APIv4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal.String() != entry.Principal.String() ||
		got.Attributes != entry.Attributes || got.MaxLife != entry.MaxLife ||
		got.Policy != entry.Policy || got.MaxRenewableLife != entry.MaxRenewableLife {
		t.Fatalf("entry = %+v, want %+v", got, entry)
	}
	w = xdrWriter{}
	writeEntry(&w, entry, KADM5PolicyClear)
	got, err = decodeEntry(&xdrReader{b: w.bytes()}, APIv4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy != "" {
		t.Fatalf("policy-clear entry policy = %q", got.Policy)
	}
}

func TestPolicyXDRRoundTripByAPIVersion(t *testing.T) {
	want := Policy{
		Name: "default", MinLife: 1, MaxLife: 2, MinLength: 3,
		MinClasses: 4, HistoryNum: 5, MaxFailure: 6,
		FailureCountInterval: 7, LockoutDuration: 8,
		Attributes: 9, MaxTicketLife: 10, MaxRenewableLife: 11,
	}
	for _, api := range []uint32{APIv2, APIv3, APIv4} {
		t.Run(fmt.Sprintf("%#x", api), func(t *testing.T) {
			w := xdrWriter{}
			writePolicy(&w, want, api)
			got, err := readPolicy(&xdrReader{b: w.bytes()}, api)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || got.MinLife != want.MinLife ||
				got.MaxLife != want.MaxLife || got.MinLength != want.MinLength ||
				got.MinClasses != want.MinClasses || got.HistoryNum != want.HistoryNum {
				t.Fatalf("policy = %+v", got)
			}
			if api >= APIv3 && (got.MaxFailure != want.MaxFailure ||
				got.FailureCountInterval != want.FailureCountInterval ||
				got.LockoutDuration != want.LockoutDuration) {
				t.Fatalf("v3 policy = %+v", got)
			}
			if api >= APIv4 && (got.Attributes != want.Attributes ||
				got.MaxTicketLife != want.MaxTicketLife ||
				got.MaxRenewableLife != want.MaxRenewableLife) {
				t.Fatalf("v4 policy = %+v", got)
			}
		})
	}
}

func TestDecodeRandKeyRejectsOversizedArray(t *testing.T) {
	w := xdrWriter{}
	w.u32(1<<16 + 1)
	r := xdrReader{b: w.bytes()}
	if _, err := readKeys(&r); err == nil {
		t.Fatal("readKeys accepted oversized array")
	}
}

func TestReadKeysSynthetic(t *testing.T) {
	w := xdrWriter{}
	w.u32(2)
	w.i32(17)
	w.opaque([]byte{1, 2, 3})
	w.i32(18)
	w.opaque([]byte{4, 5})
	keys, err := readKeys(&xdrReader{b: w.bytes()})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Enctype != 17 ||
		!bytes.Equal(keys[0].Key, []byte{1, 2, 3}) ||
		keys[1].Enctype != 18 || !bytes.Equal(keys[1].Key, []byte{4, 5}) {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestRenamePrincipalGolden(t *testing.T) {
	src, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	dest, err := principal.Parse("bob@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	w := xdrWriter{}
	w.u32(APIv4)
	w.principal(*src)
	w.principal(*dest)
	const want = "1234570400000012616c696365404558414d504c452e434f4d00000000000010626f62404558414d504c452e434f4d00"
	if got := hex.EncodeToString(w.bytes()); got != want {
		t.Fatalf("rprinc_arg = %s, want %s", got, want)
	}
}

func TestStringListRejectsMalformedInput(t *testing.T) {
	w := xdrWriter{}
	w.i32(1)
	w.boolean(true)
	w.nullString("not-terminated")
	data := w.bytes()
	data[len(data)-1] = 1
	r := xdrReader{b: data}
	if _, err := readStringList(&r, "principal"); err == nil {
		t.Fatal("accepted malformed list string")
	}
	w = xdrWriter{}
	w.i32(-1)
	if _, err := readStringList(&xdrReader{b: w.bytes()}, "policy"); err == nil {
		t.Fatal("accepted negative list count")
	}
}

func TestStringListSynthetic(t *testing.T) {
	w := xdrWriter{}
	w.i32(3)
	w.boolean(true)
	w.nullString("alice@EXAMPLE.COM")
	w.boolean(false)
	w.boolean(true)
	w.nullString("bob@EXAMPLE.COM")
	got, err := readStringList(&xdrReader{b: w.bytes()}, "principal")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "alice@EXAMPLE.COM" || got[1] != "" ||
		got[2] != "bob@EXAMPLE.COM" {
		t.Fatalf("list = %#v", got)
	}
}

func TestPolicyXDRRejectsTruncation(t *testing.T) {
	w := xdrWriter{}
	writePolicy(&w, Policy{Name: "default"}, APIv4)
	for n := 0; n < len(w.bytes()); n++ {
		if _, err := readPolicy(&xdrReader{b: w.bytes()[:n]}, APIv4); err == nil {
			t.Fatalf("accepted truncated policy at %d/%d", n, len(w.bytes()))
		}
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

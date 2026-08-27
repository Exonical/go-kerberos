package types

import (
	"bytes"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

func TestKerberosTimeEncoding(t *testing.T) {
	tests := []struct {
		name string
		time KerberosTime
		want string
	}{
		{"epoch", KerberosTime{Time: time.Unix(0, 0).UTC(), Present: true}, "19700101000000Z"},
		{"pre2038", KerberosTime{Time: time.Date(2037, 12, 31, 23, 59, 59, 0, time.UTC), Present: true}, "20371231235959Z"},
		{"post2038", KerberosTime{Time: time.Date(2040, 1, 2, 3, 4, 5, 0, time.UTC), Present: true}, "20400102030405Z"},
		{"microseconds-separate", KerberosTime{Time: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), Microseconds: 123456, Present: true}, "20240102030405Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.time.EncodeGeneralizedTime()
			if err != nil {
				t.Fatalf("EncodeGeneralizedTime: %v", err)
			}
			if got != tt.want {
				t.Fatalf("encoded time = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKerberosTimeParsing(t *testing.T) {
	for _, input := range []string{"19700101000000Z", "20380119031408Z", "20400102030405Z"} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseKerberosTime(input)
			if err != nil {
				t.Fatalf("ParseKerberosTime: %v", err)
			}
			if !got.Present {
				t.Fatalf("parsed zero/optional time: %#v", got)
			}
		})
	}
}

func TestKerberosTimeRejectsFractionalSeconds(t *testing.T) {
	if _, err := ParseKerberosTime("20240102030405.123456Z"); err == nil {
		t.Fatal("fractional GeneralizedTime unexpectedly accepted")
	}
}

func TestDeterministicClockHook(t *testing.T) {
	want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	var clock Clock = fakeClock{now: want}
	if got := clock.Now(); !got.Equal(want) {
		t.Fatalf("fake clock returned %v, want %v", got, want)
	}
}

func TestInjectedRandomSource(t *testing.T) {
	source := RandomSource(bytes.NewReader([]byte{1, 2, 3, 4}))
	buf := make([]byte, 4)
	if _, err := source.Read(buf); err != nil {
		t.Fatalf("random source: %v", err)
	}
	if !bytes.Equal(buf, []byte{1, 2, 3, 4}) {
		t.Fatalf("random source bytes = %v", buf)
	}
}

func TestFlagBitPositions(t *testing.T) {
	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"KDC forwardable", uint32(KDCForwardable), 1 << 1},
		{"KDC proxiable", uint32(KDCProxiable), 1 << 3},
		{"KDC renewable", uint32(KDCRenewable), 1 << 8},
		{"KDC canonicalize", uint32(KDCCanonicalize), 1 << 15},
		{"ticket forwardable", uint32(TicketForwardable), 1 << 1},
		{"ticket renewable", uint32(TicketRenewable), 1 << 8},
		{"AP mutual", uint32(APMutualRequired), 1 << 2},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %#x, want %#x", tt.name, tt.got, tt.want)
		}
	}
}

func TestFlagsGoldenBITString(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  []byte
	}{
		{
			"forwardable-proxiable-renewable",
			uint32(KDCForwardable | KDCProxiable | KDCRenewable),
			// DER BIT STRING: tag 03, length 05, zero unused bits;
			// bit 1 is 0x40, bit 3 is 0x10 in octet one (0x50),
			// and bit 8 is 0x80 in octet two.
			[]byte{0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00},
		},
		{
			"canonicalize-last-octet",
			uint32(KDCCanonicalize),
			// Bit 15 is the low bit of the third flag octet:
			// 03 05 00 [octet1] [octet2] [octet3] [octet4].
			[]byte{0x03, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeFlags(tt.flags)
			if err != nil {
				t.Fatalf("EncodeFlags: %v", err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("flags DER = %x, want %x", got, tt.want)
			}
		})
	}
}

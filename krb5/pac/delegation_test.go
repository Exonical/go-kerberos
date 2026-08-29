package pac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDelegationInfoMITGoldens(t *testing.T) {
	tests := []struct {
		name, wire, proxy string
		services          []string
	}{
		{
			name:     "short",
			wire:     "01100800cccccccca000000000000000000002002a002c0004000200010000000800020016000000000000001500000073007600630032002f00610064007300650072007600650072002e00610064002e0074006500730074000000010000003a003c000c0002001e000000000000001d00000073007600630031002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e0054004500530054000000",
			proxy:    "svc2/adserver.ad.test",
			services: []string{"svc1/adserver.ad.test@AD.TEST"},
		},
		{
			name:     "long",
			wire:     "01100800cccccccca80000000000000000000200300032000400020001000000080002001900000000000000180000006c006f006e0067007300760063002f00610064007300650072007600650072002e00610064002e007400650073007400010000003a003c000c0002001e000000000000001d00000073007600630031002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e005400450053005400000000000000",
			proxy:    "longsvc/adserver.ad.test",
			services: []string{"svc1/adserver.ad.test@AD.TEST"},
		},
		{
			name:     "multiple",
			wire:     "01100800ccccccccf80000000000000000000200300032000400020002000000080002001900000000000000180000006c006f006e0067007300760063002f00610064007300650072007600650072002e00610064002e007400650073007400020000003a003c000c0002003a003c00100002001e000000000000001d00000073007600630031002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e00540045005300540000001e000000000000001d00000073007600630032002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e005400450053005400000000000000",
			proxy:    "longsvc/adserver.ad.test",
			services: []string{"svc1/adserver.ad.test@AD.TEST", "svc2/adserver.ad.test@AD.TEST"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(removeSpaces(test.wire))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseDelegationInfo(wire)
			if err != nil {
				t.Fatal(err)
			}
			if got.ProxyTarget != test.proxy || !equalStrings(got.TransitedServices, test.services) {
				t.Fatalf("decoded = %#v, want proxy %q services %#v", got, test.proxy, test.services)
			}
			encoded, err := got.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, wire) {
				t.Fatalf("re-encoded delegation info differs:\n%x\n%x", encoded, wire)
			}
		})
	}
}

func removeSpaces(value string) string {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != ' ' {
			out = append(out, value[i])
		}
	}
	return string(out)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

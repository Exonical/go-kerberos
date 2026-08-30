package client

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestMITValidTimesBehavior(t *testing.T) {
	present := func(seconds int64) types.KerberosTime {
		return types.KerberosTime{Time: time.Unix(seconds, 0).UTC(), Present: true}
	}
	now := time.Unix(1000, 0).UTC()
	skew := 300 * time.Second
	tests := []struct {
		name  string
		auth  types.KerberosTime
		start *types.KerberosTime
		end   types.KerberosTime
		want  bool
	}{
		{"inside lifetime", present(500), nil, present(1500), true},
		{"start within clock skew", present(500), mitKerberosTimePtr(present(1100)), present(1500), true},
		{"start beyond clock skew", present(500), mitKerberosTimePtr(present(1400)), present(1500), false},
		{"end within clock skew", present(500), mitKerberosTimePtr(present(500)), present(800), true},
		{"end beyond clock skew", present(500), mitKerberosTimePtr(present(500)), present(600), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validTimes(test.auth, test.start, test.end, now, skew); got != test.want {
				t.Fatalf("validTimes = %v, want %v", got, test.want)
			}
		})
	}

	const boundary = int64(-1 << 31)
	now = time.Unix(boundary-100, 0).UTC()
	if !validTimes(present(boundary-200), nil, present(boundary+500), now, skew) {
		t.Fatal("valid Y2038-boundary lifetime rejected")
	}
	start := present(boundary + 100)
	if !validTimes(present(boundary-200), &start, present(boundary+500), now, skew) {
		t.Fatal("Y2038-boundary start within skew rejected")
	}
	start = present(boundary + 250)
	if validTimes(present(boundary-200), &start, present(boundary+500), now, skew) {
		t.Fatal("Y2038-boundary start beyond skew accepted")
	}
	now = time.Unix(boundary+100, 0).UTC()
	if !validTimes(present(boundary-1000), nil, present(boundary-100), now, skew) {
		t.Fatal("Y2038-boundary end within skew rejected")
	}
	if validTimes(present(boundary-1000), nil, present(boundary-300), now, skew) {
		t.Fatal("Y2038-boundary end beyond skew accepted")
	}
}

func mitKerberosTimePtr(value types.KerberosTime) *types.KerberosTime {
	return &value
}

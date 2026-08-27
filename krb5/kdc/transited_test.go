package kdc

import (
	"bytes"
	"testing"
)

func TestTransitedCompression(t *testing.T) {
	tests := []struct {
		name   string
		realms []string
		want   string
	}{
		{name: "empty"},
		{name: "domain child", realms: []string{"EDU", "MIT.EDU"}, want: "EDU,MIT."},
		{name: "domain literals", realms: []string{"REALM.A", "REALM.B"}, want: "REALM.A,REALM.B"},
		{name: "domain suffix boundary", realms: []string{"EXAMPLE.COM", "MYEXAMPLE.COM"}, want: "EXAMPLE.COM,MYEXAMPLE.COM"},
		{name: "x500 child", realms: []string{"/C=US/O=MIT", "/C=US/O=MIT/OU=KRB"}, want: "/C=US/O=MIT,/OU=KRB"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := encodeTransited(test.realms)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("encoded = %q, want %q", got, test.want)
			}
			decoded, err := decodeTransited(got)
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != len(test.realms) {
				t.Fatalf("decoded = %#v", decoded)
			}
			for i := range decoded {
				if decoded[i] != test.realms[i] {
					t.Fatalf("decoded = %#v, want %#v", decoded, test.realms)
				}
			}
		})
	}
}

func TestTransitedRFCNullSubfield(t *testing.T) {
	got, err := decodeTransited([]byte(",EDU,,MIT."))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"EDU", "MIT.EDU"}
	if len(got) != len(want) || !bytes.Equal([]byte(got[0]), []byte(want[0])) ||
		!bytes.Equal([]byte(got[1]), []byte(want[1])) {
		t.Fatalf("decoded = %#v, want %#v", got, want)
	}
}

func TestTransitedEscaping(t *testing.T) {
	realms := []string{`A\,B`, `/C=US/O=MIT`, `/C=US/O=MIT/OU=KRB`}
	encoded, err := encodeTransited(realms)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTransited(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(realms) {
		t.Fatalf("decoded = %#v", decoded)
	}
	for i := range realms {
		if decoded[i] != realms[i] {
			t.Fatalf("decoded = %#v, want %#v", decoded, realms)
		}
	}
	if _, err := decodeTransited([]byte(`REALM\`)); err == nil {
		t.Fatal("unterminated escape unexpectedly accepted")
	}
}

func TestTransitedPolicy(t *testing.T) {
	contents, err := encodeTransited([]string{"A", "B"})
	if err != nil {
		t.Fatal(err)
	}
	if transitedPermitted(contents, "A", "C", nil) {
		t.Fatal("unconfigured intermediate unexpectedly permitted")
	}
	if !transitedPermitted(contents, "A", "C", map[string]map[string][]string{
		"A": {"C": {"B"}},
	}) {
		t.Fatal("configured intermediate rejected")
	}
}

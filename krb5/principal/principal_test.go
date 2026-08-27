package principal

import (
	"reflect"
	"testing"
)

func TestParsePrincipalNames(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		realm      string
		components []string
	}{
		{"user", "alice@REALM", "REALM", []string{"alice"}},
		{"host", "host/server.example.com@REALM", "REALM", []string{"host", "server.example.com"}},
		{"http", "HTTP/server.example.com@REALM", "REALM", []string{"HTTP", "server.example.com"}},
		{"multi", "service/a/b@REALM", "REALM", []string{"service", "a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.input, err)
			}
			want := &Principal{Realm: tt.realm, NameType: NTPrincipal, Components: tt.components}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Parse(%q) = %#v, want %#v", tt.input, got, want)
			}
		})
	}
}

func TestFormatPrincipalEscaping(t *testing.T) {
	tests := []struct {
		name string
		p    Principal
		want string
	}{
		{"slash", Principal{Realm: "REALM", Components: []string{"service", "a/b"}}, `service/a\/b@REALM`},
		{"at", Principal{Realm: "REALM", Components: []string{`user@name`}}, `user\@name@REALM`},
		{"backslash", Principal{Realm: "REALM", Components: []string{`a\b`}}, `a\\b@REALM`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.Format()
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMalformedPrincipalNames(t *testing.T) {
	for _, input := range []string{"", "@REALM", "alice@", "alice/\\@REALM", "alice/"} {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatalf("Parse(%q) succeeded for malformed principal", input)
			}
		})
	}
}

func TestPrincipalFieldsRemainDistinct(t *testing.T) {
	p := Principal{
		Realm:      "REALM",
		NameType:   NTSrvHst,
		Components: []string{"host", "server.example.com"},
	}
	if p.Realm == "" || p.NameType != NTSrvHst || len(p.Components) != 2 {
		t.Fatalf("principal fields were collapsed: %#v", p)
	}
	if _, err := p.Format(); err != nil {
		t.Fatalf("Format structured principal: %v", err)
	}
}

func TestNameTypeConstants(t *testing.T) {
	tests := map[NameType]int32{
		NTUnknown:       0,
		NTPrincipal:     1,
		NTSrvInstance:   2,
		NTSrvHst:        3,
		NTSrvXhst:       4,
		NTUID:           5,
		NTX500Principal: 6,
		NTSMTPName:      7,
		NTEnterprise:    10,
	}
	for got, want := range tests {
		if int32(got) != want {
			t.Errorf("name type %d, want %d", got, want)
		}
	}
}

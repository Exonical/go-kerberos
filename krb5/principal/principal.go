package principal

import (
	"fmt"
	"strings"
)

// NameType identifies the type of a Kerberos principal name (RFC 4120,
// section 6.2).
type NameType int32

const (
	NTUnknown       NameType = 0
	NTPrincipal     NameType = 1
	NTSrvInstance   NameType = 2
	NTSrvHst        NameType = 3
	NTSrvXhst       NameType = 4
	NTUID           NameType = 5
	NTX500Principal NameType = 6
	NTSMTPName      NameType = 7
	NTEnterprise    NameType = 10
	NTWellKnown     NameType = 11
)

// Principal is a structured Kerberos principal. Components are not collapsed
// into a single string so escaping and name-type semantics remain explicit.
type Principal struct {
	Realm      string
	NameType   NameType
	Components []string
}

// Parse parses a display-form principal name.
func Parse(name string) (*Principal, error) {
	if name == "" {
		return nil, fmt.Errorf("parse principal: empty name")
	}

	components := make([]string, 0, 1)
	var component strings.Builder
	var realm strings.Builder
	inRealm := false
	flushComponent := func() error {
		if component.Len() == 0 {
			return fmt.Errorf("empty component")
		}
		components = append(components, component.String())
		component.Reset()
		return nil
	}

	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '\\':
			if i+1 == len(name) {
				return nil, fmt.Errorf("parse principal: trailing escape")
			}
			i++
			switch name[i] {
			case '/', '@', '\\':
				if inRealm {
					realm.WriteByte(name[i])
				} else {
					component.WriteByte(name[i])
				}
			default:
				return nil, fmt.Errorf("parse principal: unsupported escape \\%c", name[i])
			}
		case '/':
			if inRealm {
				return nil, fmt.Errorf("parse principal: slash in realm")
			}
			if err := flushComponent(); err != nil {
				return nil, fmt.Errorf("parse principal: %w", err)
			}
		case '@':
			if inRealm {
				return nil, fmt.Errorf("parse principal: multiple realms")
			}
			if err := flushComponent(); err != nil {
				return nil, fmt.Errorf("parse principal: %w", err)
			}
			inRealm = true
		default:
			if inRealm {
				realm.WriteByte(name[i])
			} else {
				component.WriteByte(name[i])
			}
		}
	}
	if !inRealm {
		return nil, fmt.Errorf("parse principal: missing realm")
	}
	if realm.Len() == 0 {
		return nil, fmt.Errorf("parse principal: empty realm")
	}
	return &Principal{
		Realm:      realm.String(),
		NameType:   NTPrincipal,
		Components: components,
	}, nil
}

// Format returns the escaped display form of a principal.
func (p Principal) Format() (string, error) {
	if p.Realm == "" {
		return "", fmt.Errorf("format principal: empty realm")
	}
	if len(p.Components) == 0 {
		return "", fmt.Errorf("format principal: no components")
	}
	var out strings.Builder
	for i, component := range p.Components {
		if component == "" {
			return "", fmt.Errorf("format principal: empty component")
		}
		if i != 0 {
			out.WriteByte('/')
		}
		writeEscaped(&out, component)
	}
	out.WriteByte('@')
	writeEscaped(&out, p.Realm)
	return out.String(), nil
}

// String returns the escaped display form of a principal. Invalid structured
// principals have no display form and therefore return the empty string.
func (p Principal) String() string {
	value, err := p.Format()
	if err != nil {
		return ""
	}
	return value
}

func writeEscaped(out *strings.Builder, value string) {
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '/', '@', '\\':
			out.WriteByte('\\')
		}
		out.WriteByte(value[i])
	}
}

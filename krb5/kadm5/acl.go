package kadm5

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	aclAdd uint32 = 1 << iota
	aclDelete
	aclModify
	aclChangePassword
	aclInquire
	aclExtract
	aclList
	aclSetKey
	aclIPop
)

// ACL is an MIT kadm5.acl policy.
type ACL struct {
	entries []aclEntry
}

type aclEntry struct {
	clientAny bool
	client    principal.Principal
	ops       uint32
	targetAny bool
	target    principal.Principal
}

// ParseACL parses MIT kadm5.acl syntax from r.  ACL entries are evaluated in
// file order; the first entry matching both client and target controls access.
// Restrictions are rejected because the Server callback cannot apply
// add/modify field restrictions.
func ParseACL(r io.Reader) (*ACL, error) {
	if r == nil {
		return nil, fmt.Errorf("kadm5 ACL: nil reader")
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 1<<20)
	acl := &ACL{}
	var logical string
	startLine := 0
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if logical == "" {
			startLine = lineNo
		}
		if strings.HasSuffix(line, `\`) {
			logical += strings.TrimSuffix(line, `\`)
			continue
		}
		logical += line
		if logical == "" || strings.HasPrefix(logical, "#") {
			logical = ""
			continue
		}
		entry, err := parseACLEntry(logical)
		if err != nil {
			return nil, fmt.Errorf("kadm5 ACL line %d: %w", startLine, err)
		}
		acl.entries = append(acl.entries, *entry)
		logical = ""
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("kadm5 ACL: %w", err)
	}
	if logical != "" {
		entry, err := parseACLEntry(logical)
		if err != nil {
			return nil, fmt.Errorf("kadm5 ACL line %d: %w", startLine, err)
		}
		acl.entries = append(acl.entries, *entry)
	}
	return acl, nil
}

// LoadACL loads an MIT kadm5.acl file.
func LoadACL(path string) (*ACL, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("kadm5 ACL: open %q: %w", path, err)
	}
	defer file.Close()
	return ParseACL(file)
}

// Check reports whether client may perform operation on target.
func (a *ACL) Check(client principal.Principal, operation string,
	target principal.Principal) bool {
	if a == nil {
		return false
	}
	if (operation == "change-password" || operation == "set-password" || operation == "randkey") &&
		principalEqual(client, target) {
		return true
	}
	if operation == "get-privs" {
		return true
	}
	if operation == "rename" {
		return a.check(client, aclDelete, target)
	}
	bit, ok := aclOperation(operation)
	if !ok {
		return false
	}
	return a.check(client, bit, target)
}

// Func returns the callback form accepted by Server.ACL.
func (a *ACL) Func() func(principal.Principal, string, principal.Principal) bool {
	if a == nil {
		return nil
	}
	return a.Check
}

func (a *ACL) check(client principal.Principal, bit uint32,
	target principal.Principal) bool {
	for _, entry := range a.entries {
		var wildcards []string
		if !entry.clientAny &&
			!matchACLPrincipal(entry.client, client, false, &wildcards) {
			continue
		}
		if !entry.targetAny &&
			!matchACLPrincipal(entry.target, target, true, &wildcards) {
			continue
		}
		return entry.ops&bit != 0
	}
	return false
}

func aclOperation(operation string) (uint32, bool) {
	switch operation {
	case "create", "create-policy":
		return aclAdd, true
	case "delete", "delete-policy":
		return aclDelete, true
	case "modify", "modify-policy":
		return aclModify, true
	case "change-password", "set-password":
		return aclChangePassword, true
	case "get", "get-policy":
		return aclInquire, true
	case "list", "list-policy":
		return aclList, true
	case "extract-keys":
		return aclExtract, true
	case "set-key":
		return aclSetKey, true
	default:
		return 0, false
	}
}

func parseACLEntry(line string) (*aclEntry, error) {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\f', '\v', '\r', ',':
			return true
		default:
			return false
		}
	})
	if len(fields) < 2 {
		return nil, fmt.Errorf("expected principal and permissions")
	}
	if len(fields) > 3 {
		return nil, fmt.Errorf("restrictions are unsupported")
	}
	entry := &aclEntry{}
	if fields[0] == "*" {
		entry.clientAny = true
	} else {
		p, err := principal.Parse(fields[0])
		if err != nil {
			return nil, fmt.Errorf("invalid client principal %q: %w", fields[0], err)
		}
		entry.client = *p
	}
	var err error
	entry.ops, err = parseACLOperations(fields[1])
	if err != nil {
		return nil, err
	}
	if len(fields) == 2 || fields[2] == "*" {
		entry.targetAny = true
	} else {
		p, err := principal.Parse(fields[2])
		if err != nil {
			return nil, fmt.Errorf("invalid target principal %q: %w", fields[2], err)
		}
		entry.target = *p
	}
	return entry, nil
}

func parseACLOperations(value string) (uint32, error) {
	var allowed uint32
	for _, op := range value {
		letter := byte(op)
		deny := letter >= 'A' && letter <= 'Z'
		if deny {
			letter += 'a' - 'A'
		}
		bit, ok := map[byte]uint32{
			'a': aclAdd, 'd': aclDelete, 'm': aclModify,
			'c': aclChangePassword, 'i': aclInquire, 'l': aclList,
			'p': aclIPop, 's': aclSetKey, 'e': aclExtract,
			'x': aclAdd | aclDelete | aclModify | aclChangePassword |
				aclInquire | aclList | aclIPop | aclSetKey,
			'*': aclAdd | aclDelete | aclModify | aclChangePassword |
				aclInquire | aclList | aclIPop | aclSetKey,
		}[letter]
		if !ok {
			return 0, fmt.Errorf("unrecognized permission %q", string(op))
		}
		if deny {
			allowed &^= bit
		} else {
			allowed |= bit
		}
	}
	if value == "" {
		return 0, fmt.Errorf("empty permissions")
	}
	return allowed, nil
}

func matchACLPrincipal(pattern, value principal.Principal, target bool,
	wildcards *[]string) bool {
	if len(pattern.Components) != len(value.Components) ||
		pattern.Realm != value.Realm {
		return false
	}
	for i := range pattern.Components {
		component := pattern.Components[i]
		if strings.HasPrefix(component, "*") && len(component) == 2 &&
			component[1] >= '1' && component[1] <= '9' && target {
			index := int(component[1] - '1')
			if index >= len(*wildcards) ||
				(*wildcards)[index] != value.Components[i] {
				return false
			}
			continue
		}
		if component == "*" {
			if !target {
				*wildcards = append(*wildcards, value.Components[i])
			}
			continue
		}
		if component != value.Components[i] {
			return false
		}
	}
	return true
}

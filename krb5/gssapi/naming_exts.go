package gssapi

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/authdata"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// NameAttributes is the authenticated peer-name attribute surface attached to
// an accepted Kerberos context.
type NameAttributes struct {
	Principal principal.Principal
	Context   *authdata.Context
}

// The Credential methods provide the same naming-extension operations for
// callers that retain a credential as their authenticated-name handle.
func (c *Credential) InquireName() ([]string, error) {
	if c == nil || c.nameAttributes == nil {
		return nil, errors.New("GSS name attributes: unavailable")
	}
	return c.nameAttributes.AttributeTypes(), nil
}

func (c *Credential) GetNameAttribute(attr string) ([]byte, []byte, bool, bool, error) {
	if c == nil || c.nameAttributes == nil {
		return nil, nil, false, false, errors.New("GSS name attributes: unavailable")
	}
	return c.nameAttributes.GetAttribute(attr)
}

func (c *Credential) SetNameAttribute(attr string, value []byte, complete bool) error {
	if c == nil || c.nameAttributes == nil {
		return errors.New("GSS name attributes: unavailable")
	}
	return c.nameAttributes.SetAttribute(attr, value, complete)
}

func (c *Credential) DeleteNameAttribute(attr string) error {
	if c == nil || c.nameAttributes == nil {
		return errors.New("GSS name attributes: unavailable")
	}
	return c.nameAttributes.DeleteAttribute(attr)
}

func (c *Credential) ExportNameComposite() ([]byte, error) {
	if c == nil || c.name == nil {
		return nil, errors.New("GSS name attributes: unavailable")
	}
	return exportCompositeName(*c.name, c.nameAttributes)
}

func (n *NameAttributes) InquireName() ([]string, error) {
	if n == nil || n.Context == nil {
		return nil, errors.New("GSS name attributes: unavailable")
	}
	return n.Context.AttributeTypes(), nil
}

func (n *NameAttributes) GetNameAttribute(attr string) ([]byte, []byte, bool, bool, error) {
	if n == nil || n.Context == nil {
		return nil, nil, false, false, errors.New("GSS name attributes: unavailable")
	}
	return n.Context.GetAttribute(attr)
}

func (n *NameAttributes) SetNameAttribute(attr string, value []byte, complete bool) error {
	if n == nil || n.Context == nil {
		return errors.New("GSS name attributes: unavailable")
	}
	return n.Context.SetAttribute(attr, value, complete)
}

func (n *NameAttributes) DeleteNameAttribute(attr string) error {
	if n == nil || n.Context == nil {
		return errors.New("GSS name attributes: unavailable")
	}
	return n.Context.DeleteAttribute(attr)
}

func (n *NameAttributes) ExportNameComposite() ([]byte, error) {
	if n == nil {
		return nil, errors.New("GSS name attributes: unavailable")
	}
	return exportCompositeName(n.Principal, n.Context)
}

// PeerNameAttributes returns the authdata-backed peer name for an accepted
// context. It returns nil when no authdata modules were configured.
func (c *Context) PeerNameAttributes() *NameAttributes {
	if c == nil || c.nameAttributes == nil {
		return nil
	}
	return &NameAttributes{Principal: c.source, Context: c.nameAttributes}
}

func (c *Context) InquireName() ([]string, error) {
	peer := c.PeerNameAttributes()
	if peer == nil {
		return nil, errors.New("GSS name attributes: unavailable")
	}
	return peer.InquireName()
}

func (c *Context) GetNameAttribute(attr string) ([]byte, []byte, bool, bool, error) {
	peer := c.PeerNameAttributes()
	if peer == nil {
		return nil, nil, false, false, errors.New("GSS name attributes: unavailable")
	}
	return peer.GetNameAttribute(attr)
}

func (c *Context) SetNameAttribute(attr string, value []byte, complete bool) error {
	peer := c.PeerNameAttributes()
	if peer == nil {
		return errors.New("GSS name attributes: unavailable")
	}
	return peer.SetNameAttribute(attr, value, complete)
}

func (c *Context) DeleteNameAttribute(attr string) error {
	peer := c.PeerNameAttributes()
	if peer == nil {
		return errors.New("GSS name attributes: unavailable")
	}
	return peer.DeleteNameAttribute(attr)
}

func (c *Context) ExportNameComposite() ([]byte, error) {
	if c == nil {
		return nil, errors.New("GSS name attributes: unavailable")
	}
	return exportCompositeName(c.source, c.nameAttributes)
}

// DisplayNameExt returns the Kerberos display name, its name-type OID, and
// exported attributes. Kerberos hostbased and principal names use the same
// principal display form.
func (c *Context) DisplayNameExt() (string, string, []byte, error) {
	if c == nil {
		return "", "", nil, errors.New("GSS name attributes: unavailable")
	}
	attrs, err := exportAttributes(c.nameAttributes)
	if err != nil {
		return "", "", nil, err
	}
	return c.source.String(), "1.2.840.113554.1.2.2.1", attrs, nil
}

func exportCompositeName(name principal.Principal, attributes *authdata.Context) ([]byte, error) {
	display := name.String()
	if display == "" {
		return nil, fmt.Errorf("GSS composite name: invalid principal")
	}
	attrs, err := exportAttributes(attributes)
	if err != nil {
		return nil, err
	}
	// MIT's token is: 04 02, OID length, DER OID, principal length/name,
	// attribute length/data. kerberosOID already contains the DER tag/length.
	result := make([]byte, 0, 2+2+len(kerberosOID)+4+len(display)+4+len(attrs))
	result = append(result, 0x04, 0x02)
	var length [4]byte
	var short [2]byte
	binary.BigEndian.PutUint16(short[:], uint16(len(kerberosOID)))
	result = append(result, short[:]...)
	result = append(result, kerberosOID...)
	binary.BigEndian.PutUint32(length[:], uint32(len(display)))
	result = append(result, length[:]...)
	result = append(result, display...)
	binary.BigEndian.PutUint32(length[:], uint32(len(attrs)))
	result = append(result, length[:]...)
	result = append(result, attrs...)
	return result, nil
}

func exportAttributes(attributes *authdata.Context) ([]byte, error) {
	if attributes == nil {
		return nil, nil
	}
	return attributes.ExportAttributes()
}

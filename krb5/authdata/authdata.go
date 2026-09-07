// Package authdata implements compile-time registered Kerberos authorization
// data client modules.
package authdata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	ADUsageASReq      uint32 = 0x01
	ADUsageTGSReq     uint32 = 0x02
	ADUsageAPReq      uint32 = 0x04
	ADUsageKDCIssued  uint32 = 0x08
	ADInformational   uint32 = 0x10
	ADCAMMACProtected uint32 = 0x20
)

var ErrAttributeNotFound = errors.New("authdata: attribute not found")

// Module is the required portion of a client authorization-data module.
// Optional operations are supplied by AttributeSetter, AttributeDeleter, and
// InternalExporter.
type Module interface {
	Name() string
	Flags(adType int32) uint32
	ImportAuthData(data protocol.AuthorizationData, kdcIssued bool,
		issuer *principal.Principal) error
	ExportAuthData(usage uint32) (protocol.AuthorizationData, error)
	AttributeTypes() []string
	GetAttribute(attribute string) (value, display []byte,
		authenticated, complete bool, err error)
}

type AttributeSetter interface {
	SetAttribute(attribute string, value []byte, complete bool) error
}

type AttributeDeleter interface {
	DeleteAttribute(attribute string) error
}

type InternalExporter interface {
	ExportInternal(restrictAuthenticated bool) (any, error)
}

// Context dispatches authorization data to registered modules.
type Context struct {
	modules []Module
}

func NewContext(modules ...Module) *Context {
	result := &Context{modules: make([]Module, 0, len(modules))}
	for _, module := range modules {
		if module != nil {
			result.modules = append(result.modules, module)
		}
	}
	return result
}

func (c *Context) Modules() []Module {
	if c == nil {
		return nil
	}
	return append([]Module(nil), c.modules...)
}

type importedAuthData struct {
	entry         protocol.AuthorizationDataEntry
	usage         uint32
	authenticated bool
	issuer        *principal.Principal
}

func (c *Context) Import(data protocol.AuthorizationData, usage uint32,
	ticket *protocol.EncTicketPart, key protocol.EncryptionKey) error {
	if c == nil {
		return errors.New("authdata: nil context")
	}
	items, err := c.unwrap(data, usage, false, nil, ticket, key)
	if err != nil {
		return err
	}
	for _, module := range c.modules {
		for _, item := range items {
			flags := module.Flags(item.entry.ADType)
			if flags&item.usage == 0 {
				continue
			}
			if err := module.ImportAuthData(protocol.AuthorizationData{item.entry},
				item.authenticated, item.issuer); err != nil {
				if flags&ADInformational != 0 {
					continue
				}
				return fmt.Errorf("authdata module %s: %w", module.Name(), err)
			}
		}
	}
	return nil
}

func (c *Context) unwrap(data protocol.AuthorizationData, usage uint32, authenticated bool,
	issuer *principal.Principal, ticket *protocol.EncTicketPart,
	key protocol.EncryptionKey) ([]importedAuthData, error) {
	var result []importedAuthData
	for _, entry := range data {
		switch entry.ADType {
		case protocol.ADIfRelevant:
			var inner protocol.AuthorizationData
			if err := asn1.Unmarshal(entry.ADData, &inner); err != nil {
				return nil, fmt.Errorf("authdata IF-RELEVANT: %w", err)
			}
			for _, innerEntry := range inner {
				if innerEntry.ADType == protocol.ADCAMMAC {
					wrapped, marshalErr := asn1.Marshal(protocol.AuthorizationData{innerEntry})
					if marshalErr != nil {
						return nil, marshalErr
					}
					if protocolData, verifyErr := c.unwrapCAMMAC(
						protocol.AuthorizationData{{
							ADType: protocol.ADIfRelevant,
							ADData: wrapped,
						}},
						usage, authenticated, issuer, ticket, key,
					); verifyErr == nil {
						result = append(result, protocolData...)
						continue
					}
				}
				items, err := c.unwrap(protocol.AuthorizationData{innerEntry},
					usage, authenticated, issuer, ticket, key)
				if err != nil {
					return nil, err
				}
				result = append(result, items...)
			}
		case protocol.ADKDCIssued:
			var issued protocol.KDCIssued
			if err := asn1.Unmarshal(entry.ADData, &issued); err != nil {
				return nil, fmt.Errorf("authdata KDC-ISSUED: %w", err)
			}
			encoded, err := asn1.Marshal(issued.Elements)
			if err != nil {
				return nil, err
			}
			etype, etypeErr := checksumEType(issued.Checksum.ChecksumType)
			if etypeErr != nil {
				return nil, etypeErr
			}
			verified := false
			if len(key.KeyValue) > 0 {
				if verifyErr := etype.VerifyChecksum(key.KeyValue, 19, encoded,
					issued.Checksum.Checksum); verifyErr != nil {
					return nil, fmt.Errorf("authdata KDC-ISSUED checksum: %w", verifyErr)
				}
				verified = true
			}
			var nextIssuer *principal.Principal
			if issued.IName != nil && issued.IRealm != nil {
				value := principal.Principal{
					Realm:      *issued.IRealm,
					NameType:   principal.NameType(issued.IName.NameType),
					Components: append([]string(nil), issued.IName.NameString...),
				}
				nextIssuer = &value
			} else {
				nextIssuer = issuer
			}
			nextUsage := usage
			if verified {
				nextUsage |= ADUsageKDCIssued
			}
			items, err := c.unwrap(issued.Elements, nextUsage, authenticated || verified,
				nextIssuer, ticket, key)
			if err != nil {
				return nil, err
			}
			result = append(result, items...)
		case protocol.ADCAMMAC:
			// An unwrapped CAMMAC cannot be authenticated without its
			// containing AD-IF-RELEVANT value.
			result = append(result, importedAuthData{
				entry: entry, usage: usage, authenticated: authenticated, issuer: issuer,
			})
		default:
			result = append(result, importedAuthData{
				entry: entry, usage: usage, authenticated: authenticated, issuer: issuer,
			})
		}
	}
	return result, nil
}

func (c *Context) unwrapCAMMAC(data protocol.AuthorizationData,
	usage uint32, authenticated bool, issuer *principal.Principal, ticket *protocol.EncTicketPart,
	key protocol.EncryptionKey) ([]importedAuthData, error) {
	if len(key.KeyValue) == 0 || ticket == nil || !cammac.HasCAMMAC(data) {
		return nil, cammac.ErrNotFound
	}
	if _, err := cammac.VerifyService(data, key); err != nil {
		return nil, err
	}
	protected, err := cammac.ProtectedElements(data)
	if err != nil {
		return nil, err
	}
	return c.unwrap(protected, usage|ADCAMMACProtected, true, issuer, ticket, key)
}

func checksumEType(checksumType int32) (crypto.EType, error) {
	var enctype int32
	switch checksumType {
	case crypto.ChecksumHMACSHA196AES128:
		enctype = crypto.EnctypeAES128SHA1
	case crypto.ChecksumHMACSHA196AES256:
		enctype = crypto.EnctypeAES256SHA1
	case crypto.ChecksumCMACCamellia128:
		enctype = crypto.EnctypeCamellia128
	case crypto.ChecksumCMACCamellia256:
		enctype = crypto.EnctypeCamellia256
	case crypto.ChecksumHMACSHA256128AES128:
		enctype = crypto.EnctypeAES128SHA256
	case crypto.ChecksumHMACSHA384192AES256:
		enctype = crypto.EnctypeAES256SHA384
	default:
		return nil, fmt.Errorf("authdata: unsupported keyed checksum type %d", checksumType)
	}
	return crypto.NewRegistry().Get(enctype)
}

func (c *Context) Export(usage uint32) (protocol.AuthorizationData, error) {
	if c == nil {
		return nil, errors.New("authdata: nil context")
	}
	var result protocol.AuthorizationData
	for _, module := range c.modules {
		data, err := module.ExportAuthData(usage)
		if err != nil {
			return nil, fmt.Errorf("authdata module %s: %w", module.Name(), err)
		}
		result = append(result, data...)
	}
	return result, nil
}

func (c *Context) AttributeTypes() []string {
	if c == nil {
		return nil
	}
	var result []string
	for _, module := range c.modules {
		result = append(result, module.AttributeTypes()...)
	}
	return result
}

func (c *Context) GetAttribute(attribute string) (value, display []byte,
	authenticated, complete bool, err error) {
	if c == nil {
		return nil, nil, false, false, errors.New("authdata: nil context")
	}
	for _, module := range c.modules {
		value, display, authenticated, complete, err = module.GetAttribute(attribute)
		if err == nil {
			return value, display, authenticated, complete, nil
		}
		if !errors.Is(err, ErrAttributeNotFound) {
			return nil, nil, false, false, err
		}
	}
	return nil, nil, false, false, ErrAttributeNotFound
}

func (c *Context) SetAttribute(attribute string, value []byte, complete bool) error {
	for _, module := range c.modules {
		if setter, ok := module.(AttributeSetter); ok {
			if err := setter.SetAttribute(attribute, value, complete); err == nil {
				return nil
			} else if !errors.Is(err, ErrAttributeNotFound) {
				return err
			}
		}
	}
	return ErrAttributeNotFound
}

func (c *Context) DeleteAttribute(attribute string) error {
	for _, module := range c.modules {
		if deleter, ok := module.(AttributeDeleter); ok {
			if err := deleter.DeleteAttribute(attribute); err == nil {
				return nil
			} else if !errors.Is(err, ErrAttributeNotFound) {
				return err
			}
		}
	}
	return ErrAttributeNotFound
}

func (c *Context) ExportInternal(restrictAuthenticated bool) (any, error) {
	for _, module := range c.modules {
		if exporter, ok := module.(InternalExporter); ok {
			return exporter.ExportInternal(restrictAuthenticated)
		}
	}
	return nil, errors.New("authdata: internal export unsupported")
}

// ExportAttributes returns a deterministic internal representation of the
// current name attributes. It is used by GSS composite-name tokens; it is not
// a Kerberos authorization-data wire encoding.
func (c *Context) ExportAttributes() ([]byte, error) {
	if c == nil {
		return nil, errors.New("authdata: nil context")
	}
	types := c.AttributeTypes()
	sort.Strings(types)
	var result []byte
	for _, attribute := range types {
		value, _, authenticated, complete, err := c.GetAttribute(attribute)
		if err != nil {
			if errors.Is(err, ErrAttributeNotFound) {
				continue
			}
			return nil, err
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(attribute)))
		result = append(result, length[:]...)
		result = append(result, attribute...)
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		result = append(result, length[:]...)
		result = append(result, value...)
		flags := byte(0)
		if authenticated {
			flags |= 1
		}
		if complete {
			flags |= 2
		}
		result = append(result, flags)
	}
	return result, nil
}

// Package authdata implements compile-time registered Kerberos authorization
// data client modules.
package authdata

import (
	"errors"
	"fmt"

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
	authenticated bool
	issuer        *principal.Principal
}

func (c *Context) Import(data protocol.AuthorizationData, usage uint32,
	ticket *protocol.EncTicketPart, key protocol.EncryptionKey) error {
	if c == nil {
		return errors.New("authdata: nil context")
	}
	items, err := c.unwrap(data, false, nil, ticket, key)
	if err != nil {
		return err
	}
	for _, module := range c.modules {
		for _, item := range items {
			flags := module.Flags(item.entry.ADType)
			if flags&usage == 0 {
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

func (c *Context) unwrap(data protocol.AuthorizationData, authenticated bool,
	issuer *principal.Principal, ticket *protocol.EncTicketPart,
	key protocol.EncryptionKey) ([]importedAuthData, error) {
	var result []importedAuthData
	for _, entry := range data {
		switch entry.ADType {
		case protocol.ADIfRelevant:
			if protocolData, err := c.unwrapCAMMAC(protocol.AuthorizationData{entry},
				authenticated, issuer, ticket, key); err == nil {
				result = append(result, protocolData...)
				continue
			}
			var inner protocol.AuthorizationData
			if err := asn1.Unmarshal(entry.ADData, &inner); err != nil {
				return nil, fmt.Errorf("authdata IF-RELEVANT: %w", err)
			}
			items, err := c.unwrap(inner, authenticated, issuer, ticket, key)
			if err != nil {
				return nil, err
			}
			result = append(result, items...)
		case protocol.ADKDCIssued:
			var issued protocol.KDCIssued
			if err := asn1.Unmarshal(entry.ADData, &issued); err != nil {
				return nil, fmt.Errorf("authdata KDC-ISSUED: %w", err)
			}
			encoded, err := asn1.Marshal(issued.Elements)
			if err != nil {
				return nil, err
			}
			verified := false
			if len(key.KeyValue) > 0 {
				etype, etypeErr := crypto.NewRegistry().Get(key.KeyType)
				if etypeErr != nil {
					return nil, etypeErr
				}
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
			items, err := c.unwrap(issued.Elements, authenticated || verified,
				nextIssuer, ticket, key)
			if err != nil {
				return nil, err
			}
			result = append(result, items...)
		case protocol.ADCAMMAC:
			// An unwrapped CAMMAC cannot be authenticated without its
			// containing AD-IF-RELEVANT value.
			result = append(result, importedAuthData{
				entry: entry, authenticated: authenticated, issuer: issuer,
			})
		default:
			result = append(result, importedAuthData{
				entry: entry, authenticated: authenticated, issuer: issuer,
			})
		}
	}
	if len(result) == 0 {
		if protected, err := c.unwrapCAMMAC(data, authenticated, issuer, ticket, key); err == nil {
			result = append(result, protected...)
		}
	}
	return result, nil
}

func (c *Context) unwrapCAMMAC(data protocol.AuthorizationData,
	authenticated bool, issuer *principal.Principal, ticket *protocol.EncTicketPart,
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
	return c.unwrap(protected, true, issuer, ticket, key)
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
	}
	return nil, nil, false, false, errors.New("authdata: attribute not found")
}

func (c *Context) SetAttribute(attribute string, value []byte, complete bool) error {
	for _, module := range c.modules {
		if setter, ok := module.(AttributeSetter); ok {
			if err := setter.SetAttribute(attribute, value, complete); err == nil {
				return nil
			}
		}
	}
	return errors.New("authdata: attribute not found")
}

func (c *Context) DeleteAttribute(attribute string) error {
	for _, module := range c.modules {
		if deleter, ok := module.(AttributeDeleter); ok {
			if err := deleter.DeleteAttribute(attribute); err == nil {
				return nil
			}
		}
	}
	return errors.New("authdata: attribute not found")
}

func (c *Context) ExportInternal(restrictAuthenticated bool) (any, error) {
	for _, module := range c.modules {
		if exporter, ok := module.(InternalExporter); ok {
			return exporter.ExportInternal(restrictAuthenticated)
		}
	}
	return nil, errors.New("authdata: internal export unsupported")
}

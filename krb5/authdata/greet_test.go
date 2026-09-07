package authdata

import (
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	GreetAuthDataType int32 = -42
	GreetAttribute          = "urn:greet:greeting"
)

// GreetModule is the client half of MIT's sample greet authdata plugin.
type GreetModule struct {
	greeting      []byte
	authenticated bool
}

func (m *GreetModule) Name() string { return "greet" }

func (m *GreetModule) Flags(adType int32) uint32 {
	if adType == GreetAuthDataType {
		return ADUsageAPReq | ADUsageKDCIssued | ADInformational
	}
	return 0
}

func (m *GreetModule) ImportAuthData(data protocol.AuthorizationData,
	kdcIssued bool, _ *principal.Principal) error {
	if len(data) == 0 || data[0].ADType != GreetAuthDataType {
		return fmt.Errorf("greet: %w", ErrAttributeNotFound)
	}
	m.greeting = append(m.greeting[:0], data[0].ADData...)
	m.authenticated = kdcIssued
	return nil
}

func (m *GreetModule) ExportAuthData(uint32) (protocol.AuthorizationData, error) {
	if len(m.greeting) == 0 {
		return nil, nil
	}
	return protocol.AuthorizationData{{
		ADType: GreetAuthDataType,
		ADData: append([]byte(nil), m.greeting...),
	}}, nil
}

func (m *GreetModule) AttributeTypes() []string {
	if len(m.greeting) == 0 {
		return nil
	}
	return []string{GreetAttribute}
}

func (m *GreetModule) GetAttribute(attribute string) (value, display []byte,
	authenticated, complete bool, err error) {
	if attribute != GreetAttribute || len(m.greeting) == 0 {
		return nil, nil, false, false, fmt.Errorf("greet: %w", ErrAttributeNotFound)
	}
	value = append([]byte(nil), m.greeting...)
	return value, append([]byte(nil), value...), m.authenticated, true, nil
}

func (m *GreetModule) SetAttribute(attribute string, value []byte, _ bool) error {
	if attribute != GreetAttribute {
		return fmt.Errorf("greet: %w", ErrAttributeNotFound)
	}
	if len(m.greeting) != 0 {
		return errors.New("greet: attribute already set")
	}
	m.greeting = append([]byte(nil), value...)
	m.authenticated = false
	return nil
}

func (m *GreetModule) DeleteAttribute(attribute string) error {
	if attribute != GreetAttribute {
		return fmt.Errorf("greet: %w", ErrAttributeNotFound)
	}
	m.greeting = nil
	m.authenticated = false
	return nil
}

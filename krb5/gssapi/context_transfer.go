package gssapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const contextTransferVersion = 1

type contextTransfer struct {
	Magic              string
	Version            int
	KeyType            int32
	Key                string
	PartialKeyType     int32
	PartialKey         string
	FullKeyType        int32
	FullKey            string
	Initiator          bool
	Flags              uint32
	DCEStyle           bool
	AcceptorSubkey     bool
	AcceptorSubkeyType int32
	AcceptorSubkeyKey  string
	SendSeq            uint64
	RecvSeq            uint64
	Source             principal.Principal
	Target             principal.Principal
	EndTime            time.Time
	Delegated          []*client.Credentials
}

// ExportSecContext serializes an established context for transfer between
// processes. The encoding is stable within version 1 and includes all
// message-protection keys and sequence state.
func ExportSecContext(c *Context) ([]byte, error) {
	if c == nil || len(c.key.KeyValue) == 0 ||
		len(c.prfPartial.KeyValue) == 0 || len(c.prfFull.KeyValue) == 0 {
		return nil, fmt.Errorf("GSS export context: context is not established")
	}
	wire := contextTransfer{
		Magic: "GO-KERBEROS-GSS-CONTEXT", Version: contextTransferVersion,
		KeyType: c.key.KeyType, Key: base64.StdEncoding.EncodeToString(c.key.KeyValue),
		PartialKeyType: c.prfPartial.KeyType,
		PartialKey:     base64.StdEncoding.EncodeToString(c.prfPartial.KeyValue),
		FullKeyType:    c.prfFull.KeyType,
		FullKey:        base64.StdEncoding.EncodeToString(c.prfFull.KeyValue),
		Initiator:      c.initiator, Flags: c.flags, DCEStyle: c.dceStyle,
		AcceptorSubkey: c.acceptorSubkey, SendSeq: c.sendSeq, RecvSeq: c.recvSeq,
		Source: c.source, Target: c.target, EndTime: c.endtime,
		Delegated: cloneCredentials(c.DelegatedCredentials),
	}
	if c.acceptorSubkeyKey != nil {
		wire.AcceptorSubkeyType = c.acceptorSubkeyKey.KeyType
		wire.AcceptorSubkeyKey = base64.StdEncoding.EncodeToString(c.acceptorSubkeyKey.KeyValue)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("GSS export context: %w", err)
	}
	return encoded, nil
}

// Export is the method form of ExportSecContext.
func (c *Context) Export() ([]byte, error) { return ExportSecContext(c) }

// ExportContext is an alternate descriptive name for ExportSecContext.
func ExportContext(c *Context) ([]byte, error) { return ExportSecContext(c) }

// ImportSecContext restores a context exported by ExportSecContext.
func ImportSecContext(data []byte) (*Context, error) {
	var wire contextTransfer
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("GSS import context: %w", err)
	}
	if wire.Magic != "GO-KERBEROS-GSS-CONTEXT" || wire.Version != contextTransferVersion {
		return nil, fmt.Errorf("GSS import context: unsupported context")
	}
	decode := func(label, value string, typ int32) (protocol.EncryptionKey, error) {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(raw) == 0 || typ == 0 {
			return protocol.EncryptionKey{}, fmt.Errorf("GSS import context: invalid %s key", label)
		}
		return protocol.EncryptionKey{KeyType: typ, KeyValue: raw}, nil
	}
	key, err := decode("context", wire.Key, wire.KeyType)
	if err != nil {
		return nil, err
	}
	partial, err := decode("partial", wire.PartialKey, wire.PartialKeyType)
	if err != nil {
		return nil, err
	}
	full, err := decode("full", wire.FullKey, wire.FullKeyType)
	if err != nil {
		return nil, err
	}
	ctx := &Context{
		key: key, prfPartial: partial, prfFull: full, initiator: wire.Initiator,
		flags: wire.Flags, dceStyle: wire.DCEStyle, acceptorSubkey: wire.AcceptorSubkey,
		sendSeq: wire.SendSeq, recvSeq: wire.RecvSeq, source: wire.Source,
		target: wire.Target, endtime: wire.EndTime,
		DelegatedCredentials: cloneCredentials(wire.Delegated),
	}
	if wire.AcceptorSubkeyKey != "" {
		subkey, err := decode("acceptor subkey", wire.AcceptorSubkeyKey, wire.AcceptorSubkeyType)
		if err != nil {
			return nil, err
		}
		ctx.acceptorSubkeyKey = &subkey
	}
	if ctx.acceptorSubkey && ctx.acceptorSubkeyKey == nil {
		return nil, fmt.Errorf("GSS import context: missing acceptor subkey")
	}
	return ctx, nil
}

// Import is the method-compatible top-level naming counterpart.
func (c *Context) Import(data []byte) (*Context, error) { return ImportSecContext(data) }

func cloneCredentials(values []*client.Credentials) []*client.Credentials {
	if values == nil {
		return nil
	}
	result := make([]*client.Credentials, len(values))
	for i, value := range values {
		if value == nil {
			continue
		}
		copyValue := *value
		copyValue.Client.Components = append([]string(nil), value.Client.Components...)
		copyValue.Server.Components = append([]string(nil), value.Server.Components...)
		copyValue.Key.KeyValue = append([]byte(nil), value.Key.KeyValue...)
		copyValue.Ticket = append([]byte(nil), value.Ticket...)
		result[i] = &copyValue
	}
	return result
}

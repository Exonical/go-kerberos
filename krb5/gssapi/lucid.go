package gssapi

import (
	"fmt"
	"time"
)

// LucidKey is the exported form of a protocol key.
type LucidKey struct {
	Type  int32
	Value []byte
}

// LucidContext exposes the version 1 CFX state described by MIT's
// gss_krb5_lucid_context_v1 structure.
type LucidContext struct {
	Version        uint32
	Initiate       bool
	EndTime        time.Time
	SendSeq        uint64
	RecvSeq        uint64
	Protocol       uint32
	Key            LucidKey
	AcceptorSubkey *LucidKey
}

// ExportLucidContext exports read-only CFX key and sequence state without
// consuming the context.
func (c *Context) ExportLucidContext(version uint32) (LucidContext, error) {
	if c == nil || len(c.key.KeyValue) == 0 {
		return LucidContext{}, fmt.Errorf("GSS lucid context: context is not established")
	}
	if version != 1 {
		return LucidContext{}, fmt.Errorf("GSS lucid context: unsupported version %d", version)
	}
	result := LucidContext{
		Version: 1, Initiate: c.initiator, EndTime: c.endtime,
		SendSeq: c.sendSeq, RecvSeq: c.recvSeq, Protocol: 1,
		Key: LucidKey{Type: c.prfPartial.KeyType, Value: append([]byte(nil), c.prfPartial.KeyValue...)},
	}
	if len(c.prfPartial.KeyValue) == 0 {
		result.Key = LucidKey{Type: c.key.KeyType, Value: append([]byte(nil), c.key.KeyValue...)}
	}
	if c.acceptorSubkeyKey != nil {
		result.AcceptorSubkey = &LucidKey{
			Type:  c.acceptorSubkeyKey.KeyType,
			Value: append([]byte(nil), c.acceptorSubkeyKey.KeyValue...),
		}
	}
	return result, nil
}

// Lucid is a shorthand for ExportLucidContext.
func (c *Context) Lucid(version uint32) (LucidContext, error) {
	return c.ExportLucidContext(version)
}

// ExportLucidSecContext is the top-level form matching MIT's operation name.
func ExportLucidSecContext(c *Context, version uint32) (LucidContext, error) {
	if c == nil {
		return LucidContext{}, fmt.Errorf("GSS lucid context: nil context")
	}
	return c.ExportLucidContext(version)
}

// Package spnego implements the RFC 4178 SPNEGO mechanism over Kerberos GSS.
package spnego

import (
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/keytab"
)

const (
	SPNEGOOID         = "1.3.6.1.5.5.2"
	KerberosOID       = gssapi.KerberosMechOID
	KerberosLegacyOID = "1.2.840.48018.1.2.2"

	NegStateAcceptCompleted  NegState = 0
	NegStateAcceptIncomplete NegState = 1
	NegStateReject           NegState = 2
	NegStateRequestMIC       NegState = 3
	NegStateUnset            NegState = 255
)

// NegState is the RFC 4178 negotiation result.
type NegState uint8

// NegTokenInit is the SPNEGO initiator token.
type NegTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier
	ReqFlags    []byte
	MechToken   []byte
	MechListMIC []byte
}

// NegTokenResp is the SPNEGO acceptor token.
type NegTokenResp struct {
	NegState      NegState
	SupportedMech asn1.ObjectIdentifier
	ResponseToken []byte
	MechListMIC   []byte
}

// Token is one of the two RFC 4178 negotiation choices.
type Token struct {
	Init *NegTokenInit
	Resp *NegTokenResp
}

var (
	spnegoOID         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	kerberosOID       = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	legacyKerberosOID = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
)

// EncodeToken encodes a SPNEGO token using RFC 4178 DER.
func EncodeToken(token Token) ([]byte, error) {
	var choice []byte
	switch {
	case token.Init != nil && token.Resp == nil:
		body, err := encodeInit(*token.Init)
		if err != nil {
			return nil, err
		}
		choice = tlv(0xa0, body)
	case token.Resp != nil && token.Init == nil:
		body, err := encodeResp(*token.Resp)
		if err != nil {
			return nil, err
		}
		choice = tlv(0xa1, body)
	default:
		return nil, fmt.Errorf("SPNEGO token: exactly one choice is required")
	}
	return gssFrame(tlv(0x06, oidBytes(spnegoOID)), choice), nil
}

// DecodeToken decodes a GSS-framed RFC 4178 token.
func DecodeToken(data []byte) (Token, error) {
	body := data
	if len(data) > 0 && data[0] == 0x60 {
		var err error
		body, err = unframe(data)
		if err != nil {
			return Token{}, err
		}
	}
	tag, choice, rest, err := readTLV(body)
	if err != nil || len(rest) != 0 {
		return Token{}, fmt.Errorf("SPNEGO token: invalid negotiation choice")
	}
	switch tag {
	case 0xa0:
		init, err := decodeInit(choice)
		return Token{Init: &init}, err
	case 0xa1:
		resp, err := decodeResp(choice)
		return Token{Resp: &resp}, err
	default:
		return Token{}, fmt.Errorf("SPNEGO token: unsupported choice tag 0x%x", tag)
	}
}

func encodeInit(init NegTokenInit) ([]byte, error) {
	if len(init.MechTypes) == 0 {
		return nil, fmt.Errorf("SPNEGO NegTokenInit: empty mechanism list")
	}
	fields := tlv(0xa0, encodeMechTypes(init.MechTypes))
	if len(init.ReqFlags) != 0 {
		fields = append(fields, tlv(0xa1, tlv(0x03, init.ReqFlags))...)
	}
	if init.MechToken != nil {
		fields = append(fields, tlv(0xa2, tlv(0x04, init.MechToken))...)
	}
	if init.MechListMIC != nil {
		fields = append(fields, tlv(0xa3, tlv(0x04, init.MechListMIC))...)
	}
	return tlv(0x30, fields), nil
}

func encodeResp(resp NegTokenResp) ([]byte, error) {
	var fields []byte
	if resp.NegState != NegStateUnset {
		if resp.NegState > NegStateRequestMIC {
			return nil, fmt.Errorf("SPNEGO NegTokenResp: invalid negotiation state")
		}
		fields = append(fields, tlv(0xa0, tlv(0x0a, []byte{byte(resp.NegState)}))...)
	}
	if resp.SupportedMech != nil {
		fields = append(fields, tlv(0xa1, mustOID(resp.SupportedMech))...)
	}
	if resp.ResponseToken != nil {
		fields = append(fields, tlv(0xa2, tlv(0x04, resp.ResponseToken))...)
	}
	if resp.MechListMIC != nil {
		fields = append(fields, tlv(0xa3, tlv(0x04, resp.MechListMIC))...)
	}
	return tlv(0x30, fields), nil
}

func encodeBareResp(resp NegTokenResp) ([]byte, error) {
	body, err := encodeResp(resp)
	if err != nil {
		return nil, err
	}
	return tlv(0xa1, body), nil
}

func decodeInit(data []byte) (NegTokenInit, error) {
	tag, value, rest, err := readTLV(data)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return NegTokenInit{}, fmt.Errorf("SPNEGO NegTokenInit: invalid sequence")
	}
	var out NegTokenInit
	for len(value) != 0 {
		tag, field, next, err := readTLV(value)
		if err != nil {
			return out, err
		}
		value = next
		switch tag {
		case 0xa0:
			out.MechTypes, err = decodeMechTypes(field)
		case 0xa1:
			var bitString []byte
			var rest []byte
			tag, bitString, rest, err = readTLV(field)
			if err == nil && (tag != 0x03 || len(rest) != 0 || len(bitString) == 0 ||
				bitString[0] > 7) {
				err = fmt.Errorf("SPNEGO NegTokenInit: invalid reqFlags")
			}
			if err == nil {
				out.ReqFlags = bitString
			}
		case 0xa2:
			out.MechToken, err = decodeOctet(field)
		case 0xa3:
			out.MechListMIC, err = decodeOctet(field)
		default:
			return out, fmt.Errorf("SPNEGO NegTokenInit: unexpected tag 0x%x", tag)
		}
		if err != nil {
			return out, err
		}
	}
	if len(out.MechTypes) == 0 {
		return out, fmt.Errorf("SPNEGO NegTokenInit: missing mechanism list")
	}
	return out, nil
}

func decodeResp(data []byte) (NegTokenResp, error) {
	tag, value, rest, err := readTLV(data)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return NegTokenResp{}, fmt.Errorf("SPNEGO NegTokenResp: invalid sequence")
	}
	out := NegTokenResp{NegState: NegStateUnset}
	for len(value) != 0 {
		tag, field, next, err := readTLV(value)
		if err != nil {
			return out, err
		}
		value = next
		switch tag {
		case 0xa0:
			_, enum, _, err := readTLV(field)
			if err != nil || len(enum) != 1 || enum[0] > byte(NegStateRequestMIC) {
				return out, fmt.Errorf("SPNEGO NegTokenResp: invalid negState")
			}
			out.NegState = NegState(enum[0])
		case 0xa1:
			out.SupportedMech, err = parseOID(field)
		case 0xa2:
			out.ResponseToken, err = decodeOctet(field)
		case 0xa3:
			out.MechListMIC, err = decodeOctet(field)
		default:
			return out, fmt.Errorf("SPNEGO NegTokenResp: unexpected tag 0x%x", tag)
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func encodeMechTypes(mechs []asn1.ObjectIdentifier) []byte {
	var body []byte
	for _, mech := range mechs {
		body = append(body, mustOID(mech)...)
	}
	return tlv(0x30, body)
}

func decodeMechTypes(data []byte) ([]asn1.ObjectIdentifier, error) {
	tag, value, rest, err := readTLV(data)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return nil, fmt.Errorf("SPNEGO mechanism list: invalid sequence")
	}
	var mechs []asn1.ObjectIdentifier
	for len(value) != 0 {
		tag, oid, next, err := readTLV(value)
		if err != nil || tag != 0x06 {
			return nil, fmt.Errorf("SPNEGO mechanism list: invalid OID")
		}
		parsed, err := parseOIDValue(oid)
		if err != nil {
			return nil, err
		}
		mechs = append(mechs, parsed)
		value = next
	}
	return mechs, nil
}

func decodeOctet(data []byte) ([]byte, error) {
	tag, value, rest, err := readTLV(data)
	if err != nil || tag != 0x04 || len(rest) != 0 {
		return nil, fmt.Errorf("SPNEGO: invalid OCTET STRING")
	}
	return append([]byte(nil), value...), nil
}

func parseOID(data []byte) (asn1.ObjectIdentifier, error) {
	tag, value, rest, err := readTLV(data)
	if err != nil || tag != 0x06 || len(rest) != 0 {
		return nil, fmt.Errorf("SPNEGO: invalid mechanism OID")
	}
	return parseOIDValue(value)
}

func parseOIDValue(value []byte) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(tlv(0x06, value), &oid); err != nil {
		return nil, fmt.Errorf("SPNEGO: invalid mechanism OID: %w", err)
	}
	return oid, nil
}

func mustOID(oid asn1.ObjectIdentifier) []byte {
	data, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return data
}

func oidBytes(oid asn1.ObjectIdentifier) []byte {
	return mustOID(oid)[2:]
}

func tlv(tag byte, value []byte) []byte {
	length := len(value)
	var head []byte
	if length < 128 {
		head = []byte{tag, byte(length)}
	} else {
		n := 0
		for x := length; x > 0; x >>= 8 {
			n++
		}
		head = append([]byte{tag, 0x80 | byte(n)}, make([]byte, n)...)
		for i := n - 1; i >= 0; i-- {
			head[2+i] = byte(length >> (8 * (n - i - 1)))
		}
	}
	return append(head, value...)
}

func readTLV(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("SPNEGO: truncated DER")
	}
	length, offset, err := derLength(data[1:])
	if err != nil || offset+length > len(data)-1 {
		return 0, nil, nil, fmt.Errorf("SPNEGO: invalid DER length")
	}
	start := 1 + offset
	return data[0], data[start : start+length], data[start+length:], nil
}

func derLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("SPNEGO: truncated DER length")
	}
	if data[0] < 128 {
		return int(data[0]), 1, nil
	}
	n := int(data[0] & 0x7f)
	if n == 0 || n > 4 || len(data) < n+1 || data[1] == 0 {
		return 0, 0, fmt.Errorf("SPNEGO: invalid DER length")
	}
	length := 0
	for _, b := range data[1 : n+1] {
		length = length<<8 | int(b)
	}
	if length < 128 {
		return 0, 0, fmt.Errorf("SPNEGO: non-minimal DER length")
	}
	return length, n + 1, nil
}

func gssFrame(oid, inner []byte) []byte {
	content := append(append([]byte(nil), oid...), inner...)
	return tlv(0x60, content)
}

func unframe(data []byte) ([]byte, error) {
	tag, value, rest, err := readTLV(data)
	if err != nil || tag != 0x60 || len(rest) != 0 {
		return nil, fmt.Errorf("SPNEGO: invalid GSS framing")
	}
	if len(value) < 2 {
		return nil, fmt.Errorf("SPNEGO: missing mechanism OID")
	}
	tag, oid, rest, err := readTLV(value)
	if err != nil || tag != 0x06 || len(rest) == len(value) {
		return nil, fmt.Errorf("SPNEGO: invalid mechanism OID")
	}
	parsed, err := parseOIDValue(oid)
	if err != nil || !parsed.Equal(spnegoOID) {
		return nil, fmt.Errorf("SPNEGO: unexpected mechanism OID")
	}
	return rest, nil
}

func isKerberos(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(kerberosOID) || oid.Equal(legacyKerberosOID)
}

func mechListDER(mechs []asn1.ObjectIdentifier) []byte {
	return encodeMechTypes(mechs)
}

// Initiator negotiates SPNEGO using a Kerberos GSS initiator.
type Initiator struct {
	creds    *client.Credentials
	flags    uint32
	mechs    []asn1.ObjectIdentifier
	mech     *gssapi.Initiator
	mechList []asn1.ObjectIdentifier
	needMIC  bool
	complete bool
}

// NewInitiator creates an initiator offering the Kerberos mechanism.
func NewInitiator(creds *client.Credentials, flags uint32) (*Initiator, error) {
	return NewInitiatorWithMechs(creds, flags, []asn1.ObjectIdentifier{kerberosOID})
}

// NewInitiatorWithMechs creates an initiator with an explicit mechanism order.
func NewInitiatorWithMechs(creds *client.Credentials, flags uint32, mechs []asn1.ObjectIdentifier) (*Initiator, error) {
	if len(mechs) == 0 {
		return nil, fmt.Errorf("SPNEGO initiator: empty mechanism list")
	}
	if _, index := selectKerberos(mechs); index < 0 {
		return nil, fmt.Errorf("SPNEGO initiator: Kerberos mechanism is not offered")
	}
	gi, err := gssapi.NewInitiator(creds, flags)
	if err != nil {
		return nil, err
	}
	return &Initiator{creds: creds, flags: flags, mechs: append([]asn1.ObjectIdentifier(nil), mechs...), mech: gi}, nil
}

// InitialToken emits NegTokenInit containing the Kerberos AP-REQ.
func (i *Initiator) InitialToken(now time.Time) ([]byte, error) {
	if i == nil || i.mech == nil {
		return nil, fmt.Errorf("SPNEGO initiator: incomplete context")
	}
	if i.mechList != nil {
		return nil, fmt.Errorf("SPNEGO initiator: token already sent")
	}
	mechToken, err := i.mech.InitialToken(now)
	if err != nil {
		return nil, err
	}
	i.mechList = append([]asn1.ObjectIdentifier(nil), i.mechs...)
	return EncodeToken(Token{Init: &NegTokenInit{MechTypes: i.mechList, MechToken: mechToken}})
}

// Continue processes an acceptor token. A nil return token means establishment.
func (i *Initiator) Continue(token []byte) ([]byte, error) {
	if i == nil || i.mech == nil || i.mechList == nil {
		return nil, fmt.Errorf("SPNEGO initiator: context is not initialized")
	}
	decoded, err := DecodeToken(token)
	if err != nil || decoded.Resp == nil {
		return nil, fmt.Errorf("SPNEGO initiator: %w", err)
	}
	resp := decoded.Resp
	if resp.NegState == NegStateReject {
		return nil, fmt.Errorf("SPNEGO initiator: acceptor rejected negotiation")
	}
	selected := resp.SupportedMech
	if selected == nil {
		selected = kerberosOID
	}
	if !isKerberos(selected) {
		return nil, fmt.Errorf("SPNEGO initiator: unsupported selected mechanism")
	}
	i.needMIC = resp.NegState == NegStateRequestMIC || !selected.Equal(i.mechList[0])
	if resp.ResponseToken != nil {
		if err := i.mech.VerifyToken(resp.ResponseToken); err != nil {
			return nil, err
		}
	}
	if resp.MechListMIC != nil {
		ctx, err := i.mech.Context()
		if err != nil {
			return nil, err
		}
		if err := ctx.VerifyMIC(mechListDER(i.mechList), resp.MechListMIC); err != nil {
			return nil, fmt.Errorf("SPNEGO initiator: mechListMIC: %w", err)
		}
	}
	if i.needMIC {
		ctx, err := i.mech.Context()
		if err != nil {
			return nil, err
		}
		mic, err := ctx.MIC(mechListDER(i.mechList))
		if err != nil {
			return nil, err
		}
		i.complete = true
		return encodeBareResp(NegTokenResp{
			NegState: NegStateAcceptCompleted, SupportedMech: selected, MechListMIC: mic,
		})
	}
	i.complete = true
	return nil, nil
}

// Context returns the underlying established Kerberos context.
func (i *Initiator) Context() (*Context, error) {
	if i == nil || !i.complete {
		return nil, fmt.Errorf("SPNEGO initiator: context is not established")
	}
	ctx, err := i.mech.Context()
	if err != nil {
		return nil, err
	}
	return &Context{ctx: ctx, established: true}, nil
}

// Acceptor negotiates SPNEGO using a Kerberos GSS acceptor.
type Acceptor struct {
	mech      *gssapi.Acceptor
	ctx       *Context
	mechTypes []asn1.ObjectIdentifier
	needMIC   bool
}

// NewAcceptor creates an acceptor backed by a Kerberos service keytab.
func NewAcceptor(kt *keytab.Keytab) *Acceptor {
	return &Acceptor{mech: gssapi.NewAcceptor(kt)}
}

// Accept processes an initiator token and returns an optional response token.
func (a *Acceptor) Accept(token []byte, now time.Time) (*Context, []byte, error) {
	if a == nil || a.mech == nil {
		return nil, nil, fmt.Errorf("SPNEGO acceptor: incomplete context")
	}
	if a.ctx != nil {
		decoded, err := DecodeToken(token)
		if err != nil || decoded.Resp == nil {
			return nil, nil, fmt.Errorf("SPNEGO acceptor: %w", err)
		}
		resp := decoded.Resp
		if resp.MechListMIC == nil {
			return nil, nil, fmt.Errorf("SPNEGO acceptor: missing required mechListMIC")
		}
		if err := a.ctx.ctx.VerifyMIC(mechListDER(a.mechTypes), resp.MechListMIC); err != nil {
			return nil, nil, fmt.Errorf("SPNEGO acceptor: mechListMIC: %w", err)
		}
		if resp.NegState == NegStateReject {
			return nil, nil, fmt.Errorf("SPNEGO acceptor: initiator rejected negotiation")
		}
		a.needMIC = false
		a.ctx.established = true
		return a.ctx, nil, nil
	}
	decoded, err := DecodeToken(token)
	if err != nil || decoded.Init == nil {
		return nil, nil, fmt.Errorf("SPNEGO acceptor: %w", err)
	}
	init := decoded.Init
	selected, index := selectKerberos(init.MechTypes)
	if selected == nil {
		return nil, nil, fmt.Errorf("SPNEGO acceptor: no supported mechanism")
	}
	if init.MechToken == nil {
		return nil, nil, fmt.Errorf("SPNEGO acceptor: missing mechanism token")
	}
	ctx, reply, err := a.mech.Accept(init.MechToken, now)
	if err != nil {
		return nil, nil, err
	}
	needMIC := index != 0
	if init.MechListMIC != nil {
		if err := ctx.VerifyMIC(mechListDER(init.MechTypes), init.MechListMIC); err != nil {
			return nil, nil, fmt.Errorf("SPNEGO acceptor: mechListMIC: %w", err)
		}
		needMIC = true
	}
	state := NegStateAcceptCompleted
	if needMIC {
		state = NegStateRequestMIC
	}
	resp := &NegTokenResp{NegState: state, SupportedMech: selected}
	if reply != nil {
		resp.ResponseToken = reply
	}
	if needMIC {
		mic, err := ctx.MIC(mechListDER(init.MechTypes))
		if err != nil {
			return nil, nil, err
		}
		resp.MechListMIC = mic
	}
	out, err := encodeBareResp(*resp)
	if err != nil {
		return nil, nil, err
	}
	if needMIC {
		a.ctx = &Context{ctx: ctx}
		a.mechTypes = append([]asn1.ObjectIdentifier(nil), init.MechTypes...)
		a.needMIC = true
		return a.ctx, out, nil
	}
	a.ctx = &Context{ctx: ctx, established: true}
	return a.ctx, out, nil
}

func selectKerberos(mechs []asn1.ObjectIdentifier) (asn1.ObjectIdentifier, int) {
	for index, mech := range mechs {
		if isKerberos(mech) {
			return mech, index
		}
	}
	return nil, -1
}

// Context exposes the established underlying Kerberos per-message operations.
type Context struct {
	ctx         *gssapi.Context
	established bool
}

// Wrap protects a message using RFC 4121.
func (c *Context) Wrap(data []byte, sealed bool) ([]byte, error) {
	if c == nil || c.ctx == nil || !c.established {
		return nil, fmt.Errorf("SPNEGO context: not established")
	}
	return c.ctx.Wrap(data, sealed)
}

// Unwrap verifies and decodes a protected message.
func (c *Context) Unwrap(token []byte) ([]byte, error) {
	if c == nil || c.ctx == nil || !c.established {
		return nil, fmt.Errorf("SPNEGO context: not established")
	}
	return c.ctx.Unwrap(token)
}

// MIC creates an RFC 4121 integrity token.
func (c *Context) MIC(data []byte) ([]byte, error) {
	if c == nil || c.ctx == nil || !c.established {
		return nil, fmt.Errorf("SPNEGO context: not established")
	}
	return c.ctx.MIC(data)
}

// VerifyMIC verifies an RFC 4121 integrity token.
func (c *Context) VerifyMIC(data, token []byte) error {
	if c == nil || c.ctx == nil || !c.established {
		return fmt.Errorf("SPNEGO context: not established")
	}
	return c.ctx.VerifyMIC(data, token)
}

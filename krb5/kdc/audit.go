package kdc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// AuditStage identifies the processing phase associated with an event.
type AuditStage int

const (
	AuditAuthnReqClient   AuditStage = 1
	AuditServicePrincipal AuditStage = 2
	AuditValidatePolicy   AuditStage = 3
	AuditIssueTicket      AuditStage = 4
	AuditEncryptReply     AuditStage = 5
)

// AuditViolation identifies the class of policy or protocol violation.
type AuditViolation int

const (
	AuditProtocolConstraint AuditViolation = 1
	AuditLocalPolicy        AuditViolation = 2
)

// AuditState carries the request and ticket identifiers exposed by MIT's
// krb5_audit_state. IDs are hexadecimal hashes or random request IDs and are
// safe to serialize to an audit sink.
type AuditState struct {
	RequestID        string
	InputTicketID    string
	OutputTicketID   string
	EvidenceTicketID string
	Client           principal.Principal
	Service          principal.Principal
	RequestType      string
	Status           string
	Stage            AuditStage
	Violation        AuditViolation
	S4U2SelfUser     *principal.Principal
	PreauthType      string
	AuthIndicators   []string
	ErrorCode        int32
	RemoteAddr       string
}

// AuditFunc adapts a single callback to the KDC audit module interface.
type AuditFunc func(event string, success bool, state AuditState)

type auditFuncModule struct {
	name string
	fn   AuditFunc
}

// NewFuncAuditModule creates an audit module backed by fn.
func NewFuncAuditModule(name string, fn AuditFunc) AuditModule {
	return auditFuncModule{name: name, fn: fn}
}

func (m auditFuncModule) Name() string { return m.name }
func (m auditFuncModule) call(event string, success bool, state AuditState) error {
	if m.fn != nil {
		m.fn(event, success, state)
	}
	return nil
}
func (m auditFuncModule) KDCStart(ok bool) error { return m.call("kdc_start", ok, AuditState{}) }
func (m auditFuncModule) KDCStop(ok bool) error  { return m.call("kdc_stop", ok, AuditState{}) }
func (m auditFuncModule) ASReq(ok bool, state AuditState) error {
	return m.call("as_req", ok, state)
}
func (m auditFuncModule) TGSReq(ok bool, state AuditState) error {
	return m.call("tgs_req", ok, state)
}
func (m auditFuncModule) S4U2Self(ok bool, state AuditState) error {
	return m.call("s4u2self", ok, state)
}
func (m auditFuncModule) S4U2Proxy(ok bool, state AuditState) error {
	return m.call("s4u2proxy", ok, state)
}
func (m auditFuncModule) U2U(ok bool, state AuditState) error {
	return m.call("u2u", ok, state)
}

// AuditModule receives KDC lifecycle and request events in registration
// order. Audit failures are reported to AuditErrorLog but never affect KDC
// replies.
type AuditModule interface {
	Name() string
	KDCStart(success bool) error
	KDCStop(success bool) error
	ASReq(success bool, state AuditState) error
	TGSReq(success bool, state AuditState) error
	S4U2Self(success bool, state AuditState) error
	S4U2Proxy(success bool, state AuditState) error
	U2U(success bool, state AuditState) error
}

// JSONFileAuditModule writes one JSON object per event, one event per line.
// This mirrors the event-oriented output of MIT's simple audit module while
// remaining portable and usable without libaudit.
type JSONFileAuditModule struct {
	mu   sync.Mutex
	file *os.File
}

// NewJSONFileAuditModule opens path for append-only JSON audit records.
func NewJSONFileAuditModule(path string) (*JSONFileAuditModule, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &JSONFileAuditModule{file: file}, nil
}

func (m *JSONFileAuditModule) Name() string { return "json-file" }
func (m *JSONFileAuditModule) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.file == nil {
		return nil
	}
	err := m.file.Close()
	m.file = nil
	return err
}

type auditRecord struct {
	Event            string         `json:"event"`
	Success          bool           `json:"success"`
	RequestID        string         `json:"request_id,omitempty"`
	InputTicketID    string         `json:"tkt_in_id,omitempty"`
	OutputTicketID   string         `json:"tkt_out_id,omitempty"`
	EvidenceTicketID string         `json:"evid_tkt_id,omitempty"`
	Client           string         `json:"client,omitempty"`
	Service          string         `json:"service,omitempty"`
	RequestType      string         `json:"request_type,omitempty"`
	Status           string         `json:"status,omitempty"`
	Stage            AuditStage     `json:"stage,omitempty"`
	Violation        AuditViolation `json:"violation,omitempty"`
	S4U2SelfUser     string         `json:"s4u2self_user,omitempty"`
	PreauthType      string         `json:"preauth_type,omitempty"`
	AuthIndicators   []string       `json:"auth_indicators,omitempty"`
	ErrorCode        int32          `json:"error_code,omitempty"`
	RemoteAddr       string         `json:"remote_addr,omitempty"`
}

func auditPrincipal(p principal.Principal) string {
	if p.Realm == "" && len(p.Components) == 0 {
		return ""
	}
	value, _ := p.Format()
	return value
}

func (m *JSONFileAuditModule) write(event string, success bool, state AuditState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.file == nil {
		return fmt.Errorf("audit module is closed")
	}
	record := auditRecord{
		Event: event, Success: success, RequestID: state.RequestID,
		InputTicketID: state.InputTicketID, OutputTicketID: state.OutputTicketID,
		EvidenceTicketID: state.EvidenceTicketID, Client: auditPrincipal(state.Client),
		Service: auditPrincipal(state.Service), RequestType: state.RequestType,
		Status: state.Status, Stage: state.Stage, Violation: state.Violation,
		PreauthType: state.PreauthType, AuthIndicators: state.AuthIndicators,
		ErrorCode: state.ErrorCode, RemoteAddr: state.RemoteAddr,
	}
	if state.S4U2SelfUser != nil {
		record.S4U2SelfUser = auditPrincipal(*state.S4U2SelfUser)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, err = m.file.Write(encoded)
	return err
}
func (m *JSONFileAuditModule) KDCStart(ok bool) error             { return m.write("kdc_start", ok, AuditState{}) }
func (m *JSONFileAuditModule) KDCStop(ok bool) error              { return m.write("kdc_stop", ok, AuditState{}) }
func (m *JSONFileAuditModule) ASReq(ok bool, s AuditState) error  { return m.write("as_req", ok, s) }
func (m *JSONFileAuditModule) TGSReq(ok bool, s AuditState) error { return m.write("tgs_req", ok, s) }
func (m *JSONFileAuditModule) S4U2Self(ok bool, s AuditState) error {
	return m.write("s4u2self", ok, s)
}
func (m *JSONFileAuditModule) S4U2Proxy(ok bool, s AuditState) error {
	return m.write("s4u2proxy", ok, s)
}
func (m *JSONFileAuditModule) U2U(ok bool, s AuditState) error { return m.write("u2u", ok, s) }

func auditID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

func auditRequestID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return auditID([]byte(fmt.Sprintf("%p", &id)))
	}
	return hex.EncodeToString(id[:])
}

func isKRBErrorResponse(response []byte) bool {
	return len(response) > 0 && response[0] == 0x7e
}

func (s *AuditState) SuccessState(response []byte) {
	s.OutputTicketID = ""
	s.ErrorCode = 0
	if isKRBErrorResponse(response) {
		s.Status = "error"
		var failure protocol.KRBError
		if err := asn1.Unmarshal(response, &failure); err == nil {
			s.ErrorCode = failure.ErrorCode
		}
		return
	}
	s.Status = "success"
	var tgs protocol.TGSRep
	if err := asn1.Unmarshal(response, &tgs); err == nil && tgs.MsgType == 13 {
		s.OutputTicketID = auditID(marshalDER(tgs.Ticket))
		return
	}
	var as protocol.ASRep
	if err := asn1.Unmarshal(response, &as); err == nil && as.MsgType == 11 {
		s.OutputTicketID = auditID(marshalDER(as.Ticket))
	}
}

func (s *Server) auditCall(name string, call func(AuditModule) error) {
	for _, module := range s.AuditModules {
		if module == nil {
			continue
		}
		if err := call(module); err != nil && s.AuditErrorLog != nil {
			s.AuditErrorLog(fmt.Errorf("kdc audit module %s %s: %w", module.Name(), name, err))
		}
	}
}

// AuditKDCStart and AuditKDCStop expose lifecycle events for embedders which
// manage listeners themselves.
func (s *Server) AuditKDCStart(success bool) {
	s.auditCall("kdc_start", func(m AuditModule) error { return m.KDCStart(success) })
}
func (s *Server) AuditKDCStop(success bool) {
	s.auditCall("kdc_stop", func(m AuditModule) error { return m.KDCStop(success) })
}

func (s *Server) auditAS(success bool, state AuditState) {
	s.auditCall("as_req", func(m AuditModule) error { return m.ASReq(success, state) })
}
func (s *Server) auditTGS(success bool, state AuditState) {
	s.auditCall("tgs_req", func(m AuditModule) error { return m.TGSReq(success, state) })
	switch state.RequestType {
	case "s4u2self":
		s.auditCall("s4u2self", func(m AuditModule) error { return m.S4U2Self(success, state) })
	case "s4u2proxy":
		s.auditCall("s4u2proxy", func(m AuditModule) error { return m.S4U2Proxy(success, state) })
	case "u2u":
		s.auditCall("u2u", func(m AuditModule) error { return m.U2U(success, state) })
	}
}

func newASAuditState(request protocol.ASReq) AuditState {
	state := AuditState{RequestID: auditRequestID(), RequestType: "as_req", Stage: AuditAuthnReqClient}
	if request.ReqBody.CName != nil {
		state.Client = principalFromProtocol(*request.ReqBody.CName, request.ReqBody.Realm)
	}
	if request.ReqBody.SName != nil {
		state.Service = principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	}
	return state
}

func newTGSAuditState(request protocol.TGSReq) AuditState {
	state := AuditState{RequestID: auditRequestID(), RequestType: "tgs_req", Stage: AuditAuthnReqClient}
	if request.ReqBody.SName != nil {
		state.Service = principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	}
	return state
}

func classifyTGSRequest(request protocol.TGSReq) string {
	if request.ReqBody.KDCOptions&types.KDCEncTktInSkey != 0 {
		return "u2u"
	}
	if findPA(request.PAData, protocol.PADataForUser) != nil ||
		findPA(request.PAData, protocol.PADataS4UX509User) != nil {
		return "s4u2self"
	}
	if request.ReqBody.KDCOptions&types.KDCCNameInAddlTkt != 0 {
		return "s4u2proxy"
	}
	return "tgs_req"
}

package kdc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestJSONFileAuditModule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	module, err := NewJSONFileAuditModule(path)
	if err != nil {
		t.Fatal(err)
	}
	state := AuditState{RequestID: "request", InputTicketID: "in", OutputTicketID: "out",
		Status: "success", Stage: AuditIssueTicket}
	if err := module.KDCStart(true); err != nil {
		t.Fatal(err)
	}
	if err := module.ASReq(true, state); err != nil {
		t.Fatal(err)
	}
	if err := module.TGSReq(false, state); err != nil {
		t.Fatal(err)
	}
	if err := module.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var events []map[string]any
	for scanner.Scan() {
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0]["event"] != "kdc_start" ||
		events[1]["request_id"] != "request" || events[2]["success"] != false {
		t.Fatalf("events = %#v", events)
	}
}

type recordingAudit struct {
	events *[]string
}

type lifecycleAudit struct {
	starts []bool
	stops  []bool
}

func (a *lifecycleAudit) Name() string                  { return "lifecycle" }
func (a *lifecycleAudit) KDCStart(ok bool) error        { a.starts = append(a.starts, ok); return nil }
func (a *lifecycleAudit) KDCStop(ok bool) error         { a.stops = append(a.stops, ok); return nil }
func (a *lifecycleAudit) ASReq(bool, AuditState) error  { return nil }
func (a *lifecycleAudit) TGSReq(bool, AuditState) error { return nil }
func (a *lifecycleAudit) S4U2Self(bool, AuditState) error {
	return nil
}
func (a *lifecycleAudit) S4U2Proxy(bool, AuditState) error {
	return nil
}
func (a *lifecycleAudit) U2U(bool, AuditState) error { return nil }

func (a recordingAudit) Name() string        { return "recording" }
func (a recordingAudit) KDCStart(bool) error { *a.events = append(*a.events, "start"); return nil }
func (a recordingAudit) KDCStop(bool) error  { *a.events = append(*a.events, "stop"); return nil }
func (a recordingAudit) ASReq(bool, AuditState) error {
	*a.events = append(*a.events, "as")
	return nil
}
func (a recordingAudit) TGSReq(bool, AuditState) error {
	*a.events = append(*a.events, "tgs")
	return nil
}
func (a recordingAudit) S4U2Self(bool, AuditState) error {
	*a.events = append(*a.events, "s4u-self")
	return nil
}
func (a recordingAudit) S4U2Proxy(bool, AuditState) error {
	*a.events = append(*a.events, "s4u-proxy")
	return nil
}
func (a recordingAudit) U2U(bool, AuditState) error { *a.events = append(*a.events, "u2u"); return nil }

func TestAuditModuleOrderingAndVariants(t *testing.T) {
	var events []string
	server := &Server{AuditModules: []AuditModule{
		recordingAudit{events: &events}, recordingAudit{events: &events},
	}}
	server.AuditKDCStart(true)
	server.auditTGS(true, AuditState{RequestType: "s4u2self"})
	server.auditTGS(true, AuditState{RequestType: "s4u2proxy"})
	server.auditTGS(false, AuditState{RequestType: "u2u"})
	server.AuditKDCStop(true)
	want := []string{"start", "start", "tgs", "tgs", "s4u-self", "s4u-self",
		"tgs", "tgs", "s4u-proxy", "s4u-proxy", "tgs", "tgs", "u2u", "u2u",
		"stop", "stop"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

func TestAuditSuccessStateUsesTicketDER(t *testing.T) {
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: "EXAMPLE.COM",
		SName:   protocol.PrincipalName{NameType: 2, NameString: []string{"host", "server"}},
		EncPart: protocol.EncryptedData{EType: 18, Cipher: []byte{1, 2, 3}},
	}
	response := protocol.TGSRep{PVNO: 5, MsgType: 13, Ticket: ticket}
	encoded, err := asn1.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var state AuditState
	state.SuccessState(encoded)
	if state.Status != "success" || state.OutputTicketID != auditID(marshalDER(ticket)) {
		t.Fatalf("state = %#v", state)
	}
	var failure AuditState
	failure.SuccessState([]byte{0x7e})
	if failure.Status != "error" || failure.OutputTicketID != "" {
		t.Fatalf("error state = %#v", failure)
	}
}

func TestKDCListenAuditStopReportsListenerFailure(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	if err := tcp.Close(); err != nil {
		udp.Close()
		t.Fatal(err)
	}
	audit := &lifecycleAudit{}
	server := &Server{AuditModules: []AuditModule{audit}}
	if err := server.ListenAndServe(context.Background(), udp, tcp); err == nil {
		t.Fatal("closed listener unexpectedly served successfully")
	}
	if len(audit.starts) != 1 || !audit.starts[0] ||
		len(audit.stops) != 1 || audit.stops[0] {
		t.Fatalf("lifecycle events = starts %v stops %v", audit.starts, audit.stops)
	}
}

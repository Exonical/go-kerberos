package kdc

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

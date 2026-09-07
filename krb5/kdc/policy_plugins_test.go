package kdc

import (
	"context"
	"testing"
	"time"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

type policyTestModule struct {
	name string
	as   func(*ASPolicyRequest) (KDCPolicyResult, error)
	tgs  func(*TGSPolicyRequest) (KDCPolicyResult, error)
}

func (m policyTestModule) Name() string { return m.name }
func (m policyTestModule) CheckAS(_ context.Context, req *ASPolicyRequest) (KDCPolicyResult, error) {
	if m.as == nil {
		return KDCPolicyResult{}, nil
	}
	return m.as(req)
}
func (m policyTestModule) CheckTGS(_ context.Context, req *TGSPolicyRequest) (KDCPolicyResult, error) {
	if m.tgs == nil {
		return KDCPolicyResult{}, nil
	}
	return m.tgs(req)
}

func TestKDCPolicyModulesConstrainTimesCumulatively(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	end := types.KerberosTime{Time: now.Add(10 * time.Hour), Present: true}
	renew := &types.KerberosTime{Time: now.Add(20 * time.Hour), Present: true}
	server := &Server{KDCPolicyModules: []KDCPolicyModule{
		policyTestModule{name: "first", as: func(*ASPolicyRequest) (KDCPolicyResult, error) {
			return KDCPolicyResult{Lifetime: 2 * time.Hour, RenewLifetime: 4 * time.Hour}, nil
		}},
		policyTestModule{name: "second", as: func(*ASPolicyRequest) (KDCPolicyResult, error) {
			return KDCPolicyResult{Lifetime: time.Hour, RenewLifetime: 3 * time.Hour}, nil
		}},
	}}
	req := ASPolicyRequest{Client: principal.Principal{Components: []string{"alice"}}}
	if err := server.applyASPolicies(protocol.ASReq{}, req.Client, principal.Principal{},
		kdb.PrincipalRecord{}, kdb.PrincipalRecord{}, nil, now, &end, &renew, nil); err != nil {
		t.Fatal(err)
	}
	if got := end.Time.Sub(now); got != time.Hour {
		t.Fatalf("lifetime = %v, want 1h", got)
	}
	if got := renew.Time.Sub(now); got != 3*time.Hour {
		t.Fatalf("renew lifetime = %v, want 3h", got)
	}
}

func TestKDCPolicyDenialUsesModuleCodeAndAuditStatus(t *testing.T) {
	now := time.Unix(2000000001, 0).UTC()
	server, kclient := testServer(t, now)
	server.KDCPolicyModules = []KDCPolicyModule{
		policyTestModule{name: "test", as: func(req *ASPolicyRequest) (KDCPolicyResult, error) {
			if len(req.Client.Components) == 1 && req.Client.Components[0] == "alice" {
				return KDCPolicyResult{Status: "LOCAL_POLICY"}, krberrors.NewKRBError(
					krberrors.ErrorCode(12), "krbtgt/TEST.REALM", "TEST.REALM", now, 0, nil)
			}
			return KDCPolicyResult{}, nil
		}},
	}
	var audit AuditState
	server.AuditModules = []AuditModule{NewFuncAuditModule("capture",
		func(event string, success bool, state AuditState) {
			if event == "as_req" {
				audit = state
			}
		})}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	if _, err := kclient.ASExchange(context.Background(), user, "alice-password"); err == nil ||
		!hasKRBCode(err, 12) {
		t.Fatalf("ASExchange error = %v, want policy code 12", err)
	}
	if audit.Status != "LOCAL_POLICY" || audit.ErrorCode != 12 {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestKDCPolicyLifetimeCapsIssuedASTicket(t *testing.T) {
	now := time.Unix(2000000003, 0).UTC()
	server, kclient := testServer(t, now)
	server.KDCPolicyModules = []KDCPolicyModule{policyTestModule{
		name: "lifetime",
		as: func(*ASPolicyRequest) (KDCPolicyResult, error) {
			return KDCPolicyResult{Lifetime: time.Hour}, nil
		},
		tgs: func(*TGSPolicyRequest) (KDCPolicyResult, error) {
			return KDCPolicyResult{Lifetime: 30 * time.Minute}, nil
		},
	}}
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal,
		Components: []string{"alice"}}
	tgt, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatalf("ASExchange: %v", err)
	}
	if got := tgt.EndTime.Time.Sub(now); got != time.Hour {
		t.Fatalf("TGT lifetime = %v, want 1h", got)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"}}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, service)
	if err != nil {
		t.Fatalf("TGSExchange: %v", err)
	}
	if got := credentials.EndTime.Time.Sub(now); got != 30*time.Minute {
		t.Fatalf("service ticket lifetime = %v, want 30m", got)
	}
}

func TestKDCPolicyTGSRequestIncludesHeaderAndIndicators(t *testing.T) {
	now := time.Unix(2000000002, 0).UTC()
	server := &Server{}
	header := protocol.Ticket{Realm: "TEST.REALM"}
	var got *TGSPolicyRequest
	server.KDCPolicyModules = []KDCPolicyModule{policyTestModule{
		name: "capture",
		tgs: func(req *TGSPolicyRequest) (KDCPolicyResult, error) {
			got = req
			return KDCPolicyResult{}, nil
		},
	}}
	request := protocol.TGSReq{ReqBody: protocol.KDCReqBody{Realm: "TEST.REALM"}}
	if err := server.applyTGSPolicies(request, principal.Principal{}, kdb.PrincipalRecord{},
		header, []string{"ONE_HOUR"}, now, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.AuthIndicators) != 1 ||
		got.AuthIndicators[0] != "ONE_HOUR" || got.HeaderTicket.Realm != header.Realm {
		t.Fatalf("request = %#v", got)
	}
}

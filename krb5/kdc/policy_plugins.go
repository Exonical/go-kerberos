package kdc

import (
	"context"
	stderrors "errors"
	"time"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// KDCPolicyModule applies issuance policy to AS and TGS requests.
type KDCPolicyModule interface {
	Name() string
	CheckAS(context.Context, *ASPolicyRequest) (KDCPolicyResult, error)
	CheckTGS(context.Context, *TGSPolicyRequest) (KDCPolicyResult, error)
}

// ASPolicyRequest contains the validated AS request and database records.
type ASPolicyRequest struct {
	Request        protocol.ASReq
	Client         principal.Principal
	Server         principal.Principal
	ClientRecord   kdb.PrincipalRecord
	ServerRecord   kdb.PrincipalRecord
	AuthIndicators []string
}

// TGSPolicyRequest contains the validated TGS request and ticket context.
type TGSPolicyRequest struct {
	Request        protocol.TGSReq
	Server         principal.Principal
	ServerRecord   kdb.PrincipalRecord
	HeaderTicket   protocol.Ticket
	AuthIndicators []string
}

// KDCPolicyResult contains optional ticket lifetime constraints and audit
// status from a policy module.
type KDCPolicyResult struct {
	Lifetime      time.Duration
	RenewLifetime time.Duration
	Status        string
}

func (s *Server) applyASPolicies(request protocol.ASReq, client, server principal.Principal,
	clientRecord, serverRecord kdb.PrincipalRecord, indicators []string,
	now time.Time, endTime *types.KerberosTime, renewTill **types.KerberosTime,
	auditState *AuditState) error {
	policyRequest := &ASPolicyRequest{
		Request: request, Client: client, Server: server,
		ClientRecord: clientRecord, ServerRecord: serverRecord,
		AuthIndicators: append([]string(nil), indicators...),
	}
	for _, module := range s.KDCPolicyModules {
		if module == nil {
			continue
		}
		result, err := module.CheckAS(context.Background(), policyRequest)
		if result.Status != "" && auditState != nil {
			auditState.Status = result.Status
		}
		if err != nil {
			return err
		}
		constrainTicketTimes(now, result, endTime, renewTill)
	}
	return nil
}

func (s *Server) applyTGSPolicies(request protocol.TGSReq, server principal.Principal,
	serverRecord kdb.PrincipalRecord, headerTicket protocol.Ticket,
	indicators []string, now time.Time, endTime *types.KerberosTime,
	renewTill **types.KerberosTime, auditState *AuditState) error {
	policyRequest := &TGSPolicyRequest{
		Request: request, Server: server, ServerRecord: serverRecord,
		HeaderTicket:   headerTicket,
		AuthIndicators: append([]string(nil), indicators...),
	}
	for _, module := range s.KDCPolicyModules {
		if module == nil {
			continue
		}
		result, err := module.CheckTGS(context.Background(), policyRequest)
		if result.Status != "" && auditState != nil {
			auditState.Status = result.Status
		}
		if err != nil {
			return err
		}
		constrainTicketTimes(now, result, endTime, renewTill)
	}
	return nil
}

func constrainTicketTimes(now time.Time, result KDCPolicyResult,
	endTime *types.KerberosTime, renewTill **types.KerberosTime) {
	if result.Lifetime != 0 && endTime != nil {
		limit := now.Add(result.Lifetime)
		if limit.Before(endTime.Time) {
			endTime.Time = limit
		}
	}
	if result.RenewLifetime != 0 && renewTill != nil && *renewTill != nil {
		limit := now.Add(result.RenewLifetime)
		if limit.Before((*renewTill).Time) {
			(*renewTill).Time = limit
		}
	}
}

func policyErrorCode(err error) int32 {
	code := int32(kdcErrPolicy)
	var kerberosError *krberrors.KRBError
	if stderrors.As(err, &kerberosError) {
		candidate := int32(kerberosError.Code)
		if candidate >= 0 && candidate <= 128 {
			code = candidate
		}
	}
	return code
}

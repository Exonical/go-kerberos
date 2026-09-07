// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"fmt"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func selectServiceKey(enctypes []int32, service kdb.PrincipalRecord) (int32, kdb.Key, bool) {
	for _, enctype := range enctypes {
		if key, ok := service.Keys[enctype]; ok {
			key.Enctype = enctype
			return enctype, key, true
		}
	}
	return 0, kdb.Key{}, false
}

func selectKVNO(record kdb.PrincipalRecord, enctype int32, kvno *uint32) (kdb.Key, bool) {
	key, ok := record.Keys[enctype]
	if ok && (kvno == nil || key.KVNO == *kvno) {
		key.Enctype = enctype
		return key, true
	}
	if kvno != nil {
		for _, historical := range record.PasswordHistory {
			key, ok = historical[enctype]
			if ok && key.KVNO == *kvno {
				key.Enctype = enctype
				return key, true
			}
		}
	}
	return kdb.Key{}, false
}

func authIndicatorsFromElements(elements protocol.AuthorizationData) ([]string, error) {
	var indicators []string
	for _, element := range elements {
		if element.ADType != protocol.ADAuthIndicator {
			continue
		}
		var values []types.UTF8String
		if err := asn1.Unmarshal(element.ADData, &values); err != nil {
			return nil, fmt.Errorf("auth indicators: %w", err)
		}
		for _, value := range values {
			indicators = append(indicators, string(value))
		}
	}
	return indicators, nil
}

func configuredIndicator(indicator string) []string {
	if indicator == "" {
		return nil
	}
	return []string{indicator}
}

func (s *Server) requireAuthError(record kdb.PrincipalRecord, indicators []string,
	armor *fastContext, service *protocol.PrincipalName) []byte {
	required := strings.TrimSpace(record.Strings["require_auth"])
	if required == "" {
		return nil
	}
	present := make(map[string]struct{}, len(indicators))
	for _, indicator := range indicators {
		present[indicator] = struct{}{}
	}
	for _, indicator := range strings.Fields(required) {
		if _, ok := present[indicator]; ok {
			return nil
		}
	}
	text := "Required auth indicators not present in ticket: " + required
	if armor != nil {
		return s.fastErrorResponseWithText(kdcErrPolicy, service, nil,
			armor.nonce, armor, text)
	}
	return s.errorResponseWithText(kdcErrPolicy, service, text)
}

func (s *Server) passwordPolicy(record kdb.PrincipalRecord) (kdb.PolicyRecord, bool) {
	if record.Policy == "" {
		return kdb.PolicyRecord{}, false
	}
	resolver, ok := s.DB.(kdb.PolicyResolver)
	if !ok {
		return kdb.PolicyRecord{}, false
	}
	policy, err := resolver.GetPolicy(record.Policy)
	if err != nil {
		return kdb.PolicyRecord{}, false
	}
	return policy, true
}

func (s *Server) persistLockout(name principal.Principal, record kdb.PrincipalRecord) {
	updater, ok := s.DB.(kdb.LockoutUpdater)
	if !ok {
		return
	}
	_ = updater.UpdateLockout(name, record.FailAuthCount, record.LastFailed, record.LastSuccess)
}

func (s *Server) lockedOut(name principal.Principal, record *kdb.PrincipalRecord) bool {
	policy, ok := s.passwordPolicy(*record)
	if !ok {
		return false
	}
	now := s.now()
	if policy.FailureCountInterval > 0 && !record.LastFailed.IsZero() &&
		!now.Before(record.LastFailed.Add(time.Duration(policy.FailureCountInterval)*time.Second)) {
		record.FailAuthCount = 0
		if recorder, ok := s.DB.(kdb.LockoutRecorder); ok {
			_ = recorder.ResetAuthFailures(name, record.LastFailed)
		} else {
			s.persistLockout(name, *record)
		}
	}
	if policy.MaxFailure == 0 || record.FailAuthCount < policy.MaxFailure {
		return false
	}
	if policy.LockoutDuration == 0 {
		return true
	}
	return now.Before(record.LastFailed.Add(time.Duration(policy.LockoutDuration) * time.Second))
}

func (s *Server) recordPreauthFailure(name principal.Principal, record *kdb.PrincipalRecord) {
	policy, ok := s.passwordPolicy(*record)
	now := s.now()
	interval := time.Duration(0)
	if ok && policy.FailureCountInterval > 0 {
		interval = time.Duration(policy.FailureCountInterval) * time.Second
	}
	if recorder, recorderOK := s.DB.(kdb.LockoutRecorder); recorderOK {
		count, err := recorder.RecordAuthFailure(name, now, interval)
		if err == nil {
			record.FailAuthCount = count
			record.LastFailed = now
			return
		}
	}
	if interval > 0 && !record.LastFailed.IsZero() &&
		!now.Before(record.LastFailed.Add(interval)) {
		record.FailAuthCount = 0
	}
	record.FailAuthCount++
	record.LastFailed = now
	s.persistLockout(name, *record)
}

func (s *Server) recordPreauthSuccess(name principal.Principal, record *kdb.PrincipalRecord) {
	now := s.now()
	if recorder, ok := s.DB.(kdb.LockoutRecorder); ok {
		if err := recorder.RecordAuthSuccess(name, now); err == nil {
			record.FailAuthCount = 0
			record.LastSuccess = now
			return
		}
	}
	record.FailAuthCount = 0
	record.LastSuccess = now
	s.persistLockout(name, *record)
}

func (s *Server) passwordExpired(record kdb.PrincipalRecord) bool {
	return !record.PasswordExpiration.IsZero() && !s.now().Before(record.PasswordExpiration)
}

func (s *Server) passwordExpiredForService(client, service kdb.PrincipalRecord) bool {
	return s.passwordExpired(client) && service.Flags&kdb.PWChangeService == 0
}

// ticketValidity reports whether a presented ticket is usable now, returning
// the KRB_ERROR code to send when it is not.
func (s *Server) ticketValidity(ticket protocol.EncTicketPart) (int32, bool) {
	return s.ticketValidityWithInvalidMode(ticket, false)
}

func (s *Server) ticketValidityWithInvalid(ticket protocol.EncTicketPart) (int32, bool) {
	return s.ticketValidityWithInvalidMode(ticket, true)
}

func (s *Server) ticketValidityWithInvalidMode(ticket protocol.EncTicketPart, allowInvalid bool) (int32, bool) {
	now := s.now()
	if !allowInvalid && ticket.Flags&types.TicketInvalid != 0 {
		return krbAPErrTktNYV, false
	}
	if ticket.StartTime != nil && ticket.StartTime.Present && now.Add(s.skew()).Before(ticket.StartTime.Time) {
		return krbAPErrTktNYV, false
	}
	if ticket.EndTime.Present && now.Add(-s.skew()).After(ticket.EndTime.Time) {
		return krbAPErrTktExpired, false
	}
	return 0, true
}

func (s *Server) ticketEndFrom(till types.KerberosTime, start time.Time) types.KerberosTime {
	return s.ticketEndFromRecords(till, start, nil, nil)
}

func (s *Server) ticketEndFromRecords(till types.KerberosTime, start time.Time,
	client, service *kdb.PrincipalRecord) types.KerberosTime {
	maxLife := s.MaxTicketLife
	if maxLife <= 0 {
		maxLife = 10 * time.Hour
	}
	if client != nil && client.MaxLife > 0 && client.MaxLife < maxLife {
		maxLife = client.MaxLife
	}
	if service != nil && service.MaxLife > 0 && service.MaxLife < maxLife {
		maxLife = service.MaxLife
	}
	end := start.Add(maxLife)
	if !ticketTillSet(till) {
		if s.DefaultTicketLife > 0 && s.DefaultTicketLife < maxLife {
			end = start.Add(s.DefaultTicketLife)
		}
	} else if till.Time.Before(end) {
		end = till.Time
	}
	if end.Before(start) {
		end = start
	}
	return types.KerberosTime{Time: end.Truncate(time.Second), Present: true}
}

func (s *Server) renewTill(options types.KDCOptions, requested *types.KerberosTime, till types.KerberosTime, start, end time.Time) *types.KerberosTime {
	return s.renewTillRecords(options, requested, till, start, end, nil, nil)
}

func (s *Server) renewTillRecords(options types.KDCOptions, requested *types.KerberosTime,
	till types.KerberosTime, start, end time.Time,
	client, service *kdb.PrincipalRecord) *types.KerberosTime {
	renewable := options&types.KDCRenewable != 0
	hasTill := ticketTillSet(till)
	hasRequested := requested != nil && ticketTillSet(*requested)
	if !renewable && (options&types.KDCRenewableOK == 0 || (hasTill && !till.Time.After(end))) {
		return nil
	}
	target := start.Add(s.MaxRenewableLife)
	if renewable {
		switch {
		case hasRequested:
			target = requested.Time
		case s.DefaultRenewableLife > 0:
			target = start.Add(s.DefaultRenewableLife)
		case hasTill:
			target = till.Time
		}
	} else if hasTill {
		target = till.Time
	} else if s.DefaultRenewableLife > 0 {
		target = start.Add(s.DefaultRenewableLife)
	}
	if !target.After(end) && !renewable {
		return nil
	}
	maxRenewableLife := s.MaxRenewableLife
	if client != nil && client.MaxRenew > 0 && client.MaxRenew < maxRenewableLife {
		maxRenewableLife = client.MaxRenew
	}
	if service != nil && service.MaxRenew > 0 && service.MaxRenew < maxRenewableLife {
		maxRenewableLife = service.MaxRenew
	}
	if maxRenewableLife <= 0 {
		return nil
	}
	capTime := start.Add(maxRenewableLife)
	if target.After(capTime) {
		target = capTime
	}
	if !target.After(end) && !renewable {
		return nil
	}
	if !target.After(start) {
		return nil
	}
	result := types.KerberosTime{Time: target.Truncate(time.Second), Present: true}
	return &result
}

func ticketTillSet(till types.KerberosTime) bool {
	return till.Present && !till.Time.Equal(time.Unix(0, 0).UTC())
}

func (s *Server) applyFlagPolicy(flags *types.TicketFlags) {
	if s.Policy == nil {
		return
	}
	if !s.Policy.AllowForwardable {
		*flags &^= types.TicketForwardable
	}
	if !s.Policy.AllowProxiable {
		*flags &^= types.TicketProxiable
	}
	if !s.Policy.AllowRenewable {
		*flags &^= types.TicketRenewable
	}
}

func applyPrincipalFlagPolicy(flags *types.TicketFlags, client, service *kdb.PrincipalRecord) {
	if client != nil && client.Flags&kdb.DisallowForwardable != 0 {
		*flags &^= types.TicketForwardable
	}
	if service != nil && service.Flags&kdb.DisallowForwardable != 0 {
		*flags &^= types.TicketForwardable
	}
	if client != nil && client.Flags&kdb.DisallowProxiable != 0 {
		*flags &^= types.TicketProxiable
	}
	if service != nil && service.Flags&kdb.DisallowProxiable != 0 {
		*flags &^= types.TicketProxiable
	}
	if client != nil && client.Flags&kdb.DisallowRenewable != 0 {
		*flags &^= types.TicketRenewable
	}
	if service != nil && service.Flags&kdb.DisallowRenewable != 0 {
		*flags &^= types.TicketRenewable
	}
}

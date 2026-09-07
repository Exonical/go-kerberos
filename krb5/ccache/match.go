package ccache

import (
	"bytes"
	"errors"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

var errCredentialNotFound = errors.New("ccache: credential not found")

func credentialMatchesMIT(value, tag Credential, flags uint32) bool {
	if !samePrincipal(value.Client, tag.Client, false) {
		return false
	}
	if !samePrincipal(value.Server, tag.Server, flags&MITMatchServerName != 0) {
		return false
	}
	if flags&MITMatchIsSKey != 0 && value.IsSKey != tag.IsSKey {
		return false
	}
	if flags&MITMatchIsSKey == 0 && value.IsSKey {
		return false
	}
	if flags&MITMatchFlagsExact != 0 && value.TicketFlags != tag.TicketFlags {
		return false
	}
	if flags&MITMatchFlags != 0 &&
		value.TicketFlags&tag.TicketFlags != tag.TicketFlags {
		return false
	}
	if flags&MITMatchTimesExact != 0 &&
		(value.AuthTime != tag.AuthTime || value.StartTime != tag.StartTime ||
			value.EndTime != tag.EndTime || value.RenewTill != tag.RenewTill) {
		return false
	}
	if flags&MITMatchTimes != 0 {
		if tag.EndTime != 0 && value.EndTime < tag.EndTime {
			return false
		}
		if tag.RenewTill != 0 && value.RenewTill < tag.RenewTill {
			return false
		}
	}
	if flags&MITMatchAuthData != 0 && !sameAuthData(value.AuthData, tag.AuthData) {
		return false
	}
	if flags&MITMatchSecondTicket != 0 &&
		!bytes.Equal(value.SecondTicket, tag.SecondTicket) {
		return false
	}
	if flags&MITMatchKeyType != 0 && value.Enctype != tag.Enctype {
		return false
	}
	if flags&MITMatchSupportedKTypes != 0 {
		if !isSupportedEnctype(value.Enctype) {
			return false
		}
		if tag.Enctype != 0 && value.Enctype != tag.Enctype {
			return false
		}
	}
	return true
}

func samePrincipal(value, tag principal.Principal, nameOnly bool) bool {
	if !nameOnly && value.Realm != tag.Realm {
		return false
	}
	if len(value.Components) != len(tag.Components) {
		return false
	}
	for i := range value.Components {
		if value.Components[i] != tag.Components[i] {
			return false
		}
	}
	return true
}

func sameAuthData(value, tag []AuthData) bool {
	if len(value) != len(tag) {
		return false
	}
	for i := range value {
		if value[i].Type != tag[i].Type || !bytes.Equal(value[i].Data, tag[i].Data) {
			return false
		}
	}
	return true
}

func isSupportedEnctype(value int32) bool {
	_, err := crypto.NewRegistry().Get(value)
	return err == nil
}

func retrieveCredentials(credentials []Credential, match Credential, flags uint32) (Credential, error) {
	return retrieveCredentialsWithOrder(credentials, match, flags, supportedEnctypes)
}

func retrieveCredentialsWithOrder(credentials []Credential, match Credential, flags uint32, order []int32) (Credential, error) {
	var selected Credential
	selectedRank := len(order) + 1
	found := false
	for _, candidate := range credentials {
		if !credentialMatchesMIT(candidate, match, flags) {
			continue
		}
		if flags&MITMatchSupportedKTypes == 0 {
			return candidate, nil
		}
		rank := supportedEnctypeRankIn(candidate.Enctype, order)
		if rank == len(order) {
			continue
		}
		if !found || rank < selectedRank {
			selected = candidate
			selectedRank = rank
			found = true
		}
	}
	if !found {
		return Credential{}, errCredentialNotFound
	}
	return selected, nil
}

var supportedEnctypes = []int32{
	crypto.EnctypeAES256SHA1,
	crypto.EnctypeAES128SHA1,
	crypto.EnctypeAES256SHA384,
	crypto.EnctypeAES128SHA256,
	crypto.EnctypeCamellia128,
	crypto.EnctypeCamellia256,
}

func supportedEnctypeRank(value int32) int {
	return supportedEnctypeRankIn(value, supportedEnctypes)
}

func supportedEnctypeRankIn(value int32, order []int32) int {
	for i, candidate := range order {
		if candidate == value {
			return i
		}
	}
	return len(order)
}

func supportedEnctypeOrder(h *Handle) []int32 {
	candidates := supportedEnctypes
	if h != nil && h.cfg != nil {
		if len(h.cfg.DefaultTGSEnctypes) > 0 {
			candidates = h.cfg.DefaultTGSEnctypes
		} else if len(h.cfg.PermittedEnctypes) > 0 {
			candidates = h.cfg.PermittedEnctypes
		}
	}
	registry := crypto.NewRegistry()
	result := make([]int32, 0, len(candidates))
	for _, candidate := range candidates {
		if _, err := registry.Get(candidate); err == nil {
			result = append(result, candidate)
		}
	}
	return result
}

func removeCredentials(cache *Cache, match Credential, flags uint32) error {
	if cache == nil {
		return errors.New("ccache: nil cache")
	}
	remaining := cache.Credentials[:0]
	removed := false
	for _, candidate := range cache.Credentials {
		if credentialMatchesMIT(candidate, match, flags) {
			removed = true
			continue
		}
		remaining = append(remaining, candidate)
	}
	if !removed {
		return errCredentialNotFound
	}
	cache.Credentials = remaining
	return nil
}

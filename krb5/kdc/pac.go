// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	stderrors "errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func (s *Server) pacPrivsvrKey() (kdb.Key, bool) {
	name := principal.Principal{
		Realm: s.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", s.Realm},
	}
	record, ok, err := s.DB.Lookup(name)
	if err != nil || !ok {
		return kdb.Key{}, false
	}
	enctypes := make([]int, 0, len(record.Keys))
	registry := crypto.NewRegistry()
	for enctype, key := range record.Keys {
		if key.KVNO != 0 && record.KVNO != 0 && key.KVNO != record.KVNO {
			continue
		}
		if _, err := registry.Get(enctype); err == nil {
			enctypes = append(enctypes, int(enctype))
		}
	}
	sort.Ints(enctypes)
	if len(enctypes) == 0 {
		return kdb.Key{}, false
	}
	key := record.Keys[int32(enctypes[0])]
	key.Enctype = int32(enctypes[0])
	return key, true
}

func (s *Server) issuePAC(ticketPart *protocol.EncTicketPart, client, service principal.Principal,
	headerKey, serviceKey kdb.Key, serviceTicket bool, replaceClient bool) error {
	return s.issuePACWithOptions(ticketPart, client, service, headerKey, serviceKey,
		serviceTicket, replaceClient, nil, nil, nil)
}

func (s *Server) issuePACWithOptions(ticketPart *protocol.EncTicketPart, client, service principal.Principal,
	headerKey, serviceKey kdb.Key, serviceTicket bool, replaceClient bool,
	replacedReplyKey *kdb.Key, delegationEvidence *principal.Principal,
	pacVerifyKey *kdb.Key) error {
	if !s.EnablePAC || s.DisablePAC {
		return nil
	}
	privKey, ok := s.pacPrivsvrKey()
	if !ok {
		// AS TGTs use the same krbtgt key for both PAC signatures.
		if len(service.Components) == 2 && service.Components[0] == "krbtgt" {
			privKey = serviceKey
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("PAC: no usable krbtgt key for PAC signatures")
	}
	privEType, err := crypto.NewRegistry().Get(privKey.Enctype)
	if err != nil {
		return err
	}
	verifyKey := headerKey
	if pacVerifyKey != nil {
		verifyKey = *pacVerifyKey
	}
	headerEType, err := crypto.NewRegistry().Get(verifyKey.Enctype)
	if err != nil {
		return err
	}
	headerPACKey := pac.Key{EType: headerEType, Key: verifyKey.Key}
	serviceEType, err := crypto.NewRegistry().Get(serviceKey.Enctype)
	if err != nil {
		return err
	}
	serverPACKey := pac.Key{EType: serviceEType, Key: serviceKey.Key}
	privPACKey := pac.Key{EType: privEType, Key: privKey.Key}
	p, err := pac.FromAuthorizationData(ticketPart.AuthorizationData)
	if err != nil {
		if !stderrors.Is(err, pac.ErrNotFound) {
			return err
		}
		p = pac.New()
	} else if err := p.Verify(headerPACKey, privPACKey); err != nil {
		return err
	}
	if replaceClient {
		if err := p.SetClientInfo(ticketPart.AuthTime.Time, client); err != nil {
			return err
		}
	}
	if len(p.Buffers) == 0 && s.GeneratePACIdentity != nil {
		identity, err := s.GeneratePACIdentity(client, service)
		if err != nil {
			return err
		}
		if identity != nil {
			if identity.LogonInfo != nil {
				logonInfo, err := identity.LogonInfo.MarshalBinary()
				if err != nil {
					return err
				}
				p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.LogonInfoBuffer, Data: logonInfo})
			}
			upn := pac.UPNDNSInfoData{
				UPN: identity.UPN, DNSDomainName: identity.DNSDomainName,
				SAMName: identity.SAMName, Flags: identity.Flags,
			}
			if identity.Flags&pac.UPNDNSInfoHasSAMNameAndSID != 0 {
				sid := identity.SID
				upn.SID = &sid
			}
			data, err := upn.MarshalBinary()
			if err != nil {
				return err
			}
			p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.UPNDNSInfo, Data: data})
		}
	} else if len(p.Buffers) == 0 && s.GeneratePAC != nil {
		logonInfo, err := s.GeneratePAC(client, service)
		if err != nil {
			return err
		}
		p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.LogonInfoBuffer, Data: logonInfo})
	} else if len(p.Buffers) == 0 {
		p.Buffers = append(p.Buffers, pac.Buffer{Type: pac.LogonInfoBuffer})
	}
	if replacedReplyKey != nil && s.GeneratePACCredentials != nil {
		plaintext, enctype, err := s.GeneratePACCredentials(client, service, *replacedReplyKey)
		if err != nil {
			return err
		}
		if enctype != replacedReplyKey.Enctype {
			return fmt.Errorf("PAC: credentials enctype %d does not match reply key enctype %d",
				enctype, replacedReplyKey.Enctype)
		}
		credentialEType, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return err
		}
		credentials, err := pac.EncryptCredentialInfo(credentialEType,
			replacedReplyKey.Key, plaintext)
		if err != nil {
			return err
		}
		data, err := credentials.MarshalBinary()
		if err != nil {
			return err
		}
		p.SetBuffer(pac.CredentialInfoBuffer, data)
	}
	if delegationEvidence != nil {
		var info pac.DelegationInfo
		if data, ok := p.Buffer(pac.DelegationInfoBuffer); ok {
			info, err = pac.ParseDelegationInfo(data)
			if err != nil {
				return err
			}
		}
		info.ProxyTarget = strings.Join(service.Components, "/")
		info.TransitedServices = append(info.TransitedServices, delegationEvidence.String())
		data, err := info.MarshalBinary()
		if err != nil {
			return err
		}
		p.SetBuffer(pac.DelegationInfoBuffer, data)
	}
	var dummyTicket []byte
	if serviceTicket {
		originalAuthData := ticketPart.AuthorizationData
		dummyAuthData, err := pac.AddDummyAuthorizationData(originalAuthData)
		if err != nil {
			return err
		}
		ticketPart.AuthorizationData = dummyAuthData
		dummyTicket = marshalDER(*ticketPart)
		ticketPart.AuthorizationData = originalAuthData
	}
	var encoded []byte
	if dummyTicket != nil {
		encoded, err = p.SignWithTicket(ticketPart.AuthTime.Time, &client,
			serverPACKey, privPACKey, dummyTicket)
	} else {
		encoded, err = p.Sign(ticketPart.AuthTime.Time, &client,
			serverPACKey, privPACKey, serviceTicket)
	}
	if err != nil {
		return err
	}
	authdata, err := pac.AddAuthorizationData(ticketPart.AuthorizationData, encoded)
	if err != nil {
		return err
	}
	ticketPart.AuthorizationData = authdata
	return nil
}

func stripCAMMAC(data protocol.AuthorizationData) (protocol.AuthorizationData, error) {
	out := make(protocol.AuthorizationData, 0, len(data))
	for _, outer := range data {
		if outer.ADType != protocol.ADIfRelevant {
			out = append(out, outer)
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(outer.ADData, &inner); err != nil {
			return nil, fmt.Errorf("CAMMAC IF-RELEVANT: %w", err)
		}
		filtered := make(protocol.AuthorizationData, 0, len(inner))
		for _, entry := range inner {
			if entry.ADType != protocol.ADCAMMAC {
				filtered = append(filtered, entry)
			}
		}
		if len(filtered) == len(inner) {
			out = append(out, outer)
			continue
		}
		if len(filtered) != 0 {
			encoded, err := asn1.Marshal(filtered)
			if err != nil {
				return nil, fmt.Errorf("CAMMAC IF-RELEVANT: %w", err)
			}
			out = append(out, protocol.AuthorizationDataEntry{
				ADType: protocol.ADIfRelevant, ADData: encoded,
			})
		}
	}
	return out, nil
}

func (s *Server) issueCAMMAC(ticketPart *protocol.EncTicketPart, serviceKey kdb.Key,
	verifiedElements protocol.AuthorizationData, assertedIndicators []string) error {
	var elements protocol.AuthorizationData
	var err error
	if len(assertedIndicators) > 0 {
		indicators := make([]types.UTF8String, len(assertedIndicators))
		for i, indicator := range assertedIndicators {
			indicators[i] = types.UTF8String(indicator)
		}
		encodedIndicators, marshalErr := asn1.Marshal(indicators)
		if marshalErr != nil {
			return fmt.Errorf("CAMMAC auth indicators: %w", marshalErr)
		}
		elements = protocol.AuthorizationData{{
			ADType: protocol.ADAuthIndicator, ADData: encodedIndicators,
		}}
	} else if verifiedElements != nil {
		elements = verifiedElements
	} else {
		elements, err = cammac.ProtectedElements(ticketPart.AuthorizationData)
		if err != nil && !stderrors.Is(err, cammac.ErrNotFound) {
			return err
		}
		if stderrors.Is(err, cammac.ErrNotFound) {
			return nil
		}
	}
	kdcKey, ok := s.freshnessKey(nil)
	if !ok {
		return fmt.Errorf("CAMMAC: no usable local krbtgt key")
	}
	base, err := stripCAMMAC(ticketPart.AuthorizationData)
	if err != nil {
		return err
	}
	ticketPart.AuthorizationData = base
	wrapped, err := cammac.Marshal(elements, *ticketPart,
		protocol.EncryptionKey{KeyType: kdcKey.Enctype, KeyValue: kdcKey.Key},
		protocol.EncryptionKey{KeyType: serviceKey.Enctype, KeyValue: serviceKey.Key},
		kdcKey.KVNO)
	if err != nil {
		return err
	}
	ticketPart.AuthorizationData = append(ticketPart.AuthorizationData, wrapped...)
	return nil
}

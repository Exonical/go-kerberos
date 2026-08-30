package kdc

import (
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/pkinit"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	certAuthClientNameMismatch     int32 = 75
	certAuthCertificateMismatch    int32 = 66
	certAuthInconsistentKeyPurpose int32 = 77
)

// CertAuthDecision is the result of one PKINIT certificate authorization
// module.
type CertAuthDecision uint8

const (
	// CertAuthPass leaves authorization to other modules.
	CertAuthPass CertAuthDecision = iota
	// CertAuthAccept authorizes the certificate.
	CertAuthAccept
	// CertAuthHWAuth authorizes and marks the ticket hardware-authenticated.
	CertAuthHWAuth
	// CertAuthHWAuthPass marks hardware authentication but does not authorize.
	CertAuthHWAuthPass
)

// CertAuthModule authorizes a verified PKINIT client certificate.
type CertAuthModule interface {
	Authorize(cert *x509.Certificate, client principal.Principal,
		entry *kdb.PrincipalRecord) (CertAuthDecision, []string, error)
}

// CertAuthError carries the KDC error code a certauth module wants returned.
type CertAuthError struct {
	Code int32
	Err  error
}

func (e *CertAuthError) Error() string {
	if e == nil || e.Err == nil {
		return "certificate authorization failed"
	}
	return e.Err.Error()
}

func (e *CertAuthError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func certAuthError(code int32, text string) error {
	return &CertAuthError{Code: code, Err: errors.New(text)}
}

type pkinitSANModule struct{}

func (pkinitSANModule) Authorize(cert *x509.Certificate, client principal.Principal,
	entry *kdb.PrincipalRecord) (CertAuthDecision, []string, error) {
	principals, err := pkinit.ClientSANs(cert)
	if errors.Is(err, pkinit.ErrClientSANNotFound) {
		return CertAuthPass, nil, nil
	}
	if err != nil {
		return CertAuthPass, nil, certAuthError(certAuthClientNameMismatch,
			"pkinit: malformed client subject alternative name")
	}
	for _, got := range principals {
		if got.Realm != client.Realm || len(got.Components) != len(client.Components) {
			continue
		}
		matched := true
		for i := range got.Components {
			if got.Components[i] != client.Components[i] {
				matched = false
				break
			}
		}
		if matched {
			return CertAuthAccept, nil, nil
		}
	}
	return CertAuthPass, nil, certAuthError(certAuthClientNameMismatch,
		"pkinit: client certificate SAN principal mismatch")
}

type pkinitEKUModule struct{}

func (pkinitEKUModule) Authorize(cert *x509.Certificate, client principal.Principal,
	entry *kdb.PrincipalRecord) (CertAuthDecision, []string, error) {
	if !pkinit.HasClientAuthEKU(cert) {
		return CertAuthPass, nil, certAuthError(certAuthInconsistentKeyPurpose,
			"pkinit: client certificate lacks id-pkinit-KPClientAuth EKU")
	}
	return CertAuthPass, nil, nil
}

type dbMatchModule struct{}

func (dbMatchModule) Authorize(cert *x509.Certificate, client principal.Principal,
	entry *kdb.PrincipalRecord) (CertAuthDecision, []string, error) {
	if entry == nil || entry.Strings == nil {
		return CertAuthPass, nil, nil
	}
	rule := entry.Strings["pkinit_cert_match"]
	if rule == "" {
		return CertAuthPass, nil, nil
	}
	matched, err := MatchCertificate(cert, rule)
	if err != nil {
		return CertAuthPass, nil, err
	}
	if !matched {
		return CertAuthPass, nil, certAuthError(certAuthCertificateMismatch,
			"pkinit: client certificate does not match pkinit_cert_match")
	}
	return CertAuthAccept, nil, nil
}

// MatchCertificate evaluates MIT's pkinit_cert_match expression syntax for a
// single certificate. Subject and issuer use the certificate's RDN order and
// comma/plus separators, matching X509_NAME_print_ex(..., XN_FLAG_SEP_COMMA_PLUS).
func MatchCertificate(cert *x509.Certificate, rule string) (bool, error) {
	if cert == nil {
		return false, errors.New("pkinit: missing certificate")
	}
	if rule == "" {
		return false, errors.New("pkinit: empty certificate match rule")
	}
	relation := "and"
	if strings.HasPrefix(rule, "&&") {
		rule = rule[2:]
	} else if strings.HasPrefix(rule, "||") {
		relation = "or"
		rule = rule[2:]
	}
	if rule == "" {
		return false, errors.New("pkinit: empty certificate match rule")
	}
	type component struct {
		kind, value string
	}
	var components []component
	for len(rule) > 0 {
		start := strings.IndexByte(rule, '<')
		if start != 0 {
			return false, errors.New("pkinit: invalid certificate match keyword")
		}
		end := strings.IndexByte(rule[1:], '>')
		if end < 0 {
			return false, errors.New("pkinit: invalid certificate match keyword")
		}
		end++
		kind := rule[:end+1]
		switch kind {
		case "<SUBJECT>", "<ISSUER>", "<SAN>", "<EKU>", "<KU>":
		default:
			return false, fmt.Errorf("pkinit: unsupported certificate match keyword %s", kind)
		}
		rule = rule[end+1:]
		next := nextCertificateMatchKeyword(rule)
		value := rule
		if next >= 0 {
			value, rule = rule[:next], rule[next:]
		} else {
			rule = ""
		}
		if value == "" {
			return false, errors.New("pkinit: missing certificate match value")
		}
		components = append(components, component{kind, value})
	}
	matches := make([]bool, len(components))
	var matchErr error
	for i, c := range components {
		switch c.kind {
		case "<SUBJECT>":
			matches[i], matchErr = matchRegexp(c.value, certificateName(
				cert.Subject, cert.RawSubject))
		case "<ISSUER>":
			matches[i], matchErr = matchRegexp(c.value, certificateName(
				cert.Issuer, cert.RawIssuer))
		case "<SAN>":
			matches[i], matchErr = matchSAN(cert, c.value)
		case "<EKU>":
			bits, listErr := parseMatchList(c.value, ekuMatchBits)
			matchErr = listErr
			if matchErr != nil {
				return false, matchErr
			}
			matches[i] = bits&certificateEKUBits(cert) == bits
		case "<KU>":
			bits, listErr := parseMatchList(c.value, kuMatchBits)
			matchErr = listErr
			if matchErr != nil {
				return false, matchErr
			}
			matches[i] = bits&certificateKUBits(cert) == bits
		}
		if matchErr != nil {
			return false, matchErr
		}
	}
	if relation == "or" {
		for _, matched := range matches {
			if matched {
				return true, nil
			}
		}
		return false, nil
	}
	for _, matched := range matches {
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func nextCertificateMatchKeyword(rule string) int {
	keywords := []string{"<SUBJECT>", "<ISSUER>", "<SAN>", "<EKU>", "<KU>"}
	for offset := strings.IndexByte(rule, '<'); offset >= 0; {
		for _, keyword := range keywords {
			if strings.HasPrefix(rule[offset:], keyword) {
				return offset
			}
		}
		next := strings.IndexByte(rule[offset+1:], '<')
		if next < 0 {
			return -1
		}
		offset += next + 1
	}
	return -1
}

func matchRegexp(pattern, value string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(value), nil
}

func matchSAN(cert *x509.Certificate, pattern string) (bool, error) {
	regexpMatcher, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	principals, err := pkinit.ClientSANs(cert)
	if err == nil {
		for _, p := range principals {
			if regexpMatcher.MatchString(p.String()) {
				return true, nil
			}
		}
	}
	for _, value := range certificateUPNSANs(cert) {
		if regexpMatcher.MatchString(value) {
			return true, nil
		}
	}
	return false, nil
}

var certificateAttributeNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC",
}

func certificateName(name pkix.Name, raw []byte) string {
	if len(raw) == 0 {
		return name.String()
	}
	var sequence pkix.RDNSequence
	if _, err := stdasn1.Unmarshal(raw, &sequence); err != nil {
		return name.String()
	}
	var result strings.Builder
	for i, set := range sequence {
		if i > 0 {
			result.WriteByte(',')
		}
		for j, attribute := range set {
			if j > 0 {
				result.WriteByte('+')
			}
			if label, ok := certificateAttributeNames[attribute.Type.String()]; ok {
				result.WriteString(label)
			} else {
				result.WriteString(attribute.Type.String())
			}
			result.WriteByte('=')
			result.WriteString(escapeCertificateNameValue(attribute.Value))
		}
	}
	return result.String()
}

func escapeCertificateNameValue(value any) string {
	text, ok := value.(string)
	if !ok {
		if raw, ok := value.(stdasn1.RawValue); ok {
			text = string(raw.Bytes)
		} else {
			text = fmt.Sprint(value)
		}
	}
	return text
}

const microsoftUPNSANOID = "1.3.6.1.4.1.311.20.2.3"

func certificateUPNSANs(cert *x509.Certificate) []string {
	var result []string
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal([]int{2, 5, 29, 17}) {
			continue
		}
		sequence, err := derRawFields(extension.Value)
		if err != nil || len(sequence) != 1 ||
			sequence[0].Class != 0 || sequence[0].Tag != 16 {
			continue
		}
		names, err := derRawFields(sequence[0].Bytes)
		if err != nil {
			continue
		}
		for _, name := range names {
			if name.Class != 2 || name.Tag != 0 {
				continue
			}
			otherName, err := derRawFields(name.Bytes)
			if err != nil || len(otherName) != 2 {
				continue
			}
			var oid stdasn1.ObjectIdentifier
			if _, err := stdasn1.Unmarshal(otherName[0].FullBytes, &oid); err != nil ||
				oid.String() != microsoftUPNSANOID {
				continue
			}
			if otherName[1].Class != 2 || otherName[1].Tag != 0 {
				continue
			}
			value, err := derRawFields(otherName[1].Bytes)
			if err != nil || len(value) != 1 {
				continue
			}
			if text, ok := derString(value[0]); ok {
				if strings.IndexByte(text, 0) >= 0 {
					continue
				}
				result = append(result, text)
			}
		}
	}
	return result
}

func derRawFields(data []byte) ([]stdasn1.RawValue, error) {
	var fields []stdasn1.RawValue
	for len(data) > 0 {
		var field stdasn1.RawValue
		rest, err := stdasn1.Unmarshal(data, &field)
		if err != nil || len(rest) == len(data) {
			if err == nil {
				err = errors.New("pkinit: malformed certificate SAN")
			}
			return nil, err
		}
		fields = append(fields, field)
		data = rest
	}
	return fields, nil
}

func derString(value stdasn1.RawValue) (string, bool) {
	switch value.Tag {
	case 12, 19, 20, 22:
		return string(value.Bytes), true
	case 30:
		if len(value.Bytes)%2 != 0 {
			return "", false
		}
		units := make([]uint16, len(value.Bytes)/2)
		for i := range units {
			units[i] = uint16(value.Bytes[2*i])<<8 | uint16(value.Bytes[2*i+1])
		}
		return string(utf16.Decode(units)), true
	default:
		return "", false
	}
}

var ekuMatchBits = map[string]uint32{
	"pkinit": 1 << 0, "mssclogin": 1 << 1,
	"clientauth": 1 << 2, "emailprotection": 1 << 3,
}

var kuMatchBits = map[string]uint32{
	"digitalsignature": 1 << 0, "keyencipherment": 1 << 1,
}

func parseMatchList(value string, names map[string]uint32) (uint32, error) {
	var bits uint32
	for _, item := range strings.Split(value, ",") {
		bit, ok := names[strings.ToLower(item)]
		if !ok || item == "" {
			return 0, fmt.Errorf("pkinit: unsupported certificate match value %q", item)
		}
		bits |= bit
	}
	return bits, nil
}

func certificateEKUBits(cert *x509.Certificate) uint32 {
	var bits uint32
	for _, oid := range cert.UnknownExtKeyUsage {
		switch oid.String() {
		case "1.3.6.1.5.2.3.4":
			bits |= ekuMatchBits["pkinit"]
		case "1.3.6.1.4.1.311.20.2.2":
			bits |= ekuMatchBits["mssclogin"]
		}
	}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			bits |= ekuMatchBits["clientauth"]
		case x509.ExtKeyUsageEmailProtection:
			bits |= ekuMatchBits["emailprotection"]
		}
	}
	return bits
}

func certificateKUBits(cert *x509.Certificate) uint32 {
	var bits uint32
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		bits |= kuMatchBits["digitalsignature"]
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		bits |= kuMatchBits["keyencipherment"]
	}
	return bits
}

func defaultCertAuthModules(extra []CertAuthModule) []CertAuthModule {
	modules := []CertAuthModule{pkinitSANModule{}, pkinitEKUModule{}, dbMatchModule{}}
	return append(modules, extra...)
}

func (s *Server) authorizeCertificate(cert *x509.Certificate,
	client principal.Principal, entry *kdb.PrincipalRecord) (bool, bool, []string, error) {
	return authorizeCertificateModules(defaultCertAuthModules(s.CertAuthModules),
		cert, client, entry)
}

func authorizeCertificateModules(modules []CertAuthModule, cert *x509.Certificate,
	client principal.Principal, entry *kdb.PrincipalRecord) (bool, bool, []string, error) {
	accepted, hwauth := false, false
	var indicators []string
	for _, module := range modules {
		if module == nil {
			continue
		}
		decision, moduleIndicators, err := module.Authorize(cert, client, entry)
		indicators = append(indicators, moduleIndicators...)
		if err != nil {
			return false, hwauth, indicators, err
		}
		switch decision {
		case CertAuthAccept:
			accepted = true
		case CertAuthHWAuth:
			accepted, hwauth = true, true
		case CertAuthHWAuthPass:
			hwauth = true
		case CertAuthPass:
		default:
			return false, hwauth, indicators,
				errors.New("pkinit: invalid certificate authorization decision")
		}
	}
	if !accepted {
		return false, hwauth, indicators, certAuthError(certAuthClientNameMismatch,
			"pkinit: no certificate authorization module accepted the certificate")
	}
	return accepted, hwauth, indicators, nil
}

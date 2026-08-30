// Package pkinit implements the Diffie-Hellman profile of RFC 4556 PKINIT.
package pkinit

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	krbcrypto "github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

// ErrClientSANNotFound indicates that a certificate has no id-pkinit-san
// principal SAN.  It is distinct from malformed SAN data so certauth callers
// can pass certificates without a SAN to another authorization module.
var ErrClientSANNotFound = errors.New("pkinit: client certificate has no id-pkinit-san SAN")

const (
	PADataASReq = 16
	PADataASRep = 17
	// PADataASFreshness is the RFC 8070 freshness-token padata type.
	PADataASFreshness = 150
	DHGroup14         = 14
	DHGroup2          = 2
)

// RFC 8636 PKINIT KDF algorithm identifiers, represented as the contents of
// an OBJECT IDENTIFIER as they are in MIT krb5's krb5_data values.
var (
	KDFSHA1   = []byte{0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x01}
	KDFSHA256 = []byte{0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x02}
	KDFSHA512 = []byte{0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x03}
)

// SupportedKDFAlgorithmIDs returns MIT's preference order.
func SupportedKDFAlgorithmIDs() [][]byte {
	return [][]byte{append([]byte(nil), KDFSHA256...), append([]byte(nil), KDFSHA1...), append([]byte(nil), KDFSHA512...)}
}

// PickKDFAlgorithm selects the first algorithm in the KDC's preference list
// which is present in the client's supported list.
func PickKDFAlgorithm(client [][]byte) []byte {
	for _, serverID := range SupportedKDFAlgorithmIDs() {
		for _, clientID := range client {
			if bytes.Equal(serverID, clientID) {
				return serverID
			}
		}
	}
	return nil
}

var (
	// RFC 3526 MODP group 14.
	group14P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	group14G    = big.NewInt(2)
)

// AuthPack is the RFC 4556 signed authentication payload.
type AuthPack struct {
	Authenticator PKAuthenticator
	PublicValue   []byte
	// SupportedCMSTypes contains the complete DER AlgorithmIdentifier values
	// advertised by the client, retained for round-trip fidelity.
	SupportedCMSTypes [][]byte
	DHNonce           []byte
	SupportedKDFs     [][]byte
}

// PKAuthenticator authenticates an AS-REQ body to the KDC.
type PKAuthenticator struct {
	Cusec      int32
	CTime      time.Time
	Nonce      uint32
	PAChecksum []byte
	// FreshnessToken is the opaque RFC 8070 token returned by the KDC.
	FreshnessToken []byte
}

// VerifiedPAASReq contains the authenticated PKINIT request data needed by a
// KDC. Certificate trust and principal authorization are checked separately.
type VerifiedPAASReq struct {
	Authenticator PKAuthenticator
	PublicValue   []byte
	SupportedKDFs [][]byte
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
	Signed        bool
}

// Client is an ephemeral PKINIT DH exchange state.
type Client struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	Private     *big.Int
	Public      *big.Int
	Nonce       uint32
	Anonymous   bool
}

// NewClient creates an RFC 4556 group-14 DH exchange state.
func NewClient(cert *x509.Certificate, signer crypto.Signer) (*Client, error) {
	if cert == nil || signer == nil {
		return nil, errors.New("pkinit: certificate and signer are required")
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, errors.New("pkinit: only RSA signing keys are supported")
	}
	x, err := newDHPrivate()
	if err != nil {
		return nil, err
	}
	return &Client{Certificate: cert, Signer: signer, Private: x, Public: new(big.Int).Exp(group14G, x, group14P)}, nil
}

// NewAnonymousClient creates an unsigned RFC 6112 anonymous PKINIT DH state.
func NewAnonymousClient() (*Client, error) {
	x, err := newDHPrivate()
	if err != nil {
		return nil, err
	}
	return &Client{Private: x, Public: new(big.Int).Exp(group14G, x, group14P), Anonymous: true}, nil
}

func newDHPrivate() (*big.Int, error) {
	x, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Sub(group14P, big.NewInt(2)))
	if err != nil {
		return nil, fmt.Errorf("pkinit: generate DH private value: %w", err)
	}
	x.Add(x, big.NewInt(2))
	return x, nil
}

// BuildPAASReq constructs PA-PK-AS-REQ. bodyDER must be the exact DER bytes
// of the AS-REQ KDC-REQ-BODY received by the KDC.
func (c *Client) BuildPAASReq(bodyDER []byte, now time.Time, nonce uint32) (protocol.PAData, error) {
	return c.buildPAASReq(bodyDER, now, nonce, nil)
}

// BuildPAASReqWithFreshness constructs PA-PK-AS-REQ echoing a KDC token.
func (c *Client) BuildPAASReqWithFreshness(bodyDER []byte, now time.Time,
	nonce uint32, freshnessToken []byte) (protocol.PAData, error) {
	return c.buildPAASReq(bodyDER, now, nonce, nil, freshnessToken)
}

// BuildPAASReqForPrincipals constructs PA-PK-AS-REQ with algorithm-agility
// context for the supplied client and KDC principals.
func (c *Client) BuildPAASReqForPrincipals(bodyDER []byte, now time.Time,
	nonce uint32, client, server principal.Principal) (protocol.PAData, error) {
	return c.buildPAASReq(bodyDER, now, nonce, SupportedKDFAlgorithmIDs())
}

// BuildPAASReqForPrincipalsWithFreshness constructs an algorithm-agile
// PA-PK-AS-REQ echoing a KDC freshness token.
func (c *Client) BuildPAASReqForPrincipalsWithFreshness(bodyDER []byte,
	now time.Time, nonce uint32, client, server principal.Principal,
	freshnessToken []byte) (protocol.PAData, error) {
	return c.buildPAASReq(bodyDER, now, nonce, SupportedKDFAlgorithmIDs(),
		freshnessToken)
}

func (c *Client) buildPAASReq(bodyDER []byte, now time.Time, nonce uint32,
	supportedKDFs [][]byte, freshnessToken ...[]byte) (protocol.PAData, error) {
	if c == nil || c.Private == nil || (!c.Anonymous && (c.Certificate == nil || c.Signer == nil)) {
		return protocol.PAData{}, errors.New("pkinit: incomplete client state")
	}
	if len(bodyDER) == 0 {
		return protocol.PAData{}, errors.New("pkinit: empty AS-REQ body")
	}
	sum := sha1.Sum(bodyDER)
	var token []byte
	if len(freshnessToken) > 0 {
		token = append([]byte(nil), freshnessToken[0]...)
	}
	pack := authPackDER(PKAuthenticator{
		Cusec: int32(now.Nanosecond() / 1000), CTime: now.UTC(), Nonce: nonce,
		PAChecksum: sum[:], FreshnessToken: token,
	}, marshalSPKI(c.Public), supportedKDFs)
	var cms []byte
	var err error
	if c.Anonymous {
		cms = unsignedCMS(pack, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1})
	} else {
		cms, err = signCMS(pack, c.Certificate, c.Signer)
		if err != nil {
			return protocol.PAData{}, err
		}
	}
	// signedAuthPack is [0] IMPLICIT OCTET STRING.
	value := derSeq(der(0x80, cms))
	return protocol.PAData{PADataType: PADataASReq, PADataValue: value}, nil
}

// BuildPAASReq creates a fresh DH state and its PA-PK-AS-REQ padata.
func BuildPAASReq(bodyDER []byte, now time.Time, nonce uint32, cert *x509.Certificate, signer crypto.Signer) (protocol.PAData, *Client, error) {
	c, err := NewClient(cert, signer)
	if err != nil {
		return protocol.PAData{}, nil, err
	}
	pa, err := c.BuildPAASReq(bodyDER, now, nonce)
	return pa, c, err
}

// BuildAnonymousPAASReq creates an unsigned RFC 6112 anonymous PKINIT
// request using a fresh group-14 Diffie-Hellman state.
func BuildAnonymousPAASReq(bodyDER []byte, now time.Time, nonce uint32) (protocol.PAData, *Client, error) {
	c, err := NewAnonymousClient()
	if err != nil {
		return protocol.PAData{}, nil, err
	}
	pa, err := c.BuildPAASReq(bodyDER, now, nonce)
	return pa, c, err
}

// BuildAnonymousPAASReqWithFreshness constructs an anonymous PKINIT request
// echoing a KDC freshness token.
func BuildAnonymousPAASReqWithFreshness(bodyDER []byte, now time.Time,
	nonce uint32, freshnessToken []byte) (protocol.PAData, *Client, error) {
	c, err := NewAnonymousClient()
	if err != nil {
		return protocol.PAData{}, nil, err
	}
	pa, err := c.BuildPAASReqWithFreshness(bodyDER, now, nonce, freshnessToken)
	return pa, c, err
}

// VerifyPAASReq verifies the CMS and paChecksum in PA-PK-AS-REQ and returns
// the decoded authenticator. It does not authenticate the client certificate.
func VerifyPAASReq(data, bodyDER []byte) (PKAuthenticator, error) {
	verified, err := VerifyPAASReqForKDC(data, bodyDER)
	if err != nil {
		return PKAuthenticator{}, err
	}
	return verified.Authenticator, nil
}

// VerifyPAASReqForKDC verifies the CMS and paChecksum in PA-PK-AS-REQ and
// returns the request certificate and client DH value. It does not trust or
// authorize the certificate.
func VerifyPAASReqForKDC(data, bodyDER []byte) (VerifiedPAASReq, error) {
	if err := requireSingleTLV(data); err != nil {
		return VerifiedPAASReq{}, err
	}
	content, cert, signed, intermediates, err :=
		verifyCMSChoiceStatusWithCertificates(data, nil)
	if err != nil {
		return VerifiedPAASReq{}, err
	}
	auth, publicValue, supportedKDFs, err := parseAuthPack(content)
	if err != nil {
		return VerifiedPAASReq{}, err
	}
	sum := sha1.Sum(bodyDER)
	if len(auth.PAChecksum) != len(sum) || subtle.ConstantTimeCompare(auth.PAChecksum, sum[:]) != 1 {
		return VerifiedPAASReq{}, errors.New("pkinit: PA-PK-AS-REQ checksum mismatch")
	}
	return VerifiedPAASReq{Authenticator: auth, PublicValue: publicValue,
		SupportedKDFs: supportedKDFs, Certificate: cert,
		Intermediates: intermediates, Signed: signed}, nil
}

// ValidateClientCertificate verifies a PKINIT client certificate chain,
// id-pkinit-KPClientAuth EKU, and its id-pkinit-san principal.
func ValidateClientCertificate(cert *x509.Certificate, anchors *x509.CertPool, realm string, components []string) error {
	if err := VerifyClientCertificateTrust(cert, anchors); err != nil {
		return err
	}
	if !HasClientAuthEKU(cert) {
		return errors.New("pkinit: client certificate lacks id-pkinit-KPClientAuth EKU")
	}
	principals, err := ClientSANs(cert)
	if err != nil {
		return err
	}
	for _, got := range principals {
		if got.Realm != realm || len(got.Components) != len(components) {
			continue
		}
		matched := true
		for i := range components {
			if got.Components[i] != components[i] {
				matched = false
				break
			}
		}
		if matched {
			return nil
		}
	}
	return errors.New("pkinit: client certificate SAN principal mismatch")
}

// VerifyClientCertificateTrust verifies the certificate against anchors
// without applying PKINIT authorization policy.
func VerifyClientCertificateTrust(cert *x509.Certificate, anchors *x509.CertPool,
	intermediates ...*x509.Certificate) error {
	if cert == nil {
		return errors.New("pkinit: missing client certificate")
	}
	if anchors == nil {
		return errors.New("pkinit: client certificate trust roots are required")
	}
	pool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		if intermediate != nil {
			pool.AddCert(intermediate)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: anchors, Intermediates: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return errors.New("pkinit: client certificate is not trusted")
	}
	return nil
}

// HasClientAuthEKU reports whether cert contains id-pkinit-KPClientAuth.
func HasClientAuthEKU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	clientEKU := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(clientEKU) {
			return true
		}
	}
	return false
}

// ClientSAN returns the first Kerberos principal encoded in id-pkinit-san SANs.
func ClientSAN(cert *x509.Certificate) (string, []string, error) {
	principals, err := ClientSANs(cert)
	if err != nil {
		return "", nil, err
	}
	components := principals[0].Components
	return principals[0].Realm, components, nil
}

// ClientSANs returns all Kerberos principals encoded in id-pkinit-san SANs.
func ClientSANs(cert *x509.Certificate) ([]principal.Principal, error) {
	const sanOID = "1.3.6.1.5.2.2"
	const extensionOID = "2.5.29.17"
	var principals []principal.Principal
	for _, ext := range cert.Extensions {
		if ext.Id.String() != extensionOID {
			continue
		}
		fields, err := sequenceFields(ext.Value)
		if err != nil {
			return nil, errors.New("pkinit: malformed client subject alternative name")
		}
		for _, field := range fields {
			if len(field) == 0 || field[0] != 0xa0 {
				continue
			}
			other, err := collectionFields(derSeq(mustContent(field)))
			if err != nil || len(other) != 2 {
				continue
			}
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(other[0], &oid); err != nil || oid.String() != sanOID {
				continue
			}
			value, err := tlvContent(other[1])
			if err != nil {
				return nil, errors.New("pkinit: malformed client subject alternative name")
			}
			parts, err := parseKRB5SANPrincipal(value)
			if err != nil {
				return nil, err
			}
			if len(parts) < 2 {
				return nil, errors.New("pkinit: malformed client principal SAN")
			}
			principals = append(principals, principal.Principal{
				Realm:      parts[len(parts)-1],
				Components: parts[:len(parts)-1],
			})
		}
	}
	if len(principals) == 0 {
		return nil, ErrClientSANNotFound
	}
	return principals, nil
}

// ParseAuthPack decodes an AuthPack DER value.
func ParseAuthPack(data []byte) (AuthPack, error) {
	if err := requireSingleTLV(data); err != nil {
		return AuthPack{}, err
	}
	auth, pub, supportedKDFs, err := parseAuthPack(data)
	if err != nil {
		return AuthPack{}, err
	}
	cmsTypes, dhNonce, err := parseAuthPackOptionals(data)
	if err != nil {
		return AuthPack{}, err
	}
	return AuthPack{Authenticator: auth, PublicValue: pub,
		SupportedCMSTypes: cmsTypes, DHNonce: dhNonce,
		SupportedKDFs: supportedKDFs}, nil
}

func validateAuthPackFieldOrder(fields [][]byte) error {
	lastOptionalTag := -1
	for _, field := range fields[1:] {
		if len(field) == 0 {
			return errors.New("pkinit: malformed AuthPack")
		}
		var optionalTag int
		switch field[0] {
		case 0xa1:
			optionalTag = 1
		case 0xa2:
			optionalTag = 2
		case 0xa3:
			optionalTag = 3
		case 0xa4:
			optionalTag = 4
		default:
			continue
		}
		if optionalTag <= lastOptionalTag {
			return errors.New("pkinit: duplicate or out-of-order AuthPack optional")
		}
		lastOptionalTag = optionalTag
	}
	return nil
}

func parseAuthPackOptionals(data []byte) ([][]byte, []byte, error) {
	fields, err := sequenceFields(data)
	if err != nil {
		return nil, nil, errors.New("pkinit: malformed AuthPack")
	}
	if err := validateAuthPackFieldOrder(fields); err != nil {
		return nil, nil, err
	}
	var cmsTypes [][]byte
	var dhNonce []byte
	for _, field := range fields[1:] {
		switch field[0] {
		case 0xa2:
			content, err := tlvContent(field)
			if err != nil {
				return nil, nil, err
			}
			elements, err := sequenceFields(content)
			if err != nil {
				return nil, nil, errors.New("pkinit: malformed supportedCMSTypes")
			}
			for _, element := range elements {
				cmsTypes = append(cmsTypes, append([]byte(nil), element...))
			}
		case 0xa3:
			content, err := tlvContent(field)
			if err != nil {
				return nil, nil, err
			}
			dhNonce, err = tlvContent(content)
			if err != nil {
				return nil, nil, err
			}
			dhNonce = append([]byte(nil), dhNonce...)
		}
	}
	return cmsTypes, dhNonce, nil
}

// SharedKey derives the RFC 4556 reply key from the KDC DH public value.
func (c *Client) SharedKey(serverPublic []byte, enctype int32) ([]byte, error) {
	return c.SharedKeyWithNonces(serverPublic, enctype, nil, nil)
}

// SharedKeyWithNonces derives a reply key, including the optional DH nonces.
func (c *Client) SharedKeyWithNonces(serverPublic []byte, enctype int32, clientNonce, serverNonce []byte) ([]byte, error) {
	if c == nil || c.Private == nil {
		return nil, errors.New("pkinit: incomplete DH state")
	}
	y := new(big.Int).SetBytes(serverPublic)
	if !validDHPublicValue(y) {
		return nil, errors.New("pkinit: invalid DH public value")
	}
	shared := new(big.Int).Exp(y, c.Private, group14P).Bytes()
	padded := make([]byte, (group14P.BitLen()+7)/8)
	copy(padded[len(padded)-len(shared):], shared)
	z := append(append(padded, clientNonce...), serverNonce...)
	return octetString2Key(z, enctype)
}

// SharedKeyWithContext derives the RFC 8636 key when the KDC selected a KDF.
// A nil algorithm preserves the RFC 4556 octet-string-to-key behavior.
func (c *Client) SharedKeyWithContext(serverPublic []byte, enctype int32,
	clientNonce, serverNonce, algorithm []byte, client, server principal.Principal,
	asReq, pkAsRep []byte) ([]byte, error) {
	if c == nil || c.Private == nil {
		return nil, errors.New("pkinit: incomplete DH state")
	}
	y := new(big.Int).SetBytes(serverPublic)
	if !validDHPublicValue(y) {
		return nil, errors.New("pkinit: invalid DH public value")
	}
	shared := new(big.Int).Exp(y, c.Private, group14P).Bytes()
	padded := make([]byte, (group14P.BitLen()+7)/8)
	copy(padded[len(padded)-len(shared):], shared)
	if len(algorithm) == 0 {
		z := append(append(append([]byte(nil), padded...), clientNonce...), serverNonce...)
		return octetString2Key(z, enctype)
	}
	return DeriveKey(padded, algorithm, client, server, enctype, asReq, pkAsRep)
}

// BuildPAASRep constructs the DH profile of PA-PK-AS-REP for a client
// public value. The returned key is the RFC 4556 reply key used to encrypt
// the AS-REP.
func BuildPAASRep(clientPublic []byte, enctype int32, nonce uint32, cert *x509.Certificate, signer crypto.Signer) (protocol.PAData, []byte, error) {
	return BuildPAASRepWithKDF(clientPublic, enctype, nonce, cert, signer, nil,
		principal.Principal{}, principal.Principal{}, nil)
}

// BuildPAASRepWithKDF constructs a PA-PK-AS-REP and derives its reply key
// using the selected RFC 8636 KDF. A nil algorithm selects RFC 4556.
func BuildPAASRepWithKDF(clientPublic []byte, enctype int32, nonce uint32,
	cert *x509.Certificate, signer crypto.Signer, algorithm []byte,
	client, server principal.Principal, asReq []byte) (protocol.PAData, []byte, error) {
	if cert == nil || signer == nil {
		return protocol.PAData{}, nil, errors.New("pkinit: certificate and signer are required")
	}
	if err := validateKDC(nil, cert); err != nil {
		return protocol.PAData{}, nil, err
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return protocol.PAData{}, nil, errors.New("pkinit: only RSA signing keys are supported")
	}
	clientY, err := parseSPKIPublicValue(clientPublic)
	if err != nil {
		return protocol.PAData{}, nil, err
	}
	private, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Sub(group14P, big.NewInt(2)))
	if err != nil {
		return protocol.PAData{}, nil, fmt.Errorf("pkinit: generate DH private value: %w", err)
	}
	private.Add(private, big.NewInt(2))
	serverY := new(big.Int).Exp(group14G, private, group14P)
	shared := new(big.Int).Exp(clientY, private, group14P).Bytes()
	padded := make([]byte, (group14P.BitLen()+7)/8)
	copy(padded[len(padded)-len(shared):], shared)
	dhFields := append(derExplicit(0, derBitString(derIntBig(serverY))),
		derExplicit(1, derInt(int64(nonce)))...)
	dhInfo := der(0x30, dhFields)
	signed, err := signCMSWithContentType(dhInfo,
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}, cert, signer)
	if err != nil {
		return protocol.PAData{}, nil, err
	}
	repFields := derImplicitOctet(0, signed)
	if len(algorithm) != 0 {
		repFields = append(repFields, derExplicit(2, derSeq(
			derExplicit(0, der(0x06, algorithm)),
		))...)
	}
	pa := protocol.PAData{
		PADataType:  PADataASRep,
		PADataValue: derExplicit(0, derSeq(repFields)),
	}
	if len(algorithm) == 0 {
		replyKey, err := octetString2Key(padded, enctype)
		if err != nil {
			return protocol.PAData{}, nil, err
		}
		return pa, replyKey, nil
	}
	replyKey, err := DeriveKey(padded, algorithm, client, server, enctype, asReq, pa.PADataValue)
	if err != nil {
		return protocol.PAData{}, nil, err
	}
	return pa, replyKey, nil
}

func parseSPKIPublicValue(data []byte) (*big.Int, error) {
	fields, err := sequenceFields(data)
	if err != nil || len(fields) != 2 {
		return nil, errors.New("pkinit: malformed client DH public value")
	}
	bits, err := tlvContent(fields[1])
	if err != nil || len(bits) < 2 || bits[0] != 0 {
		return nil, errors.New("pkinit: malformed client DH public value")
	}
	integerDER := bits[1:]
	value, err := parseInteger(integerDER)
	if err != nil || !validDHPublicValue(value) {
		return nil, errors.New("pkinit: invalid client DH public value")
	}
	return value, nil
}

func validDHPublicValue(value *big.Int) bool {
	if value == nil {
		return false
	}
	return value.Cmp(big.NewInt(1)) > 0 &&
		value.Cmp(new(big.Int).Sub(group14P, big.NewInt(1))) < 0
}

// VerifyPAASRep verifies a PA-PK-AS-REP and derives its DH reply key.
func (c *Client) VerifyPAASRep(data []byte, anchors *x509.CertPool, enctype int32, nonce uint32) ([]byte, error) {
	return c.VerifyPAASRepWithContext(data, anchors, enctype, nonce,
		principal.Principal{}, principal.Principal{}, nil)
}

// VerifyPAASRepWithContext verifies a PA-PK-AS-REP and derives its reply key,
// including RFC 8636 algorithm-agility context when kdfID is present.
func (c *Client) VerifyPAASRepWithContext(data []byte, anchors *x509.CertPool,
	enctype int32, nonce uint32, client, server principal.Principal,
	asReq []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("pkinit: nil client")
	}
	if err := requireSingleTLV(data); err != nil {
		return nil, err
	}
	choice, err := paASRepChoice(data)
	if err != nil {
		return nil, err
	}
	dhInfo, err := sequenceFields(choice)
	if err != nil || len(dhInfo) == 0 {
		return nil, errors.New("pkinit: malformed DHRepInfo")
	}
	dhSignedData, err := tlvContent(dhInfo[0])
	if err != nil {
		return nil, errors.New("pkinit: malformed DHRepInfo signed data")
	}
	content, cert, err := verifyCMS(dhSignedData, anchors)
	if err != nil {
		return nil, err
	}
	if err := validateKDC(certificateRoots(cert, anchors), cert); err != nil {
		return nil, err
	}
	fields, err := sequenceFields(content)
	if err != nil || len(fields) < 2 {
		return nil, errors.New("pkinit: malformed KDCDHKeyInfo")
	}
	serverY, err := parseExplicitBitStringInteger(fields[0])
	if err != nil {
		return nil, errors.New("pkinit: malformed KDC DH public value")
	}
	replyNonce, err := parseExplicitInteger(fields[1])
	if err != nil || replyNonce.Sign() < 0 || replyNonce.BitLen() > 32 || uint64(replyNonce.Uint64()) != uint64(nonce) {
		return nil, errors.New("pkinit: KDC DH nonce mismatch")
	}
	var serverNonce []byte
	var algorithm []byte
	for _, field := range dhInfo[1:] {
		switch field[0] {
		case 0x81:
			serverNonce, err = tlvContent(field)
			if err != nil {
				return nil, errors.New("pkinit: malformed KDC DH nonce")
			}
		case 0xa2:
			kdfInfo, err := sequenceFields(mustContent(field))
			if err != nil || len(kdfInfo) != 1 || kdfInfo[0][0] != 0xa0 {
				return nil, errors.New("pkinit: malformed KDF identifier")
			}
			oidDER, err := tlvContent(kdfInfo[0])
			if err != nil || len(oidDER) == 0 || oidDER[0] != 0x06 {
				return nil, errors.New("pkinit: malformed KDF OID")
			}
			algorithm, err = tlvContent(oidDER)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("pkinit: malformed DHRepInfo")
		}
	}
	return c.SharedKeyWithContext(serverY.Bytes(), enctype, nil, serverNonce,
		algorithm, client, server, asReq, data)
}

func paASRepChoice(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkinit: empty PA-PK-AS-REP")
	}
	tag, value, err := tlv(data)
	if err != nil || tag != 0xa0 {
		return nil, errors.New("pkinit: PA-PK-AS-REP is not DH signed data")
	}
	if len(data) != 1+len(derLen(len(value)))+len(value) {
		return nil, errors.New("pkinit: trailing PA-PK-AS-REP data")
	}
	return value, nil
}

func parseAuthPack(data []byte) (PKAuthenticator, []byte, [][]byte, error) {
	fields, err := sequenceFields(data)
	if err != nil || len(fields) < 1 {
		return PKAuthenticator{}, nil, nil, errors.New("pkinit: malformed AuthPack")
	}
	if err := validateAuthPackFieldOrder(fields); err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	afields, err := sequenceFields(mustContent(fields[0]))
	if err != nil || len(afields) < 4 {
		return PKAuthenticator{}, nil, nil, fmt.Errorf("pkinit: malformed PKAuthenticator (fields=%d err=%v)", len(afields), err)
	}
	cusec, err := parseExplicitInteger(afields[0])
	if err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	ctimeDER, err := tlvContent(afields[1])
	if err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	var ctime time.Time
	if _, err := asn1.Unmarshal(ctimeDER, &ctime); err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	nonce, err := parseExplicitInteger(afields[2])
	if err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	sumDER, err := tlvContent(afields[3])
	if err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	sum, err := tlvContent(sumDER)
	if err != nil {
		return PKAuthenticator{}, nil, nil, err
	}
	var pub []byte
	var freshnessToken []byte
	if len(afields) > 4 {
		if len(afields[4]) == 0 || afields[4][0] != 0xa4 {
			return PKAuthenticator{}, nil, nil, errors.New("pkinit: malformed freshness token")
		}
		tokenDER, err := tlvContent(afields[4])
		if err != nil {
			return PKAuthenticator{}, nil, nil, err
		}
		freshnessToken, err = tlvContent(tokenDER)
		if err != nil {
			return PKAuthenticator{}, nil, nil, err
		}
	}
	var supportedKDFs [][]byte
	for _, field := range fields[1:] {
		switch field[0] {
		case 0xa1:
			pub, err = tlvContent(field)
			if err != nil {
				return PKAuthenticator{}, nil, nil, err
			}
		case 0xa4:
			content, err := tlvContent(field)
			if err != nil {
				return PKAuthenticator{}, nil, nil, err
			}
			elements, err := sequenceFields(content)
			if err != nil || len(elements) == 0 {
				return PKAuthenticator{}, nil, nil, errors.New("pkinit: malformed supportedKDFs")
			}
			for _, element := range elements {
				efields, err := sequenceFields(element)
				if err != nil || len(efields) != 1 || len(efields[0]) == 0 || efields[0][0] != 0xa0 {
					return PKAuthenticator{}, nil, nil, errors.New("pkinit: malformed KDF algorithm identifier")
				}
				oidDER, err := tlvContent(efields[0])
				if err != nil {
					return PKAuthenticator{}, nil, nil, err
				}
				if len(oidDER) == 0 || oidDER[0] != 0x06 {
					return PKAuthenticator{}, nil, nil, errors.New("pkinit: malformed KDF OID")
				}
				oid, err := tlvContent(oidDER)
				if err != nil {
					return PKAuthenticator{}, nil, nil, err
				}
				supportedKDFs = append(supportedKDFs, append([]byte(nil), oid...))
			}
		}
	}
	return PKAuthenticator{
		Cusec: int32(cusec.Int64()), CTime: ctime, Nonce: uint32(nonce.Uint64()),
		PAChecksum:     append([]byte(nil), sum...),
		FreshnessToken: append([]byte(nil), freshnessToken...),
	}, pub, supportedKDFs, nil
}

func mustContent(v []byte) []byte {
	x, err := tlvContent(v)
	if err != nil {
		return nil
	}
	return x
}

func authPackDER(a PKAuthenticator, public []byte, supported ...[][]byte) []byte {
	pa := derSeq(
		derExplicit(0, derInt(int64(a.Cusec))), derExplicit(1, derTime(a.CTime)),
		derExplicit(2, derInt(int64(a.Nonce))), derExplicit(3, derOctet(a.PAChecksum)),
	)
	if len(a.FreshnessToken) > 0 {
		pa = derSeq(
			derExplicit(0, derInt(int64(a.Cusec))), derExplicit(1, derTime(a.CTime)),
			derExplicit(2, derInt(int64(a.Nonce))), derExplicit(3, derOctet(a.PAChecksum)),
			derExplicit(4, derOctet(a.FreshnessToken)),
		)
	}
	fields := []byte{}
	fields = append(fields, derExplicit(0, pa)...)
	if len(public) != 0 {
		fields = append(fields, derExplicit(1, public)...)
	}
	if len(supported) > 0 && len(supported[0]) > 0 {
		var ids []byte
		for _, oid := range supported[0] {
			ids = append(ids, derSeq(derExplicit(0, der(0x06, oid)))...)
		}
		fields = append(fields, derExplicit(4, der(0x30, ids))...)
	}
	return der(0x30, fields)
}

func octetString2Key(z []byte, enctype int32) ([]byte, error) {
	profile, err := krbcrypto.NewRegistry().Get(enctype)
	if err != nil {
		return nil, err
	}
	need := profile.KeySize()
	out := make([]byte, 0, need)
	for i := byte(0); len(out) < need; i++ {
		h := sha1.New()
		h.Write([]byte{i})
		h.Write(z)
		out = append(out, h.Sum(nil)...)
	}
	return out[:need], nil
}

// DeriveKey implements the RFC 8636 SP800-56A ASN.1 single-step KDF.
func DeriveKey(secret, algorithm []byte, client, server principal.Principal,
	enctype int32, asReq, pkAsRep []byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch {
	case bytes.Equal(algorithm, KDFSHA1):
		newHash = sha1.New
	case bytes.Equal(algorithm, KDFSHA256):
		newHash = sha256.New
	case bytes.Equal(algorithm, KDFSHA512):
		newHash = sha512.New
	default:
		return nil, errors.New("pkinit: unsupported KDF algorithm")
	}
	profile, err := krbcrypto.NewRegistry().Get(enctype)
	if err != nil {
		return nil, err
	}
	partyU := derExplicit(0, derOctet(encodePKINITPrincipal(client)))
	partyV := derExplicit(1, derOctet(encodePKINITPrincipal(server)))
	suppPubInfo := derSeq(
		derExplicit(0, derInt(int64(enctype))),
		derExplicit(1, derOctet(asReq)),
		derExplicit(2, derOctet(pkAsRep)),
	)
	algorithmIdentifier := derSeq(der(0x06, algorithm))
	otherInfo := derSeq(algorithmIdentifier, partyU, partyV, derExplicit(2, derOctet(suppPubInfo)))
	out := make([]byte, 0, profile.KeySize())
	for counter := uint32(1); len(out) < profile.KeySize(); counter++ {
		h := newHash()
		var count [4]byte
		binary.BigEndian.PutUint32(count[:], counter)
		_, _ = h.Write(count[:])
		_, _ = h.Write(secret)
		_, _ = h.Write(otherInfo)
		out = append(out, h.Sum(nil)...)
	}
	return out[:profile.KeySize()], nil
}

func encodePKINITPrincipal(value principal.Principal) []byte {
	var names []byte
	for _, component := range value.Components {
		names = append(names, der(0x1b, []byte(component))...)
	}
	principalName := derSeq(
		derExplicit(0, derInt(int64(value.NameType))),
		derExplicit(1, der(0x30, names)),
	)
	return derSeq(
		derExplicit(0, der(0x1b, []byte(value.Realm))),
		derExplicit(1, principalName),
	)
}

func marshalSPKI(y *big.Int) []byte {
	// SubjectPublicKeyInfo for id-dhPublicNumber, with RFC 3526 p and g.
	// RFC 3279 DomainParameters are p, g, q; group 14 has q = (p-1)/2.
	q := new(big.Int).Sub(group14P, big.NewInt(1))
	q.Div(q, big.NewInt(2))
	alg := derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}), derSeq(derIntBig(group14P), derIntBig(group14G), derIntBig(q)))
	pub := derIntBig(y)
	return derSeq(alg, derBitString(pub))
}

func signCMS(content []byte, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	return signCMSWithContentType(content,
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}, cert, signer)
}

func signCMSWithContentType(content []byte, contentType asn1.ObjectIdentifier,
	cert *x509.Certificate, signer crypto.Signer,
	additional ...*x509.Certificate) ([]byte, error) {
	contentDigest := sha256.Sum256(content)
	attrs := derSet(
		derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}), derSet(derOID(contentType))),
		derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}), derSet(derOctet(contentDigest[:]))),
	)
	h := sha256.Sum256(attrs)
	sig, err := signer.Sign(cryptorand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("pkinit: sign AuthPack: %w", err)
	}
	issuerSerial := derSeq(cert.RawIssuer, derIntBig(cert.SerialNumber))
	// IssuerAndSerialNumber requires CMS SignerInfo version 1.
	signerInfo := derSeq(derInt(1), issuerSerial, derSeq(derOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}), derNull()), derExplicitImplicit(0, attrs[2:]), derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), derNull()), derOctet(sig))
	certificates := append([]byte(nil), cert.Raw...)
	for _, additionalCert := range additional {
		if additionalCert != nil {
			certificates = append(certificates, additionalCert.Raw...)
		}
	}
	signed := derSeq(derInt(3), derSet(derSeq(derOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}), derNull())), derSeq(derOID(contentType), derExplicit(0, derOctet(content))), derExplicitImplicit(0, certificates), derSet(signerInfo))
	return derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), derExplicit(0, signed)), nil
}

func unsignedCMS(content []byte, contentType asn1.ObjectIdentifier) []byte {
	signedData := derSeq(
		derInt(3),
		derSet(),
		derSeq(derOID(contentType), derExplicit(0, derOctet(content))),
		derSet(),
	)
	return derSeq(
		derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}),
		derExplicit(0, signedData),
	)
}

func verifyCMSChoice(data []byte, anchors *x509.CertPool) ([]byte, *x509.Certificate, error) {
	content, cert, _, _, err := verifyCMSChoiceStatusWithCertificates(data, anchors)
	return content, cert, err
}

func verifyCMSChoiceStatus(data []byte, anchors *x509.CertPool) ([]byte, *x509.Certificate, bool, error) {
	content, cert, signed, _, err :=
		verifyCMSChoiceStatusWithCertificates(data, anchors)
	return content, cert, signed, err
}

func verifyCMSChoiceStatusWithCertificates(data []byte,
	anchors *x509.CertPool) ([]byte, *x509.Certificate, bool, []*x509.Certificate, error) {
	if err := requireSingleTLV(data); err != nil {
		return nil, nil, false, nil, err
	}
	var choice []byte
	if len(data) > 0 && (data[0] == 0xa0 || data[0] == 0x80) {
		choice = data
	} else {
		fields, err := sequenceFields(data)
		if err != nil || len(fields) == 0 || len(fields[0]) == 0 || (fields[0][0] != 0xa0 && fields[0][0] != 0x80) {
			return nil, nil, false, nil, errors.New("pkinit: PA-PK-AS-REP is not DH signed data")
		}
		choice = fields[0]
	}
	choice, err := tlvContent(choice)
	if err != nil {
		return nil, nil, false, nil, err
	}
	if len(choice) > 0 && choice[0] == 0x04 {
		choice, err = tlvContent(choice)
		if err != nil {
			return nil, nil, false, nil, err
		}
	}
	return verifyCMSStatusWithCertificates(choice, anchors)
}

func verifyCMS(data []byte, anchors *x509.CertPool) ([]byte, *x509.Certificate, error) {
	content, cert, _, _, err := verifyCMSStatusWithCertificates(data, anchors)
	return content, cert, err
}

func verifyCMSStatus(data []byte, anchors *x509.CertPool) ([]byte, *x509.Certificate, bool, error) {
	content, cert, signed, _, err :=
		verifyCMSStatusWithCertificates(data, anchors)
	return content, cert, signed, err
}

func verifyCMSStatusWithCertificates(data []byte, anchors *x509.CertPool) (
	[]byte, *x509.Certificate, bool, []*x509.Certificate, error) {
	if err := requireSingleTLV(data); err != nil {
		return nil, nil, false, nil, err
	}
	// CMS ContentInfo wraps SignedData; accept the inner SignedData form too.
	outer, outerErr := sequenceFields(data)
	if outerErr == nil && len(outer) == 2 && len(outer[0]) > 0 && outer[0][0] == 0x06 {
		_, wrapped, unwrapErr := tlv(outer[1])
		if unwrapErr != nil {
			return nil, nil, false, nil, unwrapErr
		}
		if len(wrapped) > 0 && wrapped[0] == 0x04 {
			content, contentErr := tlvContent(wrapped)
			if contentErr != nil {
				return nil, nil, false, nil, contentErr
			}
			if err := requireSingleTLV(content); err != nil {
				return nil, nil, false, nil, errors.New("pkinit: malformed CMS content")
			}
			return content, nil, false, nil, nil
		}
		data = wrapped
	}
	fields, err := sequenceFields(data)
	if err != nil || len(fields) < 4 {
		return nil, nil, false, nil, fmt.Errorf("pkinit: malformed CMS SignedData (fields=%d err=%v)", len(fields), err)
	}
	encap, err := sequenceFields(fields[2])
	if err != nil || len(encap) < 2 {
		return nil, nil, false, nil, errors.New("pkinit: malformed CMS content")
	}
	_, econtent, err := tlv(encap[1])
	if err != nil {
		return nil, nil, false, nil, err
	}
	_, content, err := tlv(econtent)
	if err != nil {
		return nil, nil, false, nil, err
	}
	if len(fields) == 4 && len(fields[3]) > 0 && fields[3][0] == 0x31 {
		if _, err := collectionFields(fields[3]); err != nil {
			return nil, nil, false, nil, err
		}
		return content, nil, false, nil, nil
	}
	certFields, err := collectionFields(fields[3])
	if err != nil || len(certFields) == 0 {
		return nil, nil, false, nil, errors.New("pkinit: malformed CMS certificate set")
	}
	certificates := make([]*x509.Certificate, 0, len(certFields))
	for _, certDER := range certFields {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			continue
		}
		certificates = append(certificates, cert)
	}
	if len(certificates) == 0 {
		return nil, nil, false, nil, errors.New("pkinit: missing KDC certificate")
	}
	if len(fields) < 5 {
		return nil, nil, false, nil, errors.New("pkinit: missing CMS signer")
	}
	infos, err := collectionFields(fields[4])
	if err != nil || len(infos) == 0 {
		return nil, nil, false, nil, errors.New("pkinit: missing CMS signer")
	}
	si, err := sequenceFields(infos[0])
	if err != nil || len(si) < 6 {
		return nil, nil, false, nil, errors.New("pkinit: malformed CMS signer")
	}
	issuerSerial, err := sequenceFields(si[1])
	if err != nil || len(issuerSerial) != 2 {
		return nil, nil, false, nil, errors.New("pkinit: malformed CMS signer identifier")
	}
	serial, err := parseInteger(issuerSerial[1])
	if err != nil {
		return nil, nil, false, nil, errors.New("pkinit: malformed CMS signer serial")
	}
	var cert *x509.Certificate
	for _, candidate := range certificates {
		if bytes.Equal(candidate.RawIssuer, issuerSerial[0]) && candidate.SerialNumber.Cmp(serial) == 0 {
			cert = candidate
			break
		}
	}
	if cert == nil {
		return nil, nil, false, nil, errors.New("pkinit: CMS signer certificate not found")
	}
	attrsContent, err := tlvContent(si[3])
	if err != nil {
		return nil, nil, false, nil, err
	}
	attrs := derSetContent(attrsContent)
	hashID, err := cmsDigestHash(si[2])
	if err != nil {
		return nil, nil, false, nil, err
	}
	contentDigest := hashBytes(hashID, content)
	if !bytes.Contains(attrs, derOctet(contentDigest)) {
		return nil, nil, false, nil, errors.New("pkinit: CMS messageDigest mismatch")
	}
	sig, err := tlvContent(si[5])
	if err != nil {
		return nil, nil, false, nil, err
	}
	sigHash := hashBytes(hashID, derSet(attrsContent))
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || rsa.VerifyPKCS1v15(rsaKey, hashID, sigHash, sig) != nil {
		return nil, nil, false, nil, errors.New("pkinit: invalid CMS signature")
	}
	if anchors != nil {
		intermediates := x509.NewCertPool()
		for _, intermediate := range certificates {
			if intermediate != cert {
				intermediates.AddCert(intermediate)
			}
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: anchors, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return nil, nil, false, nil, errors.New("pkinit: KDC certificate is not trusted")
		}
	}
	var intermediates []*x509.Certificate
	for _, candidate := range certificates {
		if candidate != cert {
			intermediates = append(intermediates, candidate)
		}
	}
	return content, cert, true, intermediates, nil
}

func requireSingleTLV(data []byte) error {
	if _, _, err := tlv(data); err != nil {
		return err
	}
	_, _, n := readTLVLen(data)
	if n != len(data) {
		return errors.New("pkinit: trailing DER data")
	}
	return nil
}

func cmsDigestHash(algorithmDER []byte) (crypto.Hash, error) {
	fields, err := sequenceFields(algorithmDER)
	if err != nil || len(fields) == 0 {
		return 0, errors.New("pkinit: malformed CMS digest algorithm")
	}
	sha1OID := derOID(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})
	sha256OID := derOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	if bytes.Equal(fields[0], sha1OID) {
		return crypto.SHA1, nil
	}
	if bytes.Equal(fields[0], sha256OID) {
		return crypto.SHA256, nil
	}
	return 0, errors.New("pkinit: unsupported CMS digest algorithm")
}

func hashBytes(hash crypto.Hash, data []byte) []byte {
	var sum []byte
	switch hash {
	case crypto.SHA1:
		v := sha1.Sum(data)
		sum = v[:]
	case crypto.SHA256:
		v := sha256.Sum256(data)
		sum = v[:]
	}
	return sum
}

func certificateRoots(_ *x509.Certificate, anchors *x509.CertPool) *x509.CertPool { return anchors }

func validateKDC(_ *x509.CertPool, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("pkinit: missing KDC certificate")
	}
	kdcEKU := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
	hasKDCEKU := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(kdcEKU) {
			hasKDCEKU = true
			break
		}
	}
	if !hasKDCEKU {
		return errors.New("pkinit: KDC certificate lacks id-pkinit-KPKdc EKU")
	}
	return validateKDCSAN(cert)
}

func validateKDCSAN(cert *x509.Certificate) error {
	const sanOID = "1.3.6.1.5.2.2"
	const extensionOID = "2.5.29.17"
	for _, ext := range cert.Extensions {
		if ext.Id.String() != extensionOID {
			continue
		}
		fields, err := sequenceFields(ext.Value)
		if err != nil {
			return errors.New("pkinit: malformed KDC subject alternative name")
		}
		for _, field := range fields {
			if len(field) == 0 || field[0] != 0xa0 {
				continue
			}
			// GeneralName.otherName is [0] IMPLICIT OtherName, so its
			// contents are the OtherName fields without an inner SEQUENCE.
			other, err := collectionFields(derSeq(mustContent(field)))
			if err != nil || len(other) != 2 {
				continue
			}
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(other[0], &oid); err != nil || oid.String() != sanOID {
				continue
			}
			value, err := tlvContent(other[1])
			if err != nil {
				return errors.New("pkinit: malformed KDC subject alternative name")
			}
			principal, err := parseKRB5SANPrincipal(value)
			if err != nil {
				return err
			}
			if len(principal) < 2 || principal[0] != "krbtgt" || principal[1] != principal[len(principal)-1] {
				return errors.New("pkinit: KDC certificate SAN is not a krbtgt principal")
			}
			return nil
		}
	}
	return errors.New("pkinit: KDC certificate has no id-pkinit-san SAN")
}

func parseKRB5SANPrincipal(data []byte) ([]string, error) {
	fields, err := sequenceFields(data)
	if err != nil || len(fields) != 2 {
		return nil, errors.New("pkinit: malformed KDC principal SAN")
	}
	realm, err := parseGeneralStringContext(fields[0])
	if err != nil || realm == "" {
		return nil, errors.New("pkinit: malformed KDC principal SAN realm")
	}
	nameFields, err := sequenceFields(mustContent(fields[1]))
	if err != nil || len(nameFields) != 2 {
		return nil, errors.New("pkinit: malformed KDC principal SAN name")
	}
	parts, err := sequenceFields(mustContent(nameFields[1]))
	if err != nil || len(parts) == 0 {
		return nil, errors.New("pkinit: malformed KDC principal SAN components")
	}
	out := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		value, err := tlvContent(part)
		if err != nil {
			return nil, err
		}
		out = append(out, string(value))
	}
	out = append(out, realm)
	return out, nil
}

func parseGeneralStringContext(data []byte) (string, error) {
	value, err := tlvContent(data)
	if err != nil {
		return "", err
	}
	if len(value) < 2 || value[0] != 0x1b {
		return "", errors.New("pkinit: expected GeneralString")
	}
	content, err := tlvContent(value)
	return string(content), err
}

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}
func der(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLen(len(content))...), content...)
}
func derSeq(v ...[]byte) []byte {
	var b []byte
	for _, x := range v {
		b = append(b, x...)
	}
	return der(0x30, b)
}
func derSet(v ...[]byte) []byte {
	var b []byte
	for _, x := range v {
		b = append(b, x...)
	}
	return der(0x31, b)
}
func derSetContent(v []byte) []byte                { return der(0x31, v) }
func derExplicit(tag int, v []byte) []byte         { return der(0xa0|byte(tag), v) }
func derExplicitImplicit(tag int, v []byte) []byte { return der(0xa0|byte(tag), v) }
func derImplicitOctet(tag int, v []byte) []byte    { return der(0x80|byte(tag), v) }
func derOctet(v []byte) []byte                     { return der(0x04, v) }
func derNull() []byte                              { return []byte{0x05, 0x00} }
func derInt(v int64) []byte                        { return derIntBig(big.NewInt(v)) }
func derIntBig(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return der(0x02, b)
}
func derOID(v asn1.ObjectIdentifier) []byte { b, _ := asn1.Marshal(v); return b }
func derTime(t time.Time) []byte            { return der(0x18, []byte(t.UTC().Format("20060102150405Z"))) }
func derBitString(v []byte) []byte          { return der(0x03, append([]byte{0}, v...)) }

func tlv(data []byte) (byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, errors.New("short DER")
	}
	headerLen := 2
	length := int(data[1])
	if length&0x80 != 0 {
		k := length & 0x7f
		if k == 0 || k > len(data)-2 || k > int(^uint(0)>>1)/256 {
			return 0, nil, errors.New("bad DER length")
		}
		headerLen += k
		length = 0
		for i := 0; i < k; i++ {
			if length > (int(^uint(0)>>1)-int(data[2+i]))/256 {
				return 0, nil, errors.New("bad DER length")
			}
			length = length*256 + int(data[2+i])
		}
	}
	if length > len(data)-headerLen {
		return 0, nil, errors.New("truncated DER")
	}
	return data[0], data[headerLen : headerLen+length], nil
}
func tlvContent(data []byte) ([]byte, error) { _, v, e := tlv(data); return v, e }
func sequenceFields(data []byte) ([][]byte, error) {
	tag, _, err := tlv(data)
	if err != nil || tag != 0x30 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("expected sequence")
	}
	return collectionFields(data)
}

func collectionFields(data []byte) ([][]byte, error) {
	_, v, err := tlv(data)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for len(v) > 0 {
		_, _, err := tlv(v)
		if err != nil {
			return nil, err
		}
		_, _, n := readTLVLen(v)
		out = append(out, append([]byte(nil), v[:n]...))
		v = v[n:]
	}
	return out, nil
}
func readTLVLen(v []byte) (byte, []byte, int) {
	if len(v) < 2 {
		return 0, nil, 0
	}
	l := int(v[1])
	n := 2
	if l&0x80 != 0 {
		k := l & 0x7f
		if k == 0 || k > len(v)-2 || k > int(^uint(0)>>1)/256 {
			return 0, nil, 0
		}
		l = 0
		for i := 0; i < k; i++ {
			if l > (int(^uint(0)>>1)-int(v[n+i]))/256 {
				return 0, nil, 0
			}
			l = l<<8 | int(v[n+i])
		}
		n += k
	}
	if l > len(v)-n {
		return 0, nil, 0
	}
	return v[0], v[n : n+l], n + l
}
func parseExplicitBitStringInteger(v []byte) (*big.Int, error) {
	inner, err := tlvContent(v)
	if err != nil {
		return nil, err
	}
	if len(inner) < 2 || inner[0] != 0x03 {
		return nil, errors.New("expected bit string")
	}
	bits, err := tlvContent(inner)
	if err != nil || len(bits) < 1 || bits[0] != 0 {
		return nil, errors.New("invalid DH bit string")
	}
	integerDER := bits[1:]
	_, integerBytes, err := tlv(integerDER)
	if err != nil {
		return nil, errors.New("invalid DH public integer")
	}
	// The DER INTEGER may include one leading sign octet for a 2048-bit
	// public value whose high bit is set.
	if len(integerBytes) > (group14P.BitLen()+7)/8+1 {
		return nil, errors.New("DH public value is too large")
	}
	value, err := parseInteger(integerDER)
	if err != nil || !validDHPublicValue(value) {
		return nil, errors.New("invalid DH public value")
	}
	return value, nil
}

func parseExplicitInteger(v []byte) (*big.Int, error) {
	inner, err := tlvContent(v)
	if err != nil {
		return nil, err
	}
	return parseInteger(inner)
}

func parseInteger(v []byte) (*big.Int, error) {
	_, x, e := tlv(v)
	if e != nil {
		return nil, e
	}
	if len(x) == 0 {
		return nil, errors.New("empty integer")
	}
	return new(big.Int).SetBytes(x), nil
}

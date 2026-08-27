// Package pkinit implements the Diffie-Hellman profile of RFC 4556 PKINIT.
package pkinit

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	krbcrypto "github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	PADataASReq = 16
	PADataASRep = 17
	DHGroup14   = 14
	DHGroup2    = 2
)

var (
	// RFC 3526 MODP group 14.
	group14P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	group14G    = big.NewInt(2)
)

// AuthPack is the RFC 4556 signed authentication payload.
type AuthPack struct {
	Authenticator PKAuthenticator
	PublicValue   []byte
	DHNonce       []byte
}

// PKAuthenticator authenticates an AS-REQ body to the KDC.
type PKAuthenticator struct {
	Cusec      int32
	CTime      time.Time
	Nonce      uint32
	PAChecksum []byte
}

// Client is an ephemeral PKINIT DH exchange state.
type Client struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	Private     *big.Int
	Public      *big.Int
	Nonce       uint32
}

// NewClient creates an RFC 4556 group-14 DH exchange state.
func NewClient(cert *x509.Certificate, signer crypto.Signer) (*Client, error) {
	if cert == nil || signer == nil {
		return nil, errors.New("pkinit: certificate and signer are required")
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, errors.New("pkinit: only RSA signing keys are supported")
	}
	x, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Sub(group14P, big.NewInt(2)))
	if err != nil {
		return nil, fmt.Errorf("pkinit: generate DH private value: %w", err)
	}
	x.Add(x, big.NewInt(2))
	return &Client{Certificate: cert, Signer: signer, Private: x, Public: new(big.Int).Exp(group14G, x, group14P)}, nil
}

// BuildPAASReq constructs PA-PK-AS-REQ. bodyDER must be the exact DER bytes
// of the AS-REQ KDC-REQ-BODY received by the KDC.
func (c *Client) BuildPAASReq(bodyDER []byte, now time.Time, nonce uint32) (protocol.PAData, error) {
	if c == nil || c.Certificate == nil || c.Signer == nil || c.Private == nil {
		return protocol.PAData{}, errors.New("pkinit: incomplete client state")
	}
	if len(bodyDER) == 0 {
		return protocol.PAData{}, errors.New("pkinit: empty AS-REQ body")
	}
	sum := sha1.Sum(bodyDER)
	pack := authPackDER(PKAuthenticator{Cusec: int32(now.Nanosecond() / 1000), CTime: now.UTC(), Nonce: nonce, PAChecksum: sum[:]}, marshalSPKI(c.Public))
	cms, err := signCMS(pack, c.Certificate, c.Signer)
	if err != nil {
		return protocol.PAData{}, err
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

// VerifyPAASReq verifies the CMS and paChecksum in PA-PK-AS-REQ and returns
// the decoded authenticator. It does not authenticate the client certificate.
func VerifyPAASReq(data, bodyDER []byte) (PKAuthenticator, error) {
	if err := requireSingleTLV(data); err != nil {
		return PKAuthenticator{}, err
	}
	content, _, err := verifyCMSChoice(data, nil)
	if err != nil {
		return PKAuthenticator{}, err
	}
	auth, _, err := parseAuthPack(content)
	if err != nil {
		return PKAuthenticator{}, err
	}
	sum := sha1.Sum(bodyDER)
	if len(auth.PAChecksum) != len(sum) || subtle.ConstantTimeCompare(auth.PAChecksum, sum[:]) != 1 {
		return PKAuthenticator{}, errors.New("pkinit: PA-PK-AS-REQ checksum mismatch")
	}
	return auth, nil
}

// ParseAuthPack decodes an AuthPack DER value.
func ParseAuthPack(data []byte) (AuthPack, error) {
	if err := requireSingleTLV(data); err != nil {
		return AuthPack{}, err
	}
	auth, pub, err := parseAuthPack(data)
	if err != nil {
		return AuthPack{}, err
	}
	return AuthPack{Authenticator: auth, PublicValue: pub}, nil
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
	if y.Sign() <= 0 || y.Cmp(group14P) >= 0 {
		return nil, errors.New("pkinit: invalid DH public value")
	}
	shared := new(big.Int).Exp(y, c.Private, group14P).Bytes()
	padded := make([]byte, (group14P.BitLen()+7)/8)
	copy(padded[len(padded)-len(shared):], shared)
	z := append(append(padded, clientNonce...), serverNonce...)
	return octetString2Key(z, enctype)
}

// VerifyPAASRep verifies a PA-PK-AS-REP and derives its DH reply key.
func (c *Client) VerifyPAASRep(data []byte, anchors *x509.CertPool, enctype int32, nonce uint32) ([]byte, error) {
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
	if len(dhInfo) > 1 {
		serverNonce, err = tlvContent(dhInfo[1])
		if err != nil {
			return nil, errors.New("pkinit: malformed KDC DH nonce")
		}
	}
	return c.SharedKeyWithNonces(serverY.Bytes(), enctype, nil, serverNonce)
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

func parseAuthPack(data []byte) (PKAuthenticator, []byte, error) {
	fields, err := sequenceFields(data)
	if err != nil || len(fields) < 1 {
		return PKAuthenticator{}, nil, errors.New("pkinit: malformed AuthPack")
	}
	afields, err := sequenceFields(mustContent(fields[0]))
	if err != nil || len(afields) < 4 {
		return PKAuthenticator{}, nil, fmt.Errorf("pkinit: malformed PKAuthenticator (fields=%d err=%v)", len(afields), err)
	}
	cusec, err := parseExplicitInteger(afields[0])
	if err != nil {
		return PKAuthenticator{}, nil, err
	}
	ctimeDER, err := tlvContent(afields[1])
	if err != nil {
		return PKAuthenticator{}, nil, err
	}
	var ctime time.Time
	if _, err := asn1.Unmarshal(ctimeDER, &ctime); err != nil {
		return PKAuthenticator{}, nil, err
	}
	nonce, err := parseExplicitInteger(afields[2])
	if err != nil {
		return PKAuthenticator{}, nil, err
	}
	sumDER, err := tlvContent(afields[3])
	if err != nil {
		return PKAuthenticator{}, nil, err
	}
	sum, err := tlvContent(sumDER)
	if err != nil {
		return PKAuthenticator{}, nil, err
	}
	var pub []byte
	if len(fields) > 1 {
		pub, err = tlvContent(fields[1])
		if err != nil {
			return PKAuthenticator{}, nil, err
		}
	}
	return PKAuthenticator{Cusec: int32(cusec.Int64()), CTime: ctime, Nonce: uint32(nonce.Uint64()), PAChecksum: append([]byte(nil), sum...)}, pub, nil
}

func mustContent(v []byte) []byte {
	x, err := tlvContent(v)
	if err != nil {
		return nil
	}
	return x
}

func authPackDER(a PKAuthenticator, public []byte) []byte {
	pa := derSeq(
		derExplicit(0, derInt(int64(a.Cusec))), derExplicit(1, derTime(a.CTime)),
		derExplicit(2, derInt(int64(a.Nonce))), derExplicit(3, derOctet(a.PAChecksum)),
	)
	return derSeq(derExplicit(0, pa), derExplicit(1, public))
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
	contentDigest := sha256.Sum256(content)
	attrs := derSet(
		derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}), derSet(derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}))),
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
	signed := derSeq(derInt(3), derSet(derSeq(derOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}), derNull())), derSeq(derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}), derExplicit(0, derOctet(content))), derExplicitImplicit(0, cert.Raw), derSet(signerInfo))
	return derSeq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), derExplicit(0, signed)), nil
}

func verifyCMSChoice(data []byte, anchors *x509.CertPool) ([]byte, *x509.Certificate, error) {
	if err := requireSingleTLV(data); err != nil {
		return nil, nil, err
	}
	var choice []byte
	if len(data) > 0 && (data[0] == 0xa0 || data[0] == 0x80) {
		choice = data
	} else {
		fields, err := sequenceFields(data)
		if err != nil || len(fields) == 0 || len(fields[0]) == 0 || (fields[0][0] != 0xa0 && fields[0][0] != 0x80) {
			return nil, nil, errors.New("pkinit: PA-PK-AS-REP is not DH signed data")
		}
		choice = fields[0]
	}
	choice, err := tlvContent(choice)
	if err != nil {
		return nil, nil, err
	}
	if len(choice) > 0 && choice[0] == 0x04 {
		choice, err = tlvContent(choice)
		if err != nil {
			return nil, nil, err
		}
	}
	content, cert, err := verifyCMS(choice, anchors)
	return content, cert, err
}

func verifyCMS(data []byte, anchors *x509.CertPool) ([]byte, *x509.Certificate, error) {
	if err := requireSingleTLV(data); err != nil {
		return nil, nil, err
	}
	// CMS ContentInfo wraps SignedData; accept the inner SignedData form too.
	outer, outerErr := sequenceFields(data)
	if outerErr == nil && len(outer) == 2 && len(outer[0]) > 0 && outer[0][0] == 0x06 {
		_, data, outerErr = tlv(outer[1])
		if outerErr != nil {
			return nil, nil, outerErr
		}
	}
	fields, err := sequenceFields(data)
	if err != nil || len(fields) < 5 {
		return nil, nil, fmt.Errorf("pkinit: malformed CMS SignedData (fields=%d err=%v)", len(fields), err)
	}
	encap, err := sequenceFields(fields[2])
	if err != nil || len(encap) < 2 {
		return nil, nil, errors.New("pkinit: malformed CMS content")
	}
	_, econtent, err := tlv(encap[1])
	if err != nil {
		return nil, nil, err
	}
	_, content, err := tlv(econtent)
	if err != nil {
		return nil, nil, err
	}
	certFields, err := collectionFields(fields[3])
	if err != nil || len(certFields) == 0 {
		return nil, nil, errors.New("pkinit: malformed CMS certificate set")
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
		return nil, nil, errors.New("pkinit: missing KDC certificate")
	}
	infos, err := collectionFields(fields[4])
	if err != nil || len(infos) == 0 {
		return nil, nil, errors.New("pkinit: missing CMS signer")
	}
	si, err := sequenceFields(infos[0])
	if err != nil || len(si) < 5 {
		return nil, nil, errors.New("pkinit: malformed CMS signer")
	}
	issuerSerial, err := sequenceFields(si[1])
	if err != nil || len(issuerSerial) != 2 {
		return nil, nil, errors.New("pkinit: malformed CMS signer identifier")
	}
	serial, err := parseInteger(issuerSerial[1])
	if err != nil {
		return nil, nil, errors.New("pkinit: malformed CMS signer serial")
	}
	var cert *x509.Certificate
	for _, candidate := range certificates {
		if bytes.Equal(candidate.RawIssuer, issuerSerial[0]) && candidate.SerialNumber.Cmp(serial) == 0 {
			cert = candidate
			break
		}
	}
	if cert == nil {
		return nil, nil, errors.New("pkinit: CMS signer certificate not found")
	}
	attrsContent, err := tlvContent(si[3])
	if err != nil {
		return nil, nil, err
	}
	attrs := derSetContent(attrsContent)
	hashID, err := cmsDigestHash(si[2])
	if err != nil {
		return nil, nil, err
	}
	contentDigest := hashBytes(hashID, content)
	if !bytes.Contains(attrs, derOctet(contentDigest)) {
		return nil, nil, errors.New("pkinit: CMS messageDigest mismatch")
	}
	sig, err := tlvContent(si[5])
	if err != nil {
		return nil, nil, err
	}
	sigHash := hashBytes(hashID, derSet(attrsContent))
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || rsa.VerifyPKCS1v15(rsaKey, hashID, sigHash, sig) != nil {
		return nil, nil, errors.New("pkinit: invalid CMS signature")
	}
	if anchors != nil {
		intermediates := x509.NewCertPool()
		for _, intermediate := range certificates {
			if intermediate != cert {
				intermediates.AddCert(intermediate)
			}
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: anchors, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return nil, nil, errors.New("pkinit: KDC certificate is not trusted")
		}
	}
	return content, cert, nil
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
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(kdcEKU) {
			return validateKDCSAN(cert)
		}
	}
	if len(cert.UnknownExtKeyUsage) > 0 {
		return errors.New("pkinit: KDC certificate lacks id-pkinit-KPKdc EKU")
	}
	// Some MIT configurations intentionally relax EKU checking and omit the
	// private PKINIT EKU. Chain validation remains mandatory when anchors are
	// supplied. When the private EKU is present, the KDC SAN is checked below.
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
	n := 1
	l := int(data[1])
	if l&0x80 != 0 {
		k := l & 0x7f
		if k == 0 || len(data) < 2+k {
			return 0, nil, errors.New("bad DER length")
		}
		l = 0
		for i := 0; i < k; i++ {
			l = l<<8 | int(data[2+i])
		}
		n += k
	}
	start := n + 1
	if start+l > len(data) {
		return 0, nil, errors.New("truncated DER")
	}
	return data[0], data[start : start+l], nil
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
	l := int(v[1])
	n := 2
	if l&0x80 != 0 {
		k := l & 0x7f
		l = 0
		for i := 0; i < k; i++ {
			l = l<<8 | int(v[n+i])
		}
		n += k
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
	return parseInteger(bits[1:])
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

package asn1_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

// Corpus vectors are from MIT Kerberos 1.22.2's src/tests/asn.1
// reference_encode.out and pkinit_encode.out.
type corpusVector struct {
	name string
	data []byte
}

func readCorpus(t *testing.T, name string) []corpusVector {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(source), "..", "..", "testdata", "mit", name)
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open MIT corpus %s: %v", name, err)
	}
	defer file.Close()
	var vectors []corpusVector
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		vectorName, encoded, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed MIT corpus line %q", line)
		}
		fields := strings.Fields(encoded)
		raw := make([]byte, len(fields))
		for i, field := range fields {
			value, err := hex.DecodeString(field)
			if err != nil || len(value) != 1 {
				t.Fatalf("invalid hex in %s: %q", vectorName, field)
			}
			raw[i] = value[0]
		}
		vectors = append(vectors, corpusVector{name: strings.TrimSpace(vectorName), data: raw})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read MIT corpus %s: %v", name, err)
	}
	return vectors
}

func corpusValue(name string) any {
	switch name {
	case "encode_krb5_authenticator", "encode_krb5_authenticator(optionals empty)", "encode_krb5_authenticator(optionals NULL)":
		return new(protocol.Authenticator)
	case "encode_krb5_ticket":
		return new(protocol.Ticket)
	case "encode_krb5_enc_tkt_part", "encode_krb5_enc_tkt_part(optionals NULL)":
		return new(protocol.EncTicketPart)
	case "encode_krb5_enc_kdc_rep_part", "encode_krb5_enc_kdc_rep_part(optionals NULL)":
		return new(protocol.EncTGSRepPart)
	case "encode_krb5_as_rep", "encode_krb5_as_rep(optionals NULL)":
		return new(protocol.ASRep)
	case "encode_krb5_tgs_rep", "encode_krb5_tgs_rep(optionals NULL)":
		return new(protocol.TGSRep)
	case "encode_krb5_as_req", "encode_krb5_as_req(optionals NULL except second_ticket)", "encode_krb5_as_req(optionals NULL except server)":
		return new(protocol.ASReq)
	case "encode_krb5_tgs_req", "encode_krb5_tgs_req(optionals NULL except second_ticket)", "encode_krb5_tgs_req(optionals NULL except server)":
		return new(protocol.TGSReq)
	case "encode_krb5_kdc_req_body", "encode_krb5_kdc_req_body(optionals NULL except second_ticket)", "encode_krb5_kdc_req_body(optionals NULL except server)":
		return new(protocol.KDCReqBody)
	case "encode_krb5_ap_req":
		return new(protocol.APReq)
	case "encode_krb5_ap_rep":
		return new(protocol.APRep)
	case "encode_krb5_ap_rep_enc_part", "encode_krb5_ap_rep_enc_part(optionals NULL)":
		return new(protocol.EncAPRepPart)
	case "encode_krb5_priv":
		return new(protocol.KRBPriv)
	case "encode_krb5_enc_priv_part", "encode_krb5_enc_priv_part(optionals NULL)":
		return new(protocol.EncKRBPrivPart)
	case "encode_krb5_safe", "encode_krb5_safe(optionals NULL)":
		return new(protocol.KRBSafe)
	case "encode_krb5_cred":
		return new(protocol.KRBCred)
	case "encode_krb5_enc_cred_part", "encode_krb5_enc_cred_part(optionals NULL)":
		return new(protocol.EncKrbCredPart)
	case "encode_krb5_error", "encode_krb5_error(optionals NULL)":
		return new(protocol.KRBError)
	case "encode_krb5_authorization_data":
		return new(protocol.AuthorizationData)
	case "encode_krb5_padata_sequence", "encode_krb5_padata_sequence(empty)":
		return new(protocol.MethodData)
	case "encode_krb5_pa_enc_ts", "encode_krb5_pa_enc_ts (no usec)":
		return new(preauth.EncTimestamp)
	case "encode_krb5_etype_info", "encode_krb5_etype_info(no info)", "encode_krb5_etype_info(only 1)":
		return new(protocol.ETypeInfo)
	case "encode_krb5_etype_info2", "encode_krb5_etype_info2(only 1)":
		return new(protocol.ETypeInfo2)
	case "encode_krb5_enc_data", "encode_krb5_enc_data(MSB-set kvno)", "encode_krb5_enc_data(kvno=-1)":
		return new(protocol.EncryptedData)
	case "encode_krb5_keyblock":
		return new(protocol.EncryptionKey)
	case "encode_krb5_cammac", "encode_krb5_cammac(optionals NULL)":
		return new(protocol.CAMMAC)
	case "encode_krb5_pa_otp_challenge", "encode_krb5_pa_otp_challenge(optionals NULL)":
		return new(protocol.PAOTPChallenge)
	case "encode_krb5_pa_otp_req", "encode_krb5_pa_otp_req(optionals NULL)":
		return new(protocol.PAOTPRequest)
	case "encode_krb5_pa_otp_enc_req":
		return new(protocol.PAOTPEncRequest)
	case "encode_krb5_otp_tokeninfo", "encode_krb5_otp_tokeninfo(optionals NULL)":
		return new(protocol.OTPTokenInfo)
	case "encode_krb5_pa_spake(support)", "encode_krb5_pa_spake(challenge)", "encode_krb5_pa_spake(response)", "encode_krb5_pa_spake(encdata)":
		return new(protocol.PASPAKE)
	case "encode_krb5_spake_factor", "encode_krb5_spake_factor(optionals NULL)":
		return new(protocol.SPAKESecondFactor)
	case "encode_krb5_fast_response":
		return new(protocol.KrbFastResponse)
	case "encode_krb5_pa_fx_fast_reply":
		return new(protocol.PAFXFastReply)
	case "encode_krb5_iakerb_header":
		return new(gssapi.IAKERBHeader)
	case "encode_krb5_iakerb_finished":
		return new(gssapi.IAKERBFinished)
	case "encode_krb5_pa_for_user":
		return new(protocol.PAForUser)
	case "encode_krb5_pa_s4u_x509_user":
		return new(protocol.PAS4UX509User)
	case "encode_krb5_kkdcp_message":
		return new(kkdcp.Message)
	case "encode_krb5_auth_pack":
		return new(protocol.AuthPack)
	case "encode_krb5_pa_pk_as_req", "encode_krb5_pa_pk_as_rep(dhInfo)", "encode_krb5_pa_pk_as_rep(encKeyPack)":
		return nil
	default:
		return nil
	}
}

var corpusSkip = map[string]string{
	"encode_krb5_ad_kdcissued":             "AD-KDC-ISSUED is not modeled as a standalone protocol type",
	"encode_krb5_cred":                     "covered by KRBCred only when the repository type is available",
	"encode_krb5_enc_sam_response_enc_2":   "SAM response structures are not implemented",
	"encode_krb5_sam_challenge_2":          "SAM challenge structures are not implemented",
	"encode_krb5_sam_challenge_2_body":     "SAM challenge structures are not implemented",
	"encode_krb5_sam_response_2":           "SAM response structures are not implemented",
	"encode_krb5_secure_cookie":            "secure-cookie structure is not implemented",
	"encode_krb5_typed_data":               "TYPED-DATA is not modeled as a standalone type",
	"encode_krb5_kdc_dh_key_info":          "PKINIT DH key info is not modeled as a standalone type",
	"encode_krb5_reply_key_pack":           "PKINIT reply key pack is not modeled as a standalone type",
	"encode_krb5_pkinit_supp_pub_info":     "PKINIT supported-pub-info is not modeled as a standalone type",
	"encode_krb5_sp80056a_other_info":      "PKINIT SP800-56A other-info is not modeled as a standalone type",
	"encode_krb5_pa_pk_as_req":             "PA-PK-AS-REQ wrapper uses PKINIT-specific CHOICE data",
	"encode_krb5_pa_pk_as_rep(dhInfo)":     "PA-PK-AS-REP CHOICE wrapper is not modeled",
	"encode_krb5_pa_pk_as_rep(encKeyPack)": "PA-PK-AS-REP CHOICE wrapper is not modeled",
}

func TestMITReferenceEncodeCorpus(t *testing.T) {
	vectors := readCorpus(t, "reference_encode.out")
	used, skipped := 0, 0
	for _, vector := range vectors {
		value := corpusValue(vector.name)
		if value == nil {
			if _, ok := corpusSkip[vector.name]; ok {
				skipped++
				continue
			}
			t.Errorf("MIT vector %q has no explicit implementation or skip entry", vector.name)
			continue
		}
		used++
		t.Run(vector.name, func(t *testing.T) {
			if err := asn1.Unmarshal(vector.data, value); err != nil {
				t.Fatalf("decode MIT bytes: %v", err)
			}
			encoded, err := asn1.Marshal(value)
			if err != nil {
				t.Fatalf("re-encode decoded value: %v", err)
			}
			if !bytes.Equal(encoded, vector.data) {
				t.Fatalf("MIT round trip mismatch:\n got %x\nwant %x", encoded, vector.data)
			}
		})
	}
	if used == 0 || skipped == 0 {
		t.Fatalf("unexpected corpus accounting: used=%d skipped=%d", used, skipped)
	}
	t.Logf("MIT reference corpus: used=%d skipped=%d", used, skipped)
}

func TestMITPKINITReferenceEncodeCorpus(t *testing.T) {
	vectors := readCorpus(t, "pkinit_encode.out")
	used, skipped := 0, 0
	for _, vector := range vectors {
		value := corpusValue(vector.name)
		if value == nil {
			if _, ok := corpusSkip[vector.name]; ok {
				skipped++
				continue
			}
			t.Errorf("MIT PKINIT vector %q has no explicit implementation or skip entry", vector.name)
			continue
		}
		used++
		t.Run(vector.name, func(t *testing.T) {
			if err := asn1.Unmarshal(vector.data, value); err != nil {
				t.Fatalf("decode MIT bytes: %v", err)
			}
			encoded, err := asn1.Marshal(value)
			if err != nil {
				t.Fatalf("re-encode decoded value: %v", err)
			}
			if !bytes.Equal(encoded, vector.data) {
				t.Fatalf("MIT round trip mismatch:\n got %x\nwant %x", encoded, vector.data)
			}
		})
	}
	if used == 0 {
		t.Fatalf("unexpected PKINIT corpus accounting: used=%d skipped=%d", used, skipped)
	}
	t.Logf("MIT PKINIT corpus: used=%d skipped=%d", used, skipped)
}

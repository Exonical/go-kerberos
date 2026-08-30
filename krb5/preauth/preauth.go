package preauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	PADataEncryptedTimestamp = 2
	PADataEncryptedChallenge = protocol.PADataEncryptedChallenge
	PADataETypeInfo          = 11
	PADataETypeInfo2         = 19
	PADataCookie             = protocol.PADataFXCookie
	PADataSPAKE              = protocol.PADataSPAKE
)

const (
	encryptedChallengeClientUsage uint32 = 54
	encryptedChallengeKDCUsage    uint32 = 55
)

// EncTimestamp is the encrypted timestamp payload used by PA-ENC-TIMESTAMP.
type EncTimestamp struct {
	PATimestamp types.KerberosTime `krb5:"tag:0"`
	PAUSec      *int32             `krb5:"tag:1,optional"`
}

// FindPAData returns the first padata element with the requested type.
func FindPAData(data protocol.MethodData, typ int32) *protocol.PAData {
	for i := range data {
		if data[i].PADataType == typ {
			return &data[i]
		}
	}
	return nil
}

// ParseMethodData decodes METHOD-DATA carried in KRB-ERROR e-data.
func ParseMethodData(data []byte) (protocol.MethodData, error) {
	var methodData protocol.MethodData
	if err := asn1.Unmarshal(data, &methodData); err != nil {
		return nil, fmt.Errorf("parse METHOD-DATA: %w", err)
	}
	return methodData, nil
}

// SelectEType selects the first supported enctype advertised by the KDC.
// It returns the enctype, salt, and string-to-key parameters.
func SelectEType(methodData protocol.MethodData, realm string, name principal.Principal, registry *crypto.Registry) (int32, []byte, []byte, error) {
	if registry == nil {
		registry = crypto.NewRegistry()
	}
	defaultSalt := []byte(realm + strings.Join(name.Components, ""))
	for _, pa := range methodData {
		var entries protocol.ETypeInfo2
		switch pa.PADataType {
		case PADataETypeInfo2:
			if err := asn1.Unmarshal(pa.PADataValue, &entries); err != nil {
				return 0, nil, nil, fmt.Errorf("parse ETYPE-INFO2: %w", err)
			}
		case PADataETypeInfo:
			var legacy protocol.ETypeInfo
			if err := asn1.Unmarshal(pa.PADataValue, &legacy); err != nil {
				return 0, nil, nil, fmt.Errorf("parse ETYPE-INFO: %w", err)
			}
			entries = make(protocol.ETypeInfo2, 0, len(legacy))
			for _, entry := range legacy {
				converted := protocol.ETypeInfo2Entry{EType: entry.EType}
				if entry.Salt != nil {
					salt := string(entrySalt(entry.Salt))
					converted.Salt = &salt
				}
				entries = append(entries, converted)
			}
		default:
			continue
		}
		for _, entry := range entries {
			if _, err := registry.Get(entry.EType); err != nil {
				continue
			}
			salt := defaultSalt
			if entry.Salt != nil {
				salt = []byte(*entry.Salt)
			}
			return entry.EType, append([]byte(nil), salt...), append([]byte(nil), entry.S2KParams...), nil
		}
	}
	return 0, nil, nil, fmt.Errorf("select preauthentication enctype: %w", krberrors.ErrUnsupportedEType)
}

func entrySalt(value *[]byte) []byte {
	if value == nil {
		return nil
	}
	return *value
}

// BuildEncryptedTimestamp encrypts PA-ENC-TS-ENC using key usage 1.
func BuildEncryptedTimestamp(etype crypto.EType, key []byte, now time.Time, microseconds int32) (protocol.PAData, error) {
	if etype == nil {
		return protocol.PAData{}, fmt.Errorf("build PA-ENC-TIMESTAMP: nil enctype")
	}
	timestamp := EncTimestamp{
		PATimestamp: types.KerberosTime{Time: now.UTC(), Present: true},
	}
	if microseconds != 0 {
		timestamp.PAUSec = &microseconds
	}
	plaintext, err := asn1.Marshal(timestamp)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("marshal PA-ENC-TS-ENC: %w", err)
	}
	ciphertext, err := etype.Encrypt(key, 1, plaintext)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("encrypt PA-ENC-TIMESTAMP: %w", err)
	}
	return protocol.PAData{PADataType: PADataEncryptedTimestamp, PADataValue: ciphertext}, nil
}

// BuildEncryptedChallenge creates the FAST encrypted-challenge request
// padata using the armor key and the client's long-term key.
func BuildEncryptedChallenge(etype crypto.EType, armorKey, clientKey []byte, now time.Time) (protocol.PAData, error) {
	return BuildEncryptedChallengeWithKeyEType(etype, armorKey, etype, clientKey, now)
}

// BuildEncryptedChallengeWithKeyEType is BuildEncryptedChallenge with an
// explicitly specified client-key enctype.
func BuildEncryptedChallengeWithKeyEType(armorEType crypto.EType, armorKey []byte, clientEType crypto.EType, clientKey []byte, now time.Time) (protocol.PAData, error) {
	etype := armorEType
	if etype == nil {
		return protocol.PAData{}, fmt.Errorf("build PA-ENCRYPTED-CHALLENGE: nil enctype")
	}
	challengeKey, err := crypto.CF2WithKeyEType(etype, armorKey, clientEType, clientKey,
		[]byte("clientchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("derive PA-ENCRYPTED-CHALLENGE key: %w", err)
	}
	timestamp := EncTimestamp{PATimestamp: types.KerberosTime{Time: now.UTC(), Present: true}}
	plaintext, err := asn1.Marshal(timestamp)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("marshal PA-ENCRYPTED-CHALLENGE: %w", err)
	}
	ciphertext, err := etype.Encrypt(challengeKey, encryptedChallengeClientUsage, plaintext)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("encrypt PA-ENCRYPTED-CHALLENGE: %w", err)
	}
	encoded, err := asn1.Marshal(protocol.EncryptedData{
		EType: etype.ID(), Cipher: ciphertext,
	})
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("marshal PA-ENCRYPTED-CHALLENGE wrapper: %w", err)
	}
	return protocol.PAData{PADataType: PADataEncryptedChallenge, PADataValue: encoded}, nil
}

// DecryptEncryptedChallenge decrypts and parses a FAST encrypted-challenge
// request using the armor key and one candidate client long-term key.
func DecryptEncryptedChallenge(etype crypto.EType, armorKey, clientKey []byte, data []byte) (time.Time, error) {
	return DecryptEncryptedChallengeWithKeyEType(etype, armorKey, etype, clientKey, data)
}

// DecryptEncryptedChallengeWithKeyEType is DecryptEncryptedChallenge with an
// explicitly specified client-key enctype.
func DecryptEncryptedChallengeWithKeyEType(armorEType crypto.EType, armorKey []byte, clientEType crypto.EType, clientKey []byte, data []byte) (time.Time, error) {
	etype := armorEType
	if etype == nil {
		return time.Time{}, fmt.Errorf("decrypt PA-ENCRYPTED-CHALLENGE: nil enctype")
	}
	var encrypted protocol.EncryptedData
	if err := asn1.Unmarshal(data, &encrypted); err != nil {
		return time.Time{}, fmt.Errorf("parse PA-ENCRYPTED-CHALLENGE: %w", err)
	}
	if encrypted.EType != etype.ID() || len(encrypted.Cipher) == 0 {
		return time.Time{}, fmt.Errorf("parse PA-ENCRYPTED-CHALLENGE: invalid encrypted data")
	}
	challengeKey, err := crypto.CF2WithKeyEType(etype, armorKey, clientEType, clientKey,
		[]byte("clientchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return time.Time{}, fmt.Errorf("derive PA-ENCRYPTED-CHALLENGE key: %w", err)
	}
	plaintext, err := etype.Decrypt(challengeKey, encryptedChallengeClientUsage, encrypted.Cipher)
	if err != nil {
		return time.Time{}, fmt.Errorf("decrypt PA-ENCRYPTED-CHALLENGE: %w", err)
	}
	var timestamp EncTimestamp
	if err := asn1.Unmarshal(plaintext, &timestamp); err != nil ||
		!timestamp.PATimestamp.Present {
		return time.Time{}, fmt.Errorf("parse PA-ENCRYPTED-CHALLENGE timestamp")
	}
	return timestamp.PATimestamp.Time, nil
}

// BuildEncryptedChallengeReply creates the KDC response challenge padata.
func BuildEncryptedChallengeReply(etype crypto.EType, armorKey, clientKey []byte, now time.Time) (protocol.PAData, error) {
	return BuildEncryptedChallengeReplyWithKeyEType(etype, armorKey, etype, clientKey, now)
}

// BuildEncryptedChallengeReplyWithKeyEType is BuildEncryptedChallengeReply
// with an explicitly specified client-key enctype.
func BuildEncryptedChallengeReplyWithKeyEType(armorEType crypto.EType, armorKey []byte, clientEType crypto.EType, clientKey []byte, now time.Time) (protocol.PAData, error) {
	etype := armorEType
	if etype == nil {
		return protocol.PAData{}, fmt.Errorf("build PA-ENCRYPTED-CHALLENGE reply: nil enctype")
	}
	challengeKey, err := crypto.CF2WithKeyEType(etype, armorKey, clientEType, clientKey,
		[]byte("kdcchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("derive PA-ENCRYPTED-CHALLENGE reply key: %w", err)
	}
	timestamp := EncTimestamp{PATimestamp: types.KerberosTime{Time: now.UTC(), Present: true}}
	plaintext, err := asn1.Marshal(timestamp)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("marshal PA-ENCRYPTED-CHALLENGE reply: %w", err)
	}
	ciphertext, err := etype.Encrypt(challengeKey, encryptedChallengeKDCUsage, plaintext)
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("encrypt PA-ENCRYPTED-CHALLENGE reply: %w", err)
	}
	encoded, err := asn1.Marshal(protocol.EncryptedData{EType: etype.ID(), Cipher: ciphertext})
	if err != nil {
		return protocol.PAData{}, fmt.Errorf("marshal PA-ENCRYPTED-CHALLENGE reply wrapper: %w", err)
	}
	return protocol.PAData{PADataType: PADataEncryptedChallenge, PADataValue: encoded}, nil
}

// VerifyEncryptedChallengeReply verifies a KDC encrypted-challenge reply.
func VerifyEncryptedChallengeReply(etype crypto.EType, armorKey, clientKey []byte, data []byte) error {
	return VerifyEncryptedChallengeReplyWithKeyEType(etype, armorKey, etype, clientKey, data)
}

// VerifyEncryptedChallengeReplyWithKeyEType is VerifyEncryptedChallengeReply
// with an explicitly specified client-key enctype.
func VerifyEncryptedChallengeReplyWithKeyEType(armorEType crypto.EType, armorKey []byte, clientEType crypto.EType, clientKey []byte, data []byte) error {
	etype := armorEType
	if etype == nil {
		return fmt.Errorf("verify PA-ENCRYPTED-CHALLENGE reply: nil enctype")
	}
	var encrypted protocol.EncryptedData
	if err := asn1.Unmarshal(data, &encrypted); err != nil {
		return fmt.Errorf("parse PA-ENCRYPTED-CHALLENGE reply: %w", err)
	}
	if encrypted.EType != etype.ID() || len(encrypted.Cipher) == 0 {
		return fmt.Errorf("parse PA-ENCRYPTED-CHALLENGE reply: invalid encrypted data")
	}
	challengeKey, err := crypto.CF2WithKeyEType(etype, armorKey, clientEType, clientKey,
		[]byte("kdcchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return fmt.Errorf("derive PA-ENCRYPTED-CHALLENGE reply key: %w", err)
	}
	plaintext, err := etype.Decrypt(challengeKey, encryptedChallengeKDCUsage, encrypted.Cipher)
	if err != nil {
		return fmt.Errorf("decrypt PA-ENCRYPTED-CHALLENGE reply: %w", err)
	}
	var timestamp EncTimestamp
	if err := asn1.Unmarshal(plaintext, &timestamp); err != nil ||
		!timestamp.PATimestamp.Present {
		return fmt.Errorf("parse PA-ENCRYPTED-CHALLENGE reply timestamp")
	}
	return nil
}

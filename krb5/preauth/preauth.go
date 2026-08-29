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
	PADataETypeInfo          = 11
	PADataETypeInfo2         = 19
	PADataCookie             = protocol.PADataFXCookie
	PADataSPAKE              = protocol.PADataSPAKE
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

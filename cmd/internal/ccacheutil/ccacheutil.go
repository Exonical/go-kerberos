package ccacheutil

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
)

func LoadConfig() (*config.Config, error) {
	if path := os.Getenv("KRB5_CONFIG"); path != "" {
		return config.ParseFile(path)
	}
	return config.ParseDefault(false)
}

func ParseEnctype(value string) (int32, error) {
	if number, err := strconv.ParseInt(value, 0, 32); err == nil {
		return int32(number), nil
	}
	normalized := strings.ToLower(value)
	for _, candidate := range []int32{
		crypto.EnctypeAES128SHA1,
		crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256,
		crypto.EnctypeAES256SHA384,
		crypto.EnctypeCamellia128,
		crypto.EnctypeCamellia256,
	} {
		if normalized == strings.ToLower(crypto.EnctypeName(candidate)) {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("unknown enctype %q", value)
}

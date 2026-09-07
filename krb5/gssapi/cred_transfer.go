package gssapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const credentialExportMagic = "K5C1"

// Export serializes a credential using the JSON shape used by MIT's
// gss_export_cred. The token is intended for Go library use; like MIT's
// implementation, it is not a cross-version credential interchange format.
func (c *Credential) Export() ([]byte, error) {
	if c == nil || c.usage == 0 {
		return nil, fmt.Errorf("GSS export credential: incomplete credential")
	}
	name := any(nil)
	if c.name != nil {
		name = []any{c.name.String(), nil, nil}
	}
	var cache any
	if c.cache != nil {
		cache = exportCache(c.cache)
	} else if c.creds != nil {
		cache = exportCache(credentialCache(c))
	}
	var keytabName any
	if c.keytab != nil {
		keytabName = c.keytabName
	}
	if keytabName == nil && c.keytabName != "" {
		keytabName = c.keytabName
	}
	cred := []any{
		uint32(c.usage), name, nil, false, false, keytabName, nil, cache,
		nil, c.tgt != nil, int64(0), int64(0), nil, nil,
	}
	return json.Marshal([]any{credentialExportMagic, cred})
}

// ImportCredential reconstructs a credential exported by Export or by an
// MIT-compatible implementation. Unknown fields represented by null are
// accepted and ignored.
func ImportCredential(data []byte) (*Credential, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var top []any
	if err := decoder.Decode(&top); err != nil {
		return nil, fmt.Errorf("GSS import credential: invalid JSON: %w", err)
	}
	if len(top) != 2 || stringValue(top[0]) != credentialExportMagic {
		return nil, fmt.Errorf("GSS import credential: invalid magic")
	}
	credArray, ok := top[1].([]any)
	if !ok || len(credArray) != 14 {
		return nil, fmt.Errorf("GSS import credential: invalid credential shape")
	}
	usageNumber, err := numberValue(credArray[0])
	if err != nil || usageNumber == 0 {
		return nil, fmt.Errorf("GSS import credential: invalid usage")
	}
	name, err := importName(credArray[1])
	if err != nil {
		return nil, err
	}
	cache, cacheName, err := importCache(credArray[7])
	if err != nil {
		return nil, err
	}
	var kt *keytab.Keytab
	keytabName := stringValue(credArray[5])
	if keytabName != "" {
		kt, err = keytab.Resolve(keytabName)
		if err != nil {
			return nil, fmt.Errorf("GSS import credential keytab: %w", err)
		}
	}
	if cache == nil {
		return &Credential{
			keytab: kt, name: name, usage: CredentialUsage(usageNumber),
			keytabName: keytabName,
		}, nil
	}
	var tgt, service *client.Credentials
	for _, entry := range cache.Credentials {
		value := fromCCacheCredential(entry)
		if isTGT(entry.Server) {
			if tgt == nil {
				tgt = value
			}
		} else if service == nil {
			service = value
		}
	}
	if tgt == nil {
		tgt = service
	}
	if service == nil {
		service = tgt
	}
	if name == nil {
		value := cache.DefaultPrincipal
		name = &value
	}
	return &Credential{
		creds: service, tgt: tgt, keytab: kt, name: name,
		usage: CredentialUsage(usageNumber), cache: cache, cacheName: cacheName,
		keytabName: keytabName,
	}, nil
}

func exportCache(cache *ccache.Cache) []any {
	result := make([]any, 0, len(cache.Credentials)+1)
	result = append(result, cache.DefaultPrincipal.String())
	for _, entry := range cache.Credentials {
		addresses := make([]any, 0, len(entry.Addresses))
		for _, address := range entry.Addresses {
			addresses = append(addresses, []any{address.Type, base64.StdEncoding.EncodeToString(address.Data)})
		}
		authdata := make([]any, 0, len(entry.AuthData))
		for _, value := range entry.AuthData {
			authdata = append(authdata, []any{value.Type, base64.StdEncoding.EncodeToString(value.Data)})
		}
		result = append(result, []any{
			entry.Client.String(), entry.Server.String(),
			[]any{entry.Enctype, base64.StdEncoding.EncodeToString(entry.Key)},
			entry.AuthTime, entry.StartTime, entry.EndTime, entry.RenewTill,
			entry.IsSKey, entry.TicketFlags, addresses,
			base64.StdEncoding.EncodeToString(entry.Ticket),
			base64.StdEncoding.EncodeToString(entry.SecondTicket), authdata,
		})
	}
	return result
}

func importCache(value any) (*ccache.Cache, string, error) {
	if value == nil {
		return nil, "", nil
	}
	if name := stringValue(value); name != "" {
		handle, err := ccache.Resolve(name)
		if err != nil {
			return nil, "", fmt.Errorf("GSS import credential ccache: %w", err)
		}
		defer handle.Close()
		cache, err := handle.Read()
		if err != nil {
			return nil, "", fmt.Errorf("GSS import credential ccache: %w", err)
		}
		return cache, handle.Name(), nil
	}
	array, ok := value.([]any)
	if !ok || len(array) == 0 {
		return nil, "", fmt.Errorf("GSS import credential: invalid ccache")
	}
	defaultPrincipal, err := parsePrincipal(stringValue(array[0]))
	if err != nil {
		return nil, "", err
	}
	result := &ccache.Cache{DefaultPrincipal: defaultPrincipal}
	for index, raw := range array[1:] {
		entry, err := importCacheCredential(raw)
		if err != nil {
			return nil, "", fmt.Errorf("GSS import credential: ccache entry %d: %w", index, err)
		}
		result.Credentials = append(result.Credentials, entry)
	}
	return result, "", nil
}

func importCacheCredential(value any) (ccache.Credential, error) {
	array, ok := value.([]any)
	if !ok || len(array) != 13 {
		return ccache.Credential{}, fmt.Errorf("invalid credential shape")
	}
	clientName, err := parsePrincipal(stringValue(array[0]))
	if err != nil {
		return ccache.Credential{}, err
	}
	serverName, err := parsePrincipal(stringValue(array[1]))
	if err != nil {
		return ccache.Credential{}, err
	}
	key, err := importKey(array[2])
	if err != nil {
		return ccache.Credential{}, err
	}
	numbers := make([]uint32, 4)
	for i := range numbers {
		value, err := numberValue(array[3+i])
		if err != nil || value < 0 || value > int64(^uint32(0)) {
			return ccache.Credential{}, fmt.Errorf("invalid credential time")
		}
		numbers[i] = uint32(value)
	}
	isSKey, ok := array[7].(bool)
	if !ok {
		return ccache.Credential{}, fmt.Errorf("invalid is_skey")
	}
	flags, err := numberValue(array[8])
	if err != nil || flags < 0 || flags > int64(^uint32(0)) {
		return ccache.Credential{}, fmt.Errorf("invalid ticket flags")
	}
	addresses, err := importAddresses(array[9])
	if err != nil {
		return ccache.Credential{}, err
	}
	ticket, err := decodeBase64(array[10])
	if err != nil {
		return ccache.Credential{}, err
	}
	secondTicket, err := decodeBase64(array[11])
	if err != nil {
		return ccache.Credential{}, err
	}
	authdata, err := importAuthData(array[12])
	if err != nil {
		return ccache.Credential{}, err
	}
	return ccache.Credential{
		Client: clientName, Server: serverName, Enctype: key.enctype, Key: key.value,
		AuthTime: numbers[0], StartTime: numbers[1], EndTime: numbers[2], RenewTill: numbers[3],
		IsSKey: isSKey, TicketFlags: uint32(flags), Addresses: addresses,
		Ticket: ticket, SecondTicket: secondTicket, AuthData: authdata,
	}, nil
}

type exportedKey struct {
	enctype int32
	value   []byte
}

func importKey(value any) (exportedKey, error) {
	array, ok := value.([]any)
	if !ok || len(array) != 2 {
		return exportedKey{}, fmt.Errorf("invalid keyblock")
	}
	enctype, err := numberValue(array[0])
	if err != nil || enctype < 0 || enctype > int64(^uint32(0)) {
		return exportedKey{}, fmt.Errorf("invalid keyblock enctype")
	}
	decoded, err := decodeBase64(array[1])
	if err != nil {
		return exportedKey{}, err
	}
	return exportedKey{enctype: int32(enctype), value: decoded}, nil
}

func importAddresses(value any) ([]ccache.Address, error) {
	if value == nil {
		return nil, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("invalid addresses")
	}
	result := make([]ccache.Address, 0, len(array))
	for _, raw := range array {
		entry, ok := raw.([]any)
		if !ok || len(entry) != 2 {
			return nil, fmt.Errorf("invalid address")
		}
		addressType, err := numberValue(entry[0])
		if err != nil || addressType < 0 || addressType > int64(^uint16(0)) {
			return nil, fmt.Errorf("invalid address type")
		}
		data, err := decodeBase64(entry[1])
		if err != nil {
			return nil, err
		}
		result = append(result, ccache.Address{Type: uint16(addressType), Data: data})
	}
	return result, nil
}

func importAuthData(value any) ([]ccache.AuthData, error) {
	if value == nil {
		return nil, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("invalid authdata")
	}
	result := make([]ccache.AuthData, 0, len(array))
	for _, raw := range array {
		entry, ok := raw.([]any)
		if !ok || len(entry) != 2 {
			return nil, fmt.Errorf("invalid authdata entry")
		}
		authType, err := numberValue(entry[0])
		if err != nil || authType < 0 || authType > int64(^uint16(0)) {
			return nil, fmt.Errorf("invalid authdata type")
		}
		data, err := decodeBase64(entry[1])
		if err != nil {
			return nil, err
		}
		result = append(result, ccache.AuthData{Type: uint16(authType), Data: data})
	}
	return result, nil
}

func importName(value any) (*principal.Principal, error) {
	if value == nil {
		return nil, nil
	}
	array, ok := value.([]any)
	if !ok || len(array) != 3 {
		return nil, fmt.Errorf("GSS import credential: invalid name")
	}
	if stringValue(array[0]) == "" {
		return nil, nil
	}
	name, err := parsePrincipal(stringValue(array[0]))
	if err != nil {
		return nil, err
	}
	return &name, nil
}

func parsePrincipal(value string) (principal.Principal, error) {
	parsed, err := principal.Parse(value)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("GSS import credential principal: %w", err)
	}
	return *parsed, nil
}

func decodeBase64(value any) ([]byte, error) {
	stringValue := stringValue(value)
	if stringValue == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(stringValue)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 data: %w", err)
	}
	return decoded, nil
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if result, ok := value.(string); ok {
		return result
	}
	return ""
}

func numberValue(value any) (int64, error) {
	switch result := value.(type) {
	case json.Number:
		return strconv.ParseInt(string(result), 10, 64)
	case float64:
		return int64(result), nil
	default:
		return 0, fmt.Errorf("expected number")
	}
}

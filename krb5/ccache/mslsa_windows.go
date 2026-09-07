//go:build windows

package ccache

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/Exonical/go-kerberos/krb5/principal"
	"golang.org/x/sys/windows"
)

const (
	microsoftKerberosName            = "Kerberos"
	kerbQueryTicketCacheEx2Message   = 14
	kerbRetrieveTicketMessage        = 4
	kerbRetrieveEncodedTicketMessage = 8
	kerbRetrieveTicketCacheTicket    = 0x8
)

var (
	secur32                         = windows.NewLazySystemDLL("secur32.dll")
	procLsaConnectUntrusted         = secur32.NewProc("LsaConnectUntrusted")
	procLsaLookupAuthenticationPack = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPack   = secur32.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer         = secur32.NewProc("LsaFreeReturnBuffer")
	procLsaDeregisterLogonProcess   = secur32.NewProc("LsaDeregisterLogonProcess")
)

type mslsaLUID struct {
	LowPart  uint32
	HighPart int32
}

type mslsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint8
}

type mslsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type mslsaQueryRequest struct {
	MessageType uint32
	LogonID     mslsaLUID
}

type mslsaTicketCacheInfoEx2 struct {
	ClientName     mslsaUnicodeString
	ClientRealm    mslsaUnicodeString
	ServerName     mslsaUnicodeString
	ServerRealm    mslsaUnicodeString
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	SessionKeyType int32
	TicketFlags    uint32
}

type mslsaQueryResponse struct {
	MessageType    uint32
	CountOfTickets uint32
}

type mslsaRetrieveRequest struct {
	MessageType    uint32
	LogonID        mslsaLUID
	TargetName     mslsaUnicodeString
	TicketFlags    uint32
	CacheOptions   uint32
	EncryptionType int32
}

type mslsaCryptoKey struct {
	KeyType uint32
	Length  uint32
	Value   *uint8
}

type mslsaExternalName struct {
	NameType  uint16
	NameCount uint16
	Names     [1]mslsaUnicodeString
}

type mslsaExternalTicket struct {
	ServiceName         *mslsaExternalName
	TargetName          *mslsaExternalName
	ClientName          *mslsaExternalName
	DomainName          mslsaUnicodeString
	TargetDomainName    mslsaUnicodeString
	AltTargetDomainName mslsaUnicodeString
	SessionKey          mslsaCryptoKey
	TicketFlags         uint32
	Flags               uint32
	KeyExpirationTime   int64
	StartTime           int64
	EndTime             int64
	RenewUntil          int64
	TimeSkew            int64
	EncodedTicketSize   uint32
	EncodedTicket       *uint8
}

type mslsaRetrieveResponse struct {
	Ticket mslsaExternalTicket
}

func resolveMSLSA(string) (*Handle, error) {
	return &Handle{typ: TypeMSLSA, name: "MSLSA:", mslsa: &mslsaHandle{}}, nil
}

func (h *mslsaHandle) read() (*Cache, error) {
	handle, packageID, err := mslsaConnect()
	if err != nil {
		return nil, err
	}
	defer mslsaDeregister(handle)

	response, responseSize, err := mslsaQuery(handle, packageID)
	if err != nil {
		return nil, err
	}
	defer mslsaFree(response)
	if responseSize < uint32(unsafe.Sizeof(mslsaQueryResponse{})) { // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		return nil, errors.New("ccache: malformed MSLSA ticket-cache response")
	}
	header := (*mslsaQueryResponse)(response)
	entrySize := unsafe.Sizeof(mslsaTicketCacheInfoEx2{})                                                      // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	if uint64(header.CountOfTickets)*uint64(entrySize)+uint64(unsafe.Sizeof(*header)) > uint64(responseSize) { // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		return nil, errors.New("ccache: malformed MSLSA ticket-cache count")
	}
	entries := unsafe.Slice((*mslsaTicketCacheInfoEx2)(unsafe.Add(response, unsafe.Sizeof(*header))), header.CountOfTickets) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	cache := &Cache{}
	if ticket, response, err := mslsaRetrieveTGT(handle, packageID); err == nil {
		if client, err := mslsaExternalNamePrincipal(ticket.ClientName, ticket.DomainName); err == nil {
			cache.DefaultPrincipal = client
		}
		mslsaFree(response)
	}
	for i := range entries {
		info := entries[i]
		if len(cache.DefaultPrincipal.Components) == 0 {
			if client, err := mslsaUnicodePrincipal(info.ClientName, info.ClientRealm); err == nil {
				cache.DefaultPrincipal = client
			}
		}
		ticket, response, err := mslsaRetrieve(handle, packageID, info)
		if err != nil {
			continue
		}
		credential, err := mslsaExternalCredential(ticket)
		mslsaFree(response)
		if err != nil {
			if errors.Is(err, errMSLSANullSessionKey) {
				continue
			}
			continue
		}
		cache.Credentials = append(cache.Credentials, credential)
	}
	return cache, nil
}

var errMSLSANullSessionKey = errors.New("ccache: MSLSA ticket has no session key")

func mslsaConnect() (windows.Handle, uint32, error) {
	var handle windows.Handle
	status, _, _ := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&handle))) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	if mslsaFailed(uint32(status)) {
		return 0, 0, fmt.Errorf("ccache: LsaConnectUntrusted: %w", mslsaStatusError(uint32(status)))
	}
	nameBytes := []byte(microsoftKerberosName)
	name := mslsaString{Length: uint16(len(nameBytes)), MaximumLength: uint16(len(nameBytes) + 1), Buffer: &nameBytes[0]}
	var packageID uint32
	status, _, _ = procLsaLookupAuthenticationPack.Call(uintptr(handle), uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&packageID))) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	if mslsaFailed(uint32(status)) {
		mslsaDeregister(handle)
		return 0, 0, fmt.Errorf("ccache: LsaLookupAuthenticationPackage: %w", mslsaStatusError(uint32(status)))
	}
	return handle, packageID, nil
}

func mslsaQuery(handle windows.Handle, packageID uint32) (unsafe.Pointer, uint32, error) {
	request := mslsaQueryRequest{MessageType: kerbQueryTicketCacheEx2Message}
	var response unsafe.Pointer
	var responseSize uint32
	var subStatus uint32
	status, _, _ := procLsaCallAuthenticationPack.Call(
		uintptr(handle), uintptr(packageID), uintptr(unsafe.Pointer(&request)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		uintptr(unsafe.Sizeof(request)), uintptr(unsafe.Pointer(&response)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		uintptr(unsafe.Pointer(&responseSize)), uintptr(unsafe.Pointer(&subStatus)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	)
	if mslsaFailed(uint32(status)) || mslsaFailed(subStatus) {
		return nil, 0, fmt.Errorf("ccache: LsaCallAuthenticationPackage query failed: %w", mslsaStatusError(firstMSLSAStatus(uint32(status), subStatus)))
	}
	return response, responseSize, nil
}

func mslsaRetrieve(handle windows.Handle, packageID uint32, info mslsaTicketCacheInfoEx2) (*mslsaExternalTicket, unsafe.Pointer, error) {
	target, _ := windows.UTF16FromString(mslsaUnicodeStringValue(info.ServerName) + "@" + mslsaUnicodeStringValue(info.ServerRealm))
	target = target[:len(target)-1]
	requestSize := int(unsafe.Sizeof(mslsaRetrieveRequest{})) + len(target)*2 // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	buffer := make([]byte, requestSize)
	request := (*mslsaRetrieveRequest)(unsafe.Pointer(&buffer[0])) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	request.MessageType = kerbRetrieveEncodedTicketMessage
	request.CacheOptions = kerbRetrieveTicketCacheTicket
	request.EncryptionType = info.SessionKeyType
	request.TicketFlags = info.TicketFlags
	request.TargetName = mslsaUnicodeString{
		Length: uint16(len(target) * 2), MaximumLength: uint16(len(target) * 2),
		Buffer: &target[0],
	}
	var response unsafe.Pointer
	var responseSize uint32
	var subStatus uint32
	status, _, _ := procLsaCallAuthenticationPack.Call(
		uintptr(handle), uintptr(packageID), uintptr(unsafe.Pointer(request)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		uintptr(len(buffer)), uintptr(unsafe.Pointer(&response)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		uintptr(unsafe.Pointer(&responseSize)), uintptr(unsafe.Pointer(&subStatus)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	)
	if mslsaFailed(uint32(status)) || mslsaFailed(subStatus) {
		return nil, nil, fmt.Errorf("ccache: LsaCallAuthenticationPackage retrieve failed: %w", mslsaStatusError(firstMSLSAStatus(uint32(status), subStatus)))
	}
	if responseSize < uint32(unsafe.Sizeof(mslsaRetrieveResponse{})) { // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		mslsaFree(response)
		return nil, nil, errors.New("ccache: malformed MSLSA ticket response")
	}
	return &(*mslsaRetrieveResponse)(response).Ticket, response, nil
}

func mslsaRetrieveTGT(handle windows.Handle, packageID uint32) (*mslsaExternalTicket, unsafe.Pointer, error) {
	request := mslsaQueryRequest{MessageType: kerbRetrieveTicketMessage}
	var response unsafe.Pointer
	var responseSize uint32
	var subStatus uint32
	status, _, _ := procLsaCallAuthenticationPack.Call(
		uintptr(handle), uintptr(packageID), uintptr(unsafe.Pointer(&request)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		uintptr(unsafe.Sizeof(request)), uintptr(unsafe.Pointer(&response)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		uintptr(unsafe.Pointer(&responseSize)), uintptr(unsafe.Pointer(&subStatus)), // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	)
	if mslsaFailed(uint32(status)) || mslsaFailed(subStatus) {
		return nil, nil, fmt.Errorf("ccache: MSLSA TGT retrieval failed: %w", mslsaStatusError(firstMSLSAStatus(uint32(status), subStatus)))
	}
	if responseSize < uint32(unsafe.Sizeof(mslsaRetrieveResponse{})) { // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
		mslsaFree(response)
		return nil, nil, errors.New("ccache: malformed MSLSA TGT response")
	}
	return &(*mslsaRetrieveResponse)(response).Ticket, response, nil
}

func mslsaExternalCredential(ticket *mslsaExternalTicket) (Credential, error) {
	client, err := mslsaExternalNamePrincipal(ticket.ClientName, ticket.DomainName)
	if err != nil {
		return Credential{}, err
	}
	service, err := mslsaExternalNamePrincipal(ticket.ServiceName, ticket.DomainName)
	if err != nil {
		return Credential{}, err
	}
	key := unsafe.Slice(ticket.SessionKey.Value, ticket.SessionKey.Length) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	if mslsaSessionKeyNull(int32(ticket.SessionKey.KeyType), key) {
		return Credential{}, errMSLSANullSessionKey
	}
	encoded := unsafe.Slice(ticket.EncodedTicket, ticket.EncodedTicketSize) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	return Credential{
		Client: client, Server: service, Enctype: int32(ticket.SessionKey.KeyType),
		Key: append([]byte(nil), key...), TicketFlags: ticket.TicketFlags,
		StartTime: mslsaFileTimeToUnix(ticket.StartTime), EndTime: mslsaFileTimeToUnix(ticket.EndTime),
		RenewTill: mslsaFileTimeToUnix(ticket.RenewUntil), Ticket: append([]byte(nil), encoded...),
	}, nil
}

func mslsaExternalNamePrincipal(name *mslsaExternalName, realm mslsaUnicodeString) (principal.Principal, error) {
	if name == nil || name.NameCount == 0 {
		return principal.Principal{}, errors.New("ccache: MSLSA ticket has no service principal")
	}
	components := make([]string, 0, name.NameCount)
	names := unsafe.Slice(&name.Names[0], int(name.NameCount)) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
	for _, component := range names {
		components = append(components, mslsaUnicodeStringValue(component))
	}
	return mslsaPrincipal(mslsaName{Components: components}, mslsaUnicodeStringValue(realm))
}

func mslsaUnicodePrincipal(name, realm mslsaUnicodeString) (principal.Principal, error) {
	return mslsaPrincipalString(mslsaUnicodeStringValue(name), mslsaUnicodeStringValue(realm))
}

func mslsaUnicodeStringValue(value mslsaUnicodeString) string {
	if value.Buffer == nil || value.Length == 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(value.Buffer, value.Length/2)) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.use-of-unsafe-block -- required for Win32 LSA ABI pointers and lazy syscall calls
}

func mslsaUTF16String(value mslsaUnicodeString) []uint16 {
	result, _ := windows.UTF16FromString(mslsaUnicodeStringValue(value))
	return result[:len(result)-1]
}

func mslsaFree(value unsafe.Pointer) {
	if value != nil {
		_, _, _ = procLsaFreeReturnBuffer.Call(uintptr(value))
	}
}

func mslsaDeregister(handle windows.Handle) {
	if handle != 0 {
		_, _, _ = procLsaDeregisterLogonProcess.Call(uintptr(handle))
	}
}

func mslsaFailed(status uint32) bool { return int32(status) < 0 }

func firstMSLSAStatus(status, subStatus uint32) uint32 {
	if mslsaFailed(status) {
		return status
	}
	return subStatus
}

func mslsaStatusError(status uint32) error {
	return fmt.Errorf("NTSTATUS 0x%08x", status)
}

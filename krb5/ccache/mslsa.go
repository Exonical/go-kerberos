package ccache

import (
	"errors"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

// ErrMSLSAReadOnly reports an attempted mutation of the Windows MSLSA cache.
var ErrMSLSAReadOnly = errors.New("ccache: MSLSA is read-only in this implementation")

type mslsaHandle struct{}

type mslsaName struct {
	Components []string
}

type mslsaTicketData struct {
	ClientName     mslsaName
	ClientRealm    string
	ServiceName    mslsaName
	ServiceRealm   string
	SessionKeyType int32
	SessionKey     []byte
	TicketFlags    uint32
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncodedTicket  []byte
}

type mslsaCacheInfo struct {
	ClientName     string
	ClientRealm    string
	ServerName     string
	ServerRealm    string
	SessionKeyType int32
	TicketFlags    uint32
	StartTime      int64
	EndTime        int64
	RenewTime      int64
}

func mslsaPrincipal(name mslsaName, realm string) (principal.Principal, error) {
	if len(name.Components) == 0 || realm == "" {
		return principal.Principal{}, errors.New("ccache: MSLSA principal is incomplete")
	}
	return principal.Principal{
		Realm:      realm,
		NameType:   principal.NTPrincipal,
		Components: append([]string(nil), name.Components...),
	}, nil
}

func mslsaPrincipalString(name, realm string) (principal.Principal, error) {
	components := strings.Split(name, "/")
	return mslsaPrincipal(mslsaName{Components: components}, realm)
}

func mslsaFileTimeToUnix(ft int64) uint32 {
	const windowsToUnixSeconds = 11644473600
	if ft <= windowsToUnixSeconds*10000000 {
		return 0
	}
	return uint32(ft/10000000 - windowsToUnixSeconds)
}

func mslsaSessionKeyNull(enctype int32, key []byte) bool {
	if enctype == 0 || len(key) == 0 {
		return true
	}
	for _, value := range key {
		if value != 0 {
			return false
		}
	}
	return true
}

func mslsaCacheInfoCredential(info mslsaCacheInfo) (Credential, error) {
	client, err := mslsaPrincipalString(info.ClientName, info.ClientRealm)
	if err != nil {
		return Credential{}, err
	}
	server, err := mslsaPrincipalString(info.ServerName, info.ServerRealm)
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		Client:      client,
		Server:      server,
		Enctype:     info.SessionKeyType,
		TicketFlags: info.TicketFlags,
		AuthTime:    mslsaFileTimeToUnix(info.StartTime),
		StartTime:   mslsaFileTimeToUnix(info.StartTime),
		EndTime:     mslsaFileTimeToUnix(info.EndTime),
		RenewTill:   mslsaFileTimeToUnix(info.RenewTime),
	}, nil
}

func mslsaTicketCredential(ticket mslsaTicketData) (Credential, error) {
	client, err := mslsaPrincipal(ticket.ClientName, ticket.ClientRealm)
	if err != nil {
		return Credential{}, err
	}
	server, err := mslsaPrincipal(ticket.ServiceName, ticket.ServiceRealm)
	if err != nil {
		return Credential{}, err
	}
	if mslsaSessionKeyNull(ticket.SessionKeyType, ticket.SessionKey) {
		return Credential{}, errors.New("ccache: MSLSA ticket has no session key")
	}
	return Credential{
		Client:      client,
		Server:      server,
		Enctype:     ticket.SessionKeyType,
		Key:         append([]byte(nil), ticket.SessionKey...),
		TicketFlags: ticket.TicketFlags,
		StartTime:   mslsaFileTimeToUnix(ticket.StartTime),
		EndTime:     mslsaFileTimeToUnix(ticket.EndTime),
		RenewTill:   mslsaFileTimeToUnix(ticket.RenewTime),
		Ticket:      append([]byte(nil), ticket.EncodedTicket...),
	}, nil
}

func (h *mslsaHandle) write(*Cache) error { return ErrMSLSAReadOnly }
func (h *mslsaHandle) initialize(principal.Principal) error {
	return ErrMSLSAReadOnly
}
func (h *mslsaHandle) store(Credential) error { return ErrMSLSAReadOnly }
func (h *mslsaHandle) remove(Credential, uint32) error {
	return ErrMSLSAReadOnly
}
func (h *mslsaHandle) destroy() error { return ErrMSLSAReadOnly }

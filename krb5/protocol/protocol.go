package protocol

// The structures in this file are compile-time protocol placeholders. Their
// wire representation is defined by RFC 4120 and is implemented later.

type PrincipalName struct {
	NameType   int32
	NameString []string
}
type HostAddress struct{}
type HostAddresses struct{}
type AuthorizationData struct{}
type PAData struct{}
type EncryptedData struct{}
type EncryptionKey struct{}
type Checksum struct{}
type Ticket struct{}
type EncTicketPart struct{}
type Authenticator struct{}
type KDCReq struct{}
type KDCReqBody struct{}
type ASReq struct{}
type TGSReq struct{}
type KDCRep struct{}
type ASRep struct{}
type TGSRep struct{}
type EncASRepPart struct{}
type EncTGSRepPart struct{}
type APReq struct{}
type APRep struct{}
type EncAPRepPart struct{}
type KRBError struct{}
type MethodData struct{}
type ETypeInfo struct{}
type ETypeInfo2 struct{}
type ETypeInfo2Entry struct{}
type LastReq struct{}
type TransitedEncoding struct{}

// RFC 4120 application tag numbers (section 5.10).
const (
	TagTicket        = 1
	TagAuthenticator = 2
	TagEncTicketPart = 3
	TagASReq         = 10
	TagASRep         = 11
	TagTGSReq        = 12
	TagTGSRep        = 13
	TagAPReq         = 14
	TagAPRep         = 15
	TagEncASRepPart  = 25
	TagEncTGSRepPart = 26
	TagEncAPRepPart  = 27
	TagKRBError      = 30
)

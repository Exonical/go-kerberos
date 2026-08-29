package protocol

import "github.com/Exonical/go-kerberos/krb5/types"

// PrincipalName is the structured name of a Kerberos principal.
type PrincipalName struct {
	NameType   int32    `krb5:"tag:0"`
	NameString []string `krb5:"tag:1"`
}

type HostAddress struct {
	AddrType int32  `krb5:"tag:0"`
	Address  []byte `krb5:"tag:1"`
}

type HostAddresses []HostAddress

type AuthorizationDataEntry struct {
	ADType int32  `krb5:"tag:0"`
	ADData []byte `krb5:"tag:1"`
}

type AuthorizationData []AuthorizationDataEntry

type PAData struct {
	PADataType  int32  `krb5:"tag:1"`
	PADataValue []byte `krb5:"tag:2"`
}

// OTPTokenInfo describes an RFC 6560 token accepted by the KDC.
type OTPTokenInfo struct {
	Flags          int32             `krb5:"tag:0,implicit"`
	Vendor         *types.UTF8String `krb5:"tag:1,optional,implicit"`
	Challenge      []byte            `krb5:"tag:2,optional,implicit"`
	Length         *int32            `krb5:"tag:3,optional,implicit"`
	Format         *int32            `krb5:"tag:4,optional,implicit"`
	TokenID        []byte            `krb5:"tag:5,optional,implicit"`
	AlgID          *types.UTF8String `krb5:"tag:6,optional,implicit"`
	IterationCount *int32            `krb5:"tag:8,optional,implicit"`
}

// PAOTPChallenge is the PA-OTP-CHALLENGE payload.
type PAOTPChallenge struct {
	Nonce     []byte            `krb5:"tag:0,implicit"`
	Service   *types.UTF8String `krb5:"tag:1,optional,implicit"`
	TokenInfo []OTPTokenInfo    `krb5:"tag:2,implicit"`
	Salt      *string           `krb5:"tag:3,optional,implicit"`
	S2KParams []byte            `krb5:"tag:4,optional,implicit"`
}

// PAOTPRequest is the PA-OTP-REQUEST payload.
type PAOTPRequest struct {
	Flags          int32               `krb5:"tag:0,implicit"`
	Nonce          []byte              `krb5:"tag:1,optional,implicit"`
	EncData        EncryptedData       `krb5:"tag:2,implicit"`
	IterationCount *int32              `krb5:"tag:4,optional,implicit"`
	OTPValue       []byte              `krb5:"tag:5,optional,implicit"`
	PIN            *types.UTF8String   `krb5:"tag:6,optional,implicit"`
	Challenge      []byte              `krb5:"tag:7,optional,implicit"`
	Time           *types.KerberosTime `krb5:"tag:8,optional,implicit"`
	Counter        []byte              `krb5:"tag:9,optional,implicit"`
	Format         *int32              `krb5:"tag:10,optional,implicit"`
	TokenID        []byte              `krb5:"tag:11,optional,implicit"`
	AlgID          *types.UTF8String   `krb5:"tag:12,optional,implicit"`
	Vendor         *types.UTF8String   `krb5:"tag:13,optional,implicit"`
}

// PAOTPEncRequest is the encrypted nonce wrapper used by MIT.
type PAOTPEncRequest struct {
	Nonce []byte `krb5:"tag:0,implicit"`
}

const (
	// PADataSPAKE is the RFC PA-SPAKE padata type.
	PADataSPAKE int32 = 151
	// PADataFXCookie is the RFC PA-FX-COOKIE padata type.
	PADataFXCookie int32 = 133
)

// SPAKESecondFactor is the RFC PA-SPAKE second-factor choice.
type SPAKESecondFactor struct {
	Type int32  `krb5:"tag:0"`
	Data []byte `krb5:"tag:1,optional"`
}

// SPAKESupport advertises the groups supported by a client.
type SPAKESupport struct {
	Groups []int32 `krb5:"tag:0"`
}

// SPAKEChallenge selects a group and carries the KDC public value.
type SPAKEChallenge struct {
	Group   int32               `krb5:"tag:0"`
	PubKey  []byte              `krb5:"tag:1"`
	Factors []SPAKESecondFactor `krb5:"tag:2"`
}

// SPAKEResponse carries the client public value and encrypted factor.
type SPAKEResponse struct {
	PubKey []byte        `krb5:"tag:0"`
	Factor EncryptedData `krb5:"tag:1"`
}

// PASPAKE is the PA-SPAKE CHOICE.
type PASPAKE struct {
	Support   *SPAKESupport   `krb5:"tag:0,choice"`
	Challenge *SPAKEChallenge `krb5:"tag:1,choice"`
	Response  *SPAKEResponse  `krb5:"tag:2,choice"`
	EncData   *EncryptedData  `krb5:"tag:3,choice"`
}

type EncryptedData struct {
	EType  int32   `krb5:"tag:0"`
	KVNO   *uint32 `krb5:"tag:1,optional"`
	Cipher []byte  `krb5:"tag:2"`
}

type EncryptionKey struct {
	KeyType  int32  `krb5:"tag:0"`
	KeyValue []byte `krb5:"tag:1"`
}

// ChangePasswdData is the RFC 3244 set-password KRB-PRIV user-data.
type ChangePasswdData struct {
	NewPassword []byte         `krb5:"tag:0"`
	TargetName  *PrincipalName `krb5:"tag:1,optional"`
	TargetRealm *string        `krb5:"tag:2,optional"`
}

type Checksum struct {
	ChecksumType int32  `krb5:"tag:0"`
	Checksum     []byte `krb5:"tag:1"`
}

type Ticket struct {
	TktVNO  int32         `krb5:"tag:0"`
	Realm   string        `krb5:"tag:1"`
	SName   PrincipalName `krb5:"tag:2"`
	EncPart EncryptedData `krb5:"tag:3"`
}

func (Ticket) ApplicationTag() int { return TagTicket }

type EncTicketPart struct {
	Flags             types.TicketFlags   `krb5:"tag:0"`
	Key               EncryptionKey       `krb5:"tag:1"`
	CRealm            string              `krb5:"tag:2"`
	CName             PrincipalName       `krb5:"tag:3"`
	Transited         TransitedEncoding   `krb5:"tag:4"`
	AuthTime          types.KerberosTime  `krb5:"tag:5"`
	StartTime         *types.KerberosTime `krb5:"tag:6,optional"`
	EndTime           types.KerberosTime  `krb5:"tag:7"`
	RenewTill         *types.KerberosTime `krb5:"tag:8,optional"`
	CAddr             HostAddresses       `krb5:"tag:9,optional"`
	AuthorizationData AuthorizationData   `krb5:"tag:10,optional"`
}

func (EncTicketPart) ApplicationTag() int { return TagEncTicketPart }

type Authenticator struct {
	AuthenticatorVNO  int32              `krb5:"tag:0"`
	CRealm            string             `krb5:"tag:1"`
	CName             PrincipalName      `krb5:"tag:2"`
	Checksum          *Checksum          `krb5:"tag:3,optional"`
	Cusec             int32              `krb5:"tag:4"`
	Ctime             types.KerberosTime `krb5:"tag:5"`
	SubKey            *EncryptionKey     `krb5:"tag:6,optional"`
	SeqNumber         *uint32            `krb5:"tag:7,optional"`
	AuthorizationData AuthorizationData  `krb5:"tag:8,optional"`
}

func (Authenticator) ApplicationTag() int { return TagAuthenticator }

type KDCReq struct {
	PVNO    int32      `krb5:"tag:1"`
	MsgType int32      `krb5:"tag:2"`
	PAData  MethodData `krb5:"tag:3,optional"`
	ReqBody KDCReqBody `krb5:"tag:4"`
}

type KDCReqBody struct {
	KDCOptions           types.KDCOptions    `krb5:"tag:0"`
	CName                *PrincipalName      `krb5:"tag:1,optional"`
	Realm                string              `krb5:"tag:2"`
	SName                *PrincipalName      `krb5:"tag:3,optional"`
	From                 *types.KerberosTime `krb5:"tag:4,optional"`
	Till                 types.KerberosTime  `krb5:"tag:5"`
	RTime                *types.KerberosTime `krb5:"tag:6,optional"`
	Nonce                uint32              `krb5:"tag:7"`
	EType                []int32             `krb5:"tag:8"`
	Addresses            HostAddresses       `krb5:"tag:9,optional"`
	EncAuthorizationData *EncryptedData      `krb5:"tag:10,optional"`
	AdditionalTickets    []Ticket            `krb5:"tag:11,optional"`
}

type ASReq struct {
	PVNO    int32      `krb5:"tag:1"`
	MsgType int32      `krb5:"tag:2"`
	PAData  MethodData `krb5:"tag:3,optional"`
	ReqBody KDCReqBody `krb5:"tag:4"`
}

func (ASReq) ApplicationTag() int { return TagASReq }

type TGSReq struct {
	PVNO    int32      `krb5:"tag:1"`
	MsgType int32      `krb5:"tag:2"`
	PAData  MethodData `krb5:"tag:3,optional"`
	ReqBody KDCReqBody `krb5:"tag:4"`
}

func (TGSReq) ApplicationTag() int { return TagTGSReq }

type KDCRep struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	PAData  MethodData    `krb5:"tag:2,optional"`
	CRealm  string        `krb5:"tag:3"`
	CName   PrincipalName `krb5:"tag:4"`
	Ticket  Ticket        `krb5:"tag:5"`
	EncPart EncryptedData `krb5:"tag:6"`
}

type ASRep struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	PAData  MethodData    `krb5:"tag:2,optional"`
	CRealm  string        `krb5:"tag:3"`
	CName   PrincipalName `krb5:"tag:4"`
	Ticket  Ticket        `krb5:"tag:5"`
	EncPart EncryptedData `krb5:"tag:6"`
}

func (ASRep) ApplicationTag() int { return TagASRep }

type TGSRep struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	PAData  MethodData    `krb5:"tag:2,optional"`
	CRealm  string        `krb5:"tag:3"`
	CName   PrincipalName `krb5:"tag:4"`
	Ticket  Ticket        `krb5:"tag:5"`
	EncPart EncryptedData `krb5:"tag:6"`
}

func (TGSRep) ApplicationTag() int { return TagTGSRep }

type EncASRepPart struct {
	Key           EncryptionKey       `krb5:"tag:0"`
	LastReq       LastReq             `krb5:"tag:1"`
	Nonce         uint32              `krb5:"tag:2"`
	KeyExpiration *types.KerberosTime `krb5:"tag:3,optional"`
	Flags         types.TicketFlags   `krb5:"tag:4"`
	AuthTime      types.KerberosTime  `krb5:"tag:5"`
	StartTime     *types.KerberosTime `krb5:"tag:6,optional"`
	EndTime       types.KerberosTime  `krb5:"tag:7"`
	RenewTill     *types.KerberosTime `krb5:"tag:8,optional"`
	SRealm        string              `krb5:"tag:9"`
	SName         PrincipalName       `krb5:"tag:10"`
	CAddr         HostAddresses       `krb5:"tag:11,optional"`
}

func (EncASRepPart) ApplicationTag() int { return TagEncASRepPart }

type EncTGSRepPart struct {
	Key           EncryptionKey       `krb5:"tag:0"`
	LastReq       LastReq             `krb5:"tag:1"`
	Nonce         uint32              `krb5:"tag:2"`
	KeyExpiration *types.KerberosTime `krb5:"tag:3,optional"`
	Flags         types.TicketFlags   `krb5:"tag:4"`
	AuthTime      types.KerberosTime  `krb5:"tag:5"`
	StartTime     *types.KerberosTime `krb5:"tag:6,optional"`
	EndTime       types.KerberosTime  `krb5:"tag:7"`
	RenewTill     *types.KerberosTime `krb5:"tag:8,optional"`
	SRealm        string              `krb5:"tag:9"`
	SName         PrincipalName       `krb5:"tag:10"`
	CAddr         HostAddresses       `krb5:"tag:11,optional"`
}

func (EncTGSRepPart) ApplicationTag() int { return TagEncTGSRepPart }

type APReq struct {
	PVNO          int32           `krb5:"tag:0"`
	MsgType       int32           `krb5:"tag:1"`
	APOptions     types.APOptions `krb5:"tag:2"`
	Ticket        Ticket          `krb5:"tag:3"`
	Authenticator EncryptedData   `krb5:"tag:4"`
}

func (APReq) ApplicationTag() int { return TagAPReq }

type APRep struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	EncPart EncryptedData `krb5:"tag:2"`
}

func (APRep) ApplicationTag() int { return TagAPRep }

type KRBPriv struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	EncPart EncryptedData `krb5:"tag:3"`
}

func (KRBPriv) ApplicationTag() int { return TagKRBPriv }

type KRBSafe struct {
	PVNO     int32    `krb5:"tag:0"`
	MsgType  int32    `krb5:"tag:1"`
	SafeBody SafeBody `krb5:"tag:2"`
	Checksum Checksum `krb5:"tag:3"`
}

func (KRBSafe) ApplicationTag() int { return TagKRBSafe }

type SafeBody struct {
	UserData  []byte              `krb5:"tag:0"`
	Timestamp *types.KerberosTime `krb5:"tag:1,optional"`
	Usec      *int32              `krb5:"tag:2,optional"`
	SeqNumber *uint32             `krb5:"tag:3,optional"`
	SAddress  HostAddress         `krb5:"tag:4"`
	RAddress  *HostAddress        `krb5:"tag:5,optional"`
}

type EncAPRepPart struct {
	Ctime     types.KerberosTime `krb5:"tag:0"`
	Cusec     int32              `krb5:"tag:1"`
	SubKey    *EncryptionKey     `krb5:"tag:2,optional"`
	SeqNumber *uint32            `krb5:"tag:3,optional"`
}

func (EncAPRepPart) ApplicationTag() int { return TagEncAPRepPart }

type EncKRBPrivPart struct {
	UserData  []byte              `krb5:"tag:0"`
	Timestamp *types.KerberosTime `krb5:"tag:1,optional"`
	Usec      *int32              `krb5:"tag:2,optional"`
	SeqNumber *uint32             `krb5:"tag:3,optional"`
	SAddress  HostAddress         `krb5:"tag:4"`
	RAddress  *HostAddress        `krb5:"tag:5,optional"`
}

func (EncKRBPrivPart) ApplicationTag() int { return TagEncKRBPrivPart }

// KRBCred is the RFC 4120 forwarded-credentials message.
type KRBCred struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	Tickets []Ticket      `krb5:"tag:2"`
	EncPart EncryptedData `krb5:"tag:3"`
}

func (KRBCred) ApplicationTag() int { return TagKRBCred }

// EncKrbCredPart is the encrypted part of a KRB-CRED message.
type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo       `krb5:"tag:0"`
	Nonce      *uint32             `krb5:"tag:1,optional"`
	Timestamp  *types.KerberosTime `krb5:"tag:2,optional"`
	Usec       *int32              `krb5:"tag:3,optional"`
	SAddress   *HostAddress        `krb5:"tag:4,optional"`
	RAddress   *HostAddress        `krb5:"tag:5,optional"`
}

func (EncKrbCredPart) ApplicationTag() int { return TagEncKrbCredPart }

// KrbCredInfo describes one ticket carried by a KRB-CRED message.
type KrbCredInfo struct {
	Key       EncryptionKey       `krb5:"tag:0"`
	Prealm    *string             `krb5:"tag:1,optional"`
	PName     *PrincipalName      `krb5:"tag:2,optional"`
	Flags     *types.TicketFlags  `krb5:"tag:3,optional"`
	AuthTime  *types.KerberosTime `krb5:"tag:4,optional"`
	StartTime *types.KerberosTime `krb5:"tag:5,optional"`
	EndTime   *types.KerberosTime `krb5:"tag:6,optional"`
	RenewTill *types.KerberosTime `krb5:"tag:7,optional"`
	SRealm    *string             `krb5:"tag:8,optional"`
	SName     *PrincipalName      `krb5:"tag:9,optional"`
	CAddr     HostAddresses       `krb5:"tag:10,optional"`
}

type KRBError struct {
	PVNO      int32               `krb5:"tag:0"`
	MsgType   int32               `krb5:"tag:1"`
	CTime     *types.KerberosTime `krb5:"tag:2,optional"`
	Cusec     *int32              `krb5:"tag:3,optional"`
	STime     types.KerberosTime  `krb5:"tag:4"`
	Susec     int32               `krb5:"tag:5"`
	ErrorCode int32               `krb5:"tag:6"`
	CRealm    *string             `krb5:"tag:7,optional"`
	CName     *PrincipalName      `krb5:"tag:8,optional"`
	Realm     string              `krb5:"tag:9"`
	SName     PrincipalName       `krb5:"tag:10"`
	EText     *string             `krb5:"tag:11,optional"`
	EData     []byte              `krb5:"tag:12,optional"`
}

func (KRBError) ApplicationTag() int { return TagKRBError }

type MethodData []PAData

// Protocol transition padata types ([MS-SFU] section 2.2).
const (
	PADataForUser     = 129
	PADataS4UX509User = 130
)

// S4UOptionsUseReplyKeyUsage asks the KDC to sign the PA-S4U-X509-USER reply
// with key usage 27 instead of 26 ([MS-SFU] section 2.2.1).
const S4UOptionsUseReplyKeyUsage = types.KDCOptions(1 << 2)

// S4UUserID identifies the impersonated user of a protocol transition
// request ([MS-SFU] section 2.2.1).
type S4UUserID struct {
	Nonce       uint32            `krb5:"tag:0"`
	CName       *PrincipalName    `krb5:"tag:1,optional"`
	CRealm      string            `krb5:"tag:2"`
	SubjectCert []byte            `krb5:"tag:3,optional"`
	Options     *types.KDCOptions `krb5:"tag:4,optional"`
}

// PAS4UX509User carries an S4UUserID and its keyed checksum.
type PAS4UX509User struct {
	UserID   S4UUserID `krb5:"tag:0"`
	Checksum Checksum  `krb5:"tag:1"`
}

// PAForUser is the legacy Microsoft protocol-transition request.
type PAForUser struct {
	UserName    PrincipalName `krb5:"tag:0"`
	UserRealm   string        `krb5:"tag:1"`
	Checksum    Checksum      `krb5:"tag:2"`
	AuthPackage string        `krb5:"tag:3"`
}

// FastOptions contains RFC 6113 FAST option bits.
type FastOptions = types.KDCOptions

// KrbFastArmor identifies the armor used by a FAST request.
type KrbFastArmor struct {
	ArmorType  int32  `krb5:"tag:0"`
	ArmorValue []byte `krb5:"tag:1"`
}

// KrbFastArmoredReq contains an armored FAST request.
type KrbFastArmoredReq struct {
	Armor       *KrbFastArmor `krb5:"tag:0,optional"`
	ReqChecksum Checksum      `krb5:"tag:1"`
	EncFastReq  EncryptedData `krb5:"tag:2"`
}

// PAFXFastRequest is the PA-FX-FAST request choice payload.
type PAFXFastRequest struct {
	ArmoredData KrbFastArmoredReq `krb5:"tag:0,choice"`
}

// KrbFastReq is the encrypted inner FAST request.
type KrbFastReq struct {
	FastOptions FastOptions `krb5:"tag:0"`
	PAData      MethodData  `krb5:"tag:1"`
	ReqBody     KDCReqBody  `krb5:"tag:2"`
}

// KrbFastArmoredRep contains an armored FAST response.
type KrbFastArmoredRep struct {
	EncFastRep EncryptedData `krb5:"tag:0"`
}

// PAFXFastReply is the PA-FX-FAST reply choice payload.
type PAFXFastReply struct {
	ArmoredData KrbFastArmoredRep `krb5:"tag:0,choice"`
}

// KrbFastResponse is the encrypted FAST response.
type KrbFastResponse struct {
	PAData        MethodData       `krb5:"tag:0"`
	StrengthenKey *EncryptionKey   `krb5:"tag:1,optional"`
	Finished      *KrbFastFinished `krb5:"tag:2,optional"`
	Nonce         uint32           `krb5:"tag:3"`
}

// KrbFastFinished authenticates a completed FAST reply.
type KrbFastFinished struct {
	Timestamp      types.KerberosTime `krb5:"tag:0"`
	Usec           int32              `krb5:"tag:1"`
	CRealm         string             `krb5:"tag:2"`
	CName          PrincipalName      `krb5:"tag:3"`
	TicketChecksum Checksum           `krb5:"tag:4"`
}

type ETypeInfoEntry struct {
	EType int32   `krb5:"tag:0"`
	Salt  *[]byte `krb5:"tag:1,optional"`
}

type ETypeInfo []ETypeInfoEntry

type ETypeInfo2Entry struct {
	EType     int32   `krb5:"tag:0"`
	Salt      *string `krb5:"tag:1,optional"`
	S2KParams []byte  `krb5:"tag:2,optional"`
}

type ETypeInfo2 []ETypeInfo2Entry

type LastReqEntry struct {
	LRType  int32              `krb5:"tag:0"`
	LRValue types.KerberosTime `krb5:"tag:1"`
}

type LastReq []LastReqEntry

type TransitedEncoding struct {
	TrType   int32  `krb5:"tag:0"`
	Contents []byte `krb5:"tag:1"`
}

// RFC 4120 application tag numbers (section 5.10).
const (
	TagTicket         = 1
	TagAuthenticator  = 2
	TagEncTicketPart  = 3
	TagASReq          = 10
	TagASRep          = 11
	TagTGSReq         = 12
	TagTGSRep         = 13
	TagAPReq          = 14
	TagAPRep          = 15
	TagKRBPriv        = 21
	TagKRBSafe        = 20
	TagEncASRepPart   = 25
	TagEncTGSRepPart  = 26
	TagEncAPRepPart   = 27
	TagEncKRBPrivPart = 28
	TagKRBCred        = 22
	TagEncKrbCredPart = 29
	TagKRBError       = 30
)

// PKINIT padata types defined by RFC 4556.
const (
	PADataPKASReq int32 = 16
	PADataPKASRep int32 = 17
)

// PKAuthenticator is the Kerberos PKINIT authenticator. Its fields are
// context-tagged by the repository ASN.1 codec.
type PKAuthenticator struct {
	Cusec      int32              `krb5:"tag:0"`
	CTime      types.KerberosTime `krb5:"tag:1"`
	Nonce      int32              `krb5:"tag:2"`
	PAChecksum []byte             `krb5:"tag:3,optional"`
}

// AuthPack is the Kerberos portion of a PKINIT request.
type AuthPack struct {
	PKAuthenticator   PKAuthenticator `krb5:"tag:0"`
	ClientPublicValue []byte          `krb5:"tag:1,optional"`
	ClientDHNonce     []byte          `krb5:"tag:3,optional"`
}

package protocol

import "github.com/Exonical/go-kerberos/krb5/types"

// PrincipalName is the structured name of a Kerberos principal.
type PrincipalName struct {
	NameType   int32    `krb5:"tag:0"`
	NameString []string `krb5:"tag:1"`
}

// HostAddress identifies a network address in a Kerberos request or ticket.
type HostAddress struct {
	AddrType int32  `krb5:"tag:0"`
	Address  []byte `krb5:"tag:1"`
}

// HostAddresses is a sequence of network addresses.
type HostAddresses []HostAddress

// AuthorizationDataEntry carries one typed authorization-data element.
type AuthorizationDataEntry struct {
	ADType int32  `krb5:"tag:0"`
	ADData []byte `krb5:"tag:1"`
}

// AuthorizationData is a sequence of authorization-data elements.
type AuthorizationData []AuthorizationDataEntry

// KDCIssued is the RFC 4120 AD-KDC-ISSUED authorization-data payload.
type KDCIssued struct {
	Checksum Checksum          `krb5:"tag:0"`
	IRealm   *string           `krb5:"tag:1,optional"`
	IName    *PrincipalName    `krb5:"tag:2,optional"`
	Elements AuthorizationData `krb5:"tag:3"`
}

// VerifierMAC is the RFC 7751 CAMMAC verifier-mac structure.
type VerifierMAC struct {
	Princ    *PrincipalName `krb5:"tag:0,optional"`
	KVNO     *uint32        `krb5:"tag:1,optional"`
	Enctype  *int32         `krb5:"tag:2,optional"`
	Checksum Checksum       `krb5:"tag:3"`
}

// CAMMAC is the RFC 7751 container for KDC-protected authorization data.
type CAMMAC struct {
	Elements       AuthorizationData `krb5:"tag:0"`
	KDCVerifier    *VerifierMAC      `krb5:"tag:1,optional"`
	SVCVerifier    *VerifierMAC      `krb5:"tag:2,optional"`
	OtherVerifiers []VerifierMAC     `krb5:"tag:3,optional"`
}

// AlgorithmIdentifier is the RFC 5280 algorithm identifier used by PKINIT
// and OTP. Algorithm contains the DER OBJECT IDENTIFIER value octets.
type AlgorithmIdentifier struct {
	Algorithm  types.ObjectIdentifier `krb5:"tag:0,bare"`
	Parameters *types.RawDER          `krb5:"tag:1,optional,bare"`
}

// SupportedKDF identifies a PKINIT KDF algorithm.
type SupportedKDF struct {
	KDF types.ObjectIdentifier `krb5:"tag:0"`
}

// PAData carries one preauthentication or method-data value.
type PAData struct {
	PADataType  int32  `krb5:"tag:1"`
	PADataValue []byte `krb5:"tag:2"`
}

// TypedData is the RFC 4120 KRB-ERROR e-data container.
type TypedData []TypedDataEntry

// TypedDataEntry carries one typed KRB-ERROR extension value.
type TypedDataEntry struct {
	DataType  int32  `krb5:"tag:0"`
	DataValue []byte `krb5:"tag:1,optional"`
}

// OTPTokenInfo describes an RFC 6560 token accepted by the KDC.
type OTPTokenInfo struct {
	Flags            types.OTPFlags        `krb5:"tag:0,implicit"`
	Vendor           *types.UTF8String     `krb5:"tag:1,optional,implicit"`
	Challenge        []byte                `krb5:"tag:2,optional,implicit"`
	Length           *int32                `krb5:"tag:3,optional,implicit"`
	Format           *int32                `krb5:"tag:4,optional,implicit"`
	TokenID          []byte                `krb5:"tag:5,optional,implicit"`
	AlgID            *types.UTF8String     `krb5:"tag:6,optional,implicit"`
	SupportedHashAlg []AlgorithmIdentifier `krb5:"tag:7,optional,implicit"`
	IterationCount   *int32                `krb5:"tag:8,optional,implicit"`
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
	Flags          types.OTPFlags       `krb5:"tag:0,implicit"`
	Nonce          []byte               `krb5:"tag:1,optional,implicit"`
	EncData        EncryptedData        `krb5:"tag:2,implicit"`
	HashAlg        *AlgorithmIdentifier `krb5:"tag:3,optional,implicit"`
	IterationCount *int32               `krb5:"tag:4,optional,implicit"`
	OTPValue       []byte               `krb5:"tag:5,optional,implicit"`
	PIN            *types.UTF8String    `krb5:"tag:6,optional,implicit"`
	Challenge      []byte               `krb5:"tag:7,optional,implicit"`
	Time           *types.KerberosTime  `krb5:"tag:8,optional,implicit"`
	Counter        []byte               `krb5:"tag:9,optional,implicit"`
	Format         *int32               `krb5:"tag:10,optional,implicit"`
	TokenID        []byte               `krb5:"tag:11,optional,implicit"`
	AlgID          *types.UTF8String    `krb5:"tag:12,optional,implicit"`
	Vendor         *types.UTF8String    `krb5:"tag:13,optional,implicit"`
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
	// PADataASFreshness is the RFC 8070 freshness-token padata type.
	PADataASFreshness int32 = 150
	// PADataEncryptedChallenge is the RFC 6113 encrypted-challenge padata type.
	PADataEncryptedChallenge int32 = 138
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

// EncryptedData identifies the enctype and ciphertext of an encrypted value.
type EncryptedData struct {
	EType  int32   `krb5:"tag:0"`
	KVNO   *uint32 `krb5:"tag:1,optional,signed"`
	Cipher []byte  `krb5:"tag:2"`
}

// EncryptionKey contains an enctype and its key material.
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

// Checksum identifies the checksum type and checksum bytes.
type Checksum struct {
	ChecksumType int32  `krb5:"tag:0"`
	Checksum     []byte `krb5:"tag:1"`
}

// Ticket is the RFC 4120 service ticket.
type Ticket struct {
	TktVNO  int32         `krb5:"tag:0"`
	Realm   string        `krb5:"tag:1"`
	SName   PrincipalName `krb5:"tag:2"`
	EncPart EncryptedData `krb5:"tag:3"`
}

func (Ticket) ApplicationTag() int { return TagTicket }

// EncTicketPart is the encrypted portion of a service ticket.
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

// Authenticator binds a client identity and timestamp to an AP request.
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

// KDCReq is the common RFC 4120 KDC request body.
type KDCReq struct {
	PVNO    int32      `krb5:"tag:1"`
	MsgType int32      `krb5:"tag:2"`
	PAData  MethodData `krb5:"tag:3,optional"`
	ReqBody KDCReqBody `krb5:"tag:4"`
}

// KDCReqBody contains the requested ticket parameters.
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

// ASReq is an initial-authentication request.
type ASReq struct {
	PVNO    int32      `krb5:"tag:1"`
	MsgType int32      `krb5:"tag:2"`
	PAData  MethodData `krb5:"tag:3,optional"`
	ReqBody KDCReqBody `krb5:"tag:4"`
}

func (ASReq) ApplicationTag() int { return TagASReq }

// TGSReq is a ticket-granting request.
type TGSReq struct {
	PVNO    int32      `krb5:"tag:1"`
	MsgType int32      `krb5:"tag:2"`
	PAData  MethodData `krb5:"tag:3,optional"`
	ReqBody KDCReqBody `krb5:"tag:4"`
}

func (TGSReq) ApplicationTag() int { return TagTGSReq }

// KDCRep is the common RFC 4120 KDC reply structure.
type KDCRep struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	PAData  MethodData    `krb5:"tag:2,optional"`
	CRealm  string        `krb5:"tag:3"`
	CName   PrincipalName `krb5:"tag:4"`
	Ticket  Ticket        `krb5:"tag:5"`
	EncPart EncryptedData `krb5:"tag:6"`
}

// ASRep is an initial-authentication reply.
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

// TGSRep is a ticket-granting reply.
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

// EncASRepPart is the encrypted portion of an AS reply.
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

// EncTGSRepPart is the encrypted portion of a TGS reply.
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

// APReq is an application request carrying a ticket and authenticator.
type APReq struct {
	PVNO          int32           `krb5:"tag:0"`
	MsgType       int32           `krb5:"tag:1"`
	APOptions     types.APOptions `krb5:"tag:2"`
	Ticket        Ticket          `krb5:"tag:3"`
	Authenticator EncryptedData   `krb5:"tag:4"`
}

func (APReq) ApplicationTag() int { return TagAPReq }

// APRep is the application reply to an AP request.
type APRep struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	EncPart EncryptedData `krb5:"tag:2"`
}

func (APRep) ApplicationTag() int { return TagAPRep }

// KRBPriv carries encrypted private application data.
type KRBPriv struct {
	PVNO    int32         `krb5:"tag:0"`
	MsgType int32         `krb5:"tag:1"`
	EncPart EncryptedData `krb5:"tag:3"`
}

func (KRBPriv) ApplicationTag() int { return TagKRBPriv }

// KRBSafe carries integrity-protected application data.
type KRBSafe struct {
	PVNO     int32    `krb5:"tag:0"`
	MsgType  int32    `krb5:"tag:1"`
	SafeBody SafeBody `krb5:"tag:2"`
	Checksum Checksum `krb5:"tag:3"`
}

func (KRBSafe) ApplicationTag() int { return TagKRBSafe }

// SafeBody contains the data and addresses protected by a KRB-SAFE message.
type SafeBody struct {
	UserData  []byte              `krb5:"tag:0"`
	Timestamp *types.KerberosTime `krb5:"tag:1,optional"`
	Usec      *int32              `krb5:"tag:2,optional"`
	SeqNumber *uint32             `krb5:"tag:3,optional"`
	SAddress  HostAddress         `krb5:"tag:4"`
	RAddress  *HostAddress        `krb5:"tag:5,optional"`
}

// EncAPRepPart is the encrypted portion of an AP reply.
type EncAPRepPart struct {
	Ctime     types.KerberosTime `krb5:"tag:0"`
	Cusec     int32              `krb5:"tag:1"`
	SubKey    *EncryptionKey     `krb5:"tag:2,optional"`
	SeqNumber *uint32            `krb5:"tag:3,optional"`
}

func (EncAPRepPart) ApplicationTag() int { return TagEncAPRepPart }

// EncKRBPrivPart is the encrypted portion of a KRB-PRIV message.
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

// KRBError is the RFC 4120 error reply.
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

// MethodData is a sequence of preauthentication data values.
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

// ETypeInfoEntry describes a legacy enctype and salt.
type ETypeInfoEntry struct {
	EType int32   `krb5:"tag:0"`
	Salt  *[]byte `krb5:"tag:1,optional"`
}

// ETypeInfo is a sequence of legacy enctype information entries.
type ETypeInfo []ETypeInfoEntry

// ETypeInfo2Entry describes an enctype, salt, and string-to-key parameters.
type ETypeInfo2Entry struct {
	EType     int32   `krb5:"tag:0"`
	Salt      *string `krb5:"tag:1,optional"`
	S2KParams []byte  `krb5:"tag:2,optional"`
}

// ETypeInfo2 is a sequence of modern enctype information entries.
type ETypeInfo2 []ETypeInfo2Entry

// LastReqEntry records the time of a previous request.
type LastReqEntry struct {
	LRType  int32              `krb5:"tag:0"`
	LRValue types.KerberosTime `krb5:"tag:1"`
}

// LastReq is a sequence of previous-request records.
type LastReq []LastReqEntry

// TransitedEncoding records the transited-realm encoding in a ticket.
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

// Authorization-data type numbers used by RFC 7751 and RFC 4120.
const (
	ADIfRelevant      int32 = 1
	ADKDCIssued       int32 = 4
	ADMandatoryForKDC int32 = 8
	ADCAMMAC          int32 = 96
	ADAuthIndicator   int32 = 97
)

// PKINIT padata types defined by RFC 4556.
const (
	PADataPKASReq int32 = 16
	PADataPKASRep int32 = 17
)

// PKAuthenticator is the Kerberos PKINIT authenticator. Its fields are
// context-tagged by the repository ASN.1 codec.
type PKAuthenticator struct {
	Cusec          int32              `krb5:"tag:0"`
	CTime          types.KerberosTime `krb5:"tag:1"`
	Nonce          int32              `krb5:"tag:2"`
	PAChecksum     []byte             `krb5:"tag:3,optional"`
	FreshnessToken []byte             `krb5:"tag:4,optional"`
}

// AuthPack is the Kerberos portion of a PKINIT request.
type AuthPack struct {
	PKAuthenticator   PKAuthenticator       `krb5:"tag:0"`
	ClientPublicValue []byte                `krb5:"tag:1,optional"`
	SupportedCMSTypes []AlgorithmIdentifier `krb5:"tag:2,optional"`
	ClientDHNonce     []byte                `krb5:"tag:3,optional"`
	SupportedKDFs     []SupportedKDF        `krb5:"tag:4,optional"`
}

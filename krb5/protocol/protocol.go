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

type EncryptedData struct {
	EType  int32   `krb5:"tag:0"`
	KVNO   *uint32 `krb5:"tag:1,optional"`
	Cipher []byte  `krb5:"tag:2"`
}

type EncryptionKey struct {
	KeyType  int32  `krb5:"tag:0"`
	KeyValue []byte `krb5:"tag:1"`
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

type EncAPRepPart struct {
	Ctime     types.KerberosTime `krb5:"tag:0"`
	Cusec     int32              `krb5:"tag:1"`
	SubKey    *EncryptionKey     `krb5:"tag:2,optional"`
	SeqNumber *uint32            `krb5:"tag:3,optional"`
}

func (EncAPRepPart) ApplicationTag() int { return TagEncAPRepPart }

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

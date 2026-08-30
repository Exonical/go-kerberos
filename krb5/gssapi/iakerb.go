package gssapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// IAKERBMechOID is the Kerberos mechanism for proxying KDC exchanges.
const IAKERBMechOID = "1.3.6.1.5.2.5"

const (
	iakerbTokenProxy        = 0x0501
	iakerbFinishedUsage     = 41
	iakerbFinishedExtension = 2
)

var iakerbOID = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x05}

// IAKERBHeader is the IAKERB proxy header (draft-ietf-kitten-iakerb).
type IAKERBHeader struct {
	TargetRealm types.UTF8String `krb5:"tag:1"`
	Cookie      []byte           `krb5:"tag:2,optional"`
}

// IAKERBFinished contains the conversation checksum carried in an
// authenticator checksum extension.
type IAKERBFinished struct {
	Checksum protocol.Checksum `krb5:"tag:1"`
}

// MarshalIAKERBHeader encodes an IAKERB header.
func MarshalIAKERBHeader(header IAKERBHeader) ([]byte, error) {
	return asn1.Marshal(header)
}

// ParseIAKERBHeader decodes an IAKERB header.
func ParseIAKERBHeader(data []byte) (IAKERBHeader, error) {
	var header IAKERBHeader
	if err := asn1.Unmarshal(data, &header); err != nil {
		return IAKERBHeader{}, err
	}
	return header, nil
}

// MarshalIAKERBFinished creates an IAKERB-FINISHED checksum over conv.
func MarshalIAKERBFinished(key protocol.EncryptionKey, conv []byte) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	sum, err := etype.Checksum(key.KeyValue, iakerbFinishedUsage, conv)
	if err != nil {
		return nil, fmt.Errorf("IAKERB finished checksum: %w", err)
	}
	return asn1.Marshal(IAKERBFinished{
		Checksum: protocol.Checksum{ChecksumType: checksumTypeForKey(key.KeyType), Checksum: sum},
	})
}

// VerifyIAKERBFinished verifies an IAKERB-FINISHED checksum.
func VerifyIAKERBFinished(key protocol.EncryptionKey, conv, finished []byte) error {
	var value IAKERBFinished
	if err := asn1.Unmarshal(finished, &value); err != nil {
		return fmt.Errorf("IAKERB finished: %w", err)
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return err
	}
	if value.Checksum.ChecksumType != checksumTypeForKey(key.KeyType) {
		return fmt.Errorf("IAKERB finished: %w", krberrors.ErrIntegrity)
	}
	if err := etype.VerifyChecksum(key.KeyValue, iakerbFinishedUsage, conv, value.Checksum.Checksum); err != nil {
		return fmt.Errorf("IAKERB finished: %w", err)
	}
	return nil
}

// BuildIAKERBProxyToken frames a KDC message in an IAKERB token.
func BuildIAKERBProxyToken(realm string, cookie, request []byte) ([]byte, error) {
	header, err := MarshalIAKERBHeader(IAKERBHeader{
		TargetRealm: types.UTF8String(realm),
		Cookie:      append([]byte(nil), cookie...),
	})
	if err != nil {
		return nil, fmt.Errorf("IAKERB header: %w", err)
	}
	body := append(header, request...)
	content := append(append([]byte(nil), iakerbOID...), byte(iakerbTokenProxy>>8), byte(iakerbTokenProxy&0xff))
	content = append(content, body...)
	return append([]byte{0x60}, appendDERLength(content)...), nil
}

func parseIAKERBProxyToken(token []byte) (IAKERBHeader, []byte, error) {
	if len(token) < 2 || token[0] != 0x60 {
		return IAKERBHeader{}, nil, fmt.Errorf("IAKERB token: invalid framing")
	}
	offset, err := derLength(token[1:])
	if err != nil {
		return IAKERBHeader{}, nil, err
	}
	if 1+offset > len(token) || derLengthValue(token[1:]) != len(token)-(1+offset) {
		return IAKERBHeader{}, nil, fmt.Errorf("IAKERB token: invalid length")
	}
	content := token[1+offset:]
	if len(content) < len(iakerbOID)+2 || !bytes.Equal(content[:len(iakerbOID)], iakerbOID) ||
		binary.BigEndian.Uint16(content[len(iakerbOID):]) != iakerbTokenProxy {
		return IAKERBHeader{}, nil, fmt.Errorf("IAKERB token: unexpected mechanism or token id")
	}
	body := content[len(iakerbOID)+2:]
	if len(body) < 2 || body[0] != 0x30 {
		return IAKERBHeader{}, nil, fmt.Errorf("IAKERB token: missing header")
	}
	headerLen, err := derLength(body[1:])
	if err != nil {
		return IAKERBHeader{}, nil, err
	}
	headerSize := 1 + headerLen + derLengthValue(body[1:])
	if headerSize > len(body) {
		return IAKERBHeader{}, nil, fmt.Errorf("IAKERB token: truncated header")
	}
	header, err := ParseIAKERBHeader(body[:headerSize])
	if err != nil {
		return IAKERBHeader{}, nil, fmt.Errorf("IAKERB header: %w", err)
	}
	return header, append([]byte(nil), body[headerSize:]...), nil
}

func checksumTypeForKey(keyType int32) int32 {
	switch keyType {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256
	case crypto.EnctypeCamellia128:
		return crypto.ChecksumCMACCamellia128
	case crypto.EnctypeCamellia256:
		return crypto.ChecksumCMACCamellia256
	default:
		return 0
	}
}

func buildIAKERBAuthenticatorChecksum(flags uint32, finished []byte, bindings *ChannelBindings) *protocol.Checksum {
	value := make([]byte, 24)
	binary.LittleEndian.PutUint32(value, 16)
	if bindings != nil {
		sum := ChecksumChannelBindings(bindings)
		copy(value[4:20], sum[:])
	}
	binary.LittleEndian.PutUint32(value[20:], flags)
	if len(finished) != 0 {
		extension := make([]byte, 8+len(finished))
		binary.BigEndian.PutUint32(extension, iakerbFinishedExtension)
		binary.BigEndian.PutUint32(extension[4:], uint32(len(finished)))
		copy(extension[8:], finished)
		value = append(value, extension...)
	}
	return &protocol.Checksum{ChecksumType: 0x8003, Checksum: value}
}

// IAKERBInitiator performs the stepwise proxy exchange and then hands the
// resulting AP exchange to the normal Kerberos GSS mechanism.
type IAKERBInitiator struct {
	KDC                 *client.Client
	Password            string
	Client              principal.Principal
	Target              principal.Principal
	TGT                 *client.Credentials
	Service             *client.Credentials
	Flags               uint32
	state               int
	request             protocol.ASReq
	nonce               uint32
	tgsRequest          *protocol.TGSReq
	tgsNonce            uint32
	tgsRealm            string
	tgsCurrentRealm     string
	tgsService          principal.Principal
	tgsRequestedService principal.Principal
	tgsMapped           bool
	tgsCross            bool
	tgsPath             []string
	tgsPathIndex        int
	tgsReferralHops     int
	tgsVisited          map[string]bool
	etype               int32
	key                 []byte
	realm               string
	cookie              []byte
	context             *Context
	apState             *ap.APReq
	conversation        []byte
	discovery           bool
	channelBindings     *ChannelBindings
}

const (
	iakerbStateAS = iota
	iakerbStateTGS
	iakerbStateAP
	iakerbStateDone
)

// NewIAKERBInitiator creates a password-backed IAKERB initiator.
func NewIAKERBInitiator(kdc *client.Client, clientPrincipal, target principal.Principal,
	password string, flags uint32) (*IAKERBInitiator, error) {
	return NewIAKERBInitiatorWithOptions(kdc, clientPrincipal, target, password, flags, InitiatorOptions{})
}

// NewIAKERBInitiatorWithOptions creates a password-backed IAKERB initiator
// with optional channel bindings for the final Kerberos context.
func NewIAKERBInitiatorWithOptions(kdc *client.Client, clientPrincipal, target principal.Principal,
	password string, flags uint32, options InitiatorOptions) (*IAKERBInitiator, error) {
	if kdc == nil || len(clientPrincipal.Components) == 0 {
		return nil, fmt.Errorf("IAKERB initiator: incomplete credentials")
	}
	if flags&GSSDelegFlag != 0 {
		return nil, fmt.Errorf("IAKERB initiator: credential delegation is not supported")
	}
	return &IAKERBInitiator{
		KDC: kdc, Password: password, Client: clientPrincipal, Target: target,
		Flags: flags, state: iakerbStateAS, realm: clientPrincipal.Realm,
		discovery:       clientPrincipal.Realm == "",
		channelBindings: cloneChannelBindings(options.ChannelBindings),
	}, nil
}

// NewIAKERBInitiatorWithCredentials starts at TGS or AP using existing
// credentials. A non-nil service credential skips the proxy exchange.
func NewIAKERBInitiatorWithCredentials(tgt, service *client.Credentials,
	target principal.Principal, flags uint32) (*IAKERBInitiator, error) {
	return NewIAKERBInitiatorWithCredentialsOptions(tgt, service, target, flags, InitiatorOptions{})
}

// NewIAKERBInitiatorWithCredentialsOptions starts IAKERB with existing
// credentials and optional channel bindings.
func NewIAKERBInitiatorWithCredentialsOptions(tgt, service *client.Credentials,
	target principal.Principal, flags uint32, options InitiatorOptions) (*IAKERBInitiator, error) {
	if service == nil && (tgt == nil || len(tgt.Ticket) == 0) {
		return nil, fmt.Errorf("IAKERB initiator: missing credentials")
	}
	if flags&GSSDelegFlag != 0 {
		return nil, fmt.Errorf("IAKERB initiator: credential delegation is not supported")
	}
	var clientPrincipal principal.Principal
	if service != nil {
		clientPrincipal = service.Client
	} else {
		clientPrincipal = tgt.Client
	}
	return &IAKERBInitiator{
		TGT: tgt, Service: service, Client: clientPrincipal, Target: target,
		Flags: flags, state: iakerbStateTGS, realm: clientPrincipal.Realm,
		channelBindings: cloneChannelBindings(options.ChannelBindings),
	}, nil
}

// SetKDC supplies the KDC client required when a TGT must obtain a service
// ticket. Existing service credentials do not require a KDC client.
func (i *IAKERBInitiator) SetKDC(kdc *client.Client) {
	if i != nil {
		i.KDC = kdc
	}
}

// SetChannelBindings supplies bindings for the final AP exchange.
func (i *IAKERBInitiator) SetChannelBindings(bindings *ChannelBindings) {
	if i != nil {
		i.channelBindings = cloneChannelBindings(bindings)
	}
}

func (i *IAKERBInitiator) initTGSPath() error {
	if i.tgsRealm != "" {
		return nil
	}
	realm, mapped := client.ServiceRealm(i.KDC.Config, i.Target)
	if realm == "" {
		realm = i.Target.Realm
	}
	currentRealm := i.TGT.Server.Realm
	if currentRealm == "" {
		currentRealm = i.TGT.Client.Realm
	}
	if realm == "" {
		realm = currentRealm
	}
	if realm == "" || currentRealm == "" {
		return fmt.Errorf("IAKERB initiator: missing TGS realm")
	}
	i.tgsRealm, i.tgsMapped = realm, mapped
	i.tgsRequestedService = i.Target
	i.tgsService = i.Target
	i.tgsService.Realm = realm
	i.tgsPath = []string{currentRealm}
	i.tgsPathIndex = 1
	i.tgsVisited = map[string]bool{strings.ToUpper(currentRealm): true}
	if !strings.EqualFold(currentRealm, realm) {
		i.tgsPath = []string{currentRealm, realm}
		if i.KDC.Config != nil {
			path, configured, err := i.KDC.Config.RealmPath(currentRealm, realm)
			if err != nil {
				return fmt.Errorf("IAKERB initiator: %w", err)
			}
			if configured {
				i.tgsPath = path
			}
		}
		if len(i.tgsPath) < 2 || len(i.tgsPath) > 11 {
			return fmt.Errorf("IAKERB initiator: invalid capath")
		}
	}
	return nil
}

// Step advances the IAKERB exchange. An empty input starts the exchange.
func (i *IAKERBInitiator) Step(input []byte, now time.Time) ([]byte, error) {
	if i == nil || i.KDC == nil && i.Service == nil && i.TGT == nil {
		return nil, fmt.Errorf("IAKERB initiator: incomplete context")
	}
	if i.state == iakerbStateDone {
		if len(input) != 0 {
			if err := i.verifyAPReply(input); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	now = now.UTC()
	var response []byte
	var header IAKERBHeader
	var err error
	if len(input) != 0 && i.state != iakerbStateAP {
		header, response, err = parseIAKERBProxyToken(input)
		if err != nil {
			return nil, err
		}
		i.conversation = append(i.conversation, input...)
		i.cookie = append([]byte(nil), header.Cookie...)
		if header.TargetRealm != "" {
			i.realm = string(header.TargetRealm)
			if i.Client.Realm == "" {
				i.Client.Realm = i.realm
			}
		}
		if i.discovery {
			if i.realm == "" {
				return nil, fmt.Errorf("IAKERB initiator: proxy returned empty realm")
			}
			i.discovery = false
			input = nil
		}
	}
	if i.state == iakerbStateAS {
		if len(input) == 0 {
			if i.discovery {
				return i.proxyRequest("", nil, []byte{})
			}
			i.request, err = i.KDC.BuildASRequest(i.Client, now)
			if err != nil {
				return nil, err
			}
			i.nonce = i.request.ReqBody.Nonce
			return i.proxyRequest(i.realm, nil, i.request)
		}
		var kerror protocol.KRBError
		if asn1.Unmarshal(response, &kerror) == nil && kerror.ErrorCode != 0 {
			if kerror.ErrorCode != 25 {
				return nil, krberrors.NewKRBError(krberrors.ErrorCode(kerror.ErrorCode),
					"", i.realm, kerror.STime.Time, kerror.Susec, kerror.EData)
			}
			methodData, err := preauth.ParseMethodData(kerror.EData)
			if err != nil {
				return nil, err
			}
			var salt, params []byte
			i.etype, salt, params, err = preauth.SelectEType(methodData, i.realm, i.Client, crypto.NewRegistry())
			if err != nil {
				return nil, err
			}
			etype, err := crypto.NewRegistry().Get(i.etype)
			if err != nil {
				return nil, err
			}
			i.key, err = etype.StringToKey([]byte(i.Password), salt, params)
			if err != nil {
				return nil, err
			}
			timestamp, err := preauth.BuildEncryptedTimestamp(etype, i.key, now, 0)
			if err != nil {
				return nil, err
			}
			i.request.PAData = protocol.MethodData{timestamp}
			return i.proxyRequest(i.realm, i.cookie, i.request)
		}
		if i.etype == 0 {
			return nil, fmt.Errorf("IAKERB initiator: missing AS reply key")
		}
		i.TGT, err = i.KDC.DecodeASResponse(response, i.Client, i.nonce, i.etype, i.key, now)
		if err != nil {
			return nil, err
		}
		i.state = iakerbStateTGS
		input = nil
		response = nil
	}
	if i.state == iakerbStateTGS {
		if i.Service == nil {
			if i.TGT == nil {
				return nil, fmt.Errorf("IAKERB initiator: missing TGT")
			}
			if i.KDC == nil {
				return nil, fmt.Errorf("IAKERB initiator: KDC client required for TGT start")
			}
			if len(response) != 0 {
				result, referral, err := i.KDC.DecodeTGSResponseForExchange(
					response, i.TGT, i.tgsService, i.tgsRequestedService,
					i.tgsMapped, i.tgsNonce, now)
				if err != nil {
					return nil, err
				}
				if i.tgsCross {
					if referral || len(result.Server.Components) != 2 ||
						result.Server.Components[0] != "krbtgt" ||
						!strings.EqualFold(result.Server.Components[1], i.tgsPath[i.tgsPathIndex]) ||
						!strings.EqualFold(result.Server.Realm, i.tgsCurrentRealm) {
						return nil, fmt.Errorf("IAKERB initiator: malformed cross-realm TGT")
					}
					i.TGT = result
					i.tgsPathIndex++
				} else if referral {
					if i.tgsReferralHops >= 10 || len(result.Server.Components) != 2 ||
						result.Server.Components[0] != "krbtgt" {
						return nil, fmt.Errorf("IAKERB initiator: referral hop limit exceeded")
					}
					nextRealm := result.Server.Components[1]
					if nextRealm == "" || strings.EqualFold(nextRealm, i.tgsRealm) ||
						i.tgsVisited[strings.ToUpper(nextRealm)] {
						return nil, fmt.Errorf("IAKERB initiator: referral realm loop")
					}
					i.TGT, i.tgsRealm = result, nextRealm
					i.tgsReferralHops++
					i.tgsVisited[strings.ToUpper(nextRealm)] = true
				} else {
					i.Service = result
				}
				i.tgsRequest = nil
			}
			if i.Service == nil {
				if i.tgsRequest == nil {
					if err := i.initTGSPath(); err != nil {
						return nil, err
					}
					var request protocol.TGSReq
					var nonce uint32
					if i.tgsPathIndex < len(i.tgsPath) {
						i.tgsCurrentRealm = i.tgsPath[i.tgsPathIndex-1]
						nextRealm := i.tgsPath[i.tgsPathIndex]
						i.tgsService = principal.Principal{
							Realm: i.tgsCurrentRealm, NameType: principal.NTSrvInstance,
							Components: []string{"krbtgt", nextRealm},
						}
						i.tgsRequestedService = i.tgsService
						i.tgsRequestedService.Realm = nextRealm
						i.tgsMapped, i.tgsCross = true, true
						request, nonce, err = i.KDC.BuildTGSRequestForRealm(
							i.TGT, i.tgsService, i.tgsCurrentRealm, false, now)
					} else {
						i.tgsCurrentRealm = i.TGT.Server.Realm
						i.tgsService = i.Target
						i.tgsService.Realm = i.tgsRealm
						i.tgsRequestedService = i.Target
						i.tgsCross = false
						referral := i.tgsReferralHops > 0 ||
							(!i.tgsMapped && i.Target.Realm == "")
						request, nonce, err = i.KDC.BuildTGSRequestForRealm(
							i.TGT, i.tgsService, i.tgsRealm, referral, now)
					}
					if err != nil {
						return nil, err
					}
					i.tgsRequest, i.tgsNonce = &request, nonce
				}
				return i.proxyRequest(i.tgsRequest.ReqBody.Realm, i.cookie, *i.tgsRequest)
			}
		}
		i.state = iakerbStateAP
	}
	if i.state == iakerbStateAP {
		if i.apState == nil {
			if i.Service == nil {
				return nil, fmt.Errorf("IAKERB initiator: missing service credentials")
			}
			subkey := protocol.EncryptionKey{KeyType: i.Service.Key.KeyType}
			etype, err := crypto.NewRegistry().Get(subkey.KeyType)
			if err != nil {
				return nil, err
			}
			subkey.KeyValue = make([]byte, etype.KeySize())
			if _, err := io.ReadFull(crypto.RandomSource, subkey.KeyValue); err != nil {
				return nil, err
			}
			finished, err := MarshalIAKERBFinished(subkey, i.conversation)
			if err != nil {
				return nil, err
			}
			checksum := buildIAKERBAuthenticatorChecksum(i.Flags, finished, i.channelBindings)
			opts := types.APOptions(0)
			if i.Flags&GSSMutualFlag != 0 {
				opts |= types.APMutualRequired
			}
			i.apState, response, err = ap.BuildAPReqWithOptions(i.Service, opts, now,
				ap.APReqOptions{Checksum: checksum, SubKey: &subkey})
			if err != nil {
				return nil, err
			}
			i.context = &Context{key: contextKey(i.apState.SessionKey, i.apState.SubKey),
				initiator: true, flags: i.Flags | channelBoundFlag(i.channelBindings),
				sendSeq: sequenceValue(i.apState.SeqNumber)}
			if i.Flags&GSSMutualFlag == 0 {
				i.state = iakerbStateDone
			}
			return frameToken([]byte{0x01, 0x00}, response), nil
		}
		if len(input) != 0 {
			if err := i.verifyAPReply(input); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func (i *IAKERBInitiator) proxyRequest(realm string, cookie []byte, request any) ([]byte, error) {
	var encoded []byte
	if raw, ok := request.([]byte); ok && len(raw) == 0 {
		encoded = nil
	} else {
		var err error
		encoded, err = asn1.Marshal(request)
		if err != nil {
			return nil, err
		}
	}
	token, err := BuildIAKERBProxyToken(realm, cookie, encoded)
	if err != nil {
		return nil, err
	}
	i.conversation = append(i.conversation, token...)
	return token, nil
}

func (i *IAKERBInitiator) verifyAPReply(token []byte) error {
	inner, err := unframeTokenAnyOID(token, []byte{0x02, 0x00})
	if err != nil {
		return err
	}
	details, err := ap.VerifyAPRepWithDetails(i.apState, inner)
	if err != nil {
		return err
	}
	if details.SubKey != nil {
		i.context.key = contextKey(i.apState.SessionKey, details.SubKey)
		i.context.acceptorSubkey = true
	}
	if details.SeqNumber != nil {
		i.context.recvSeq = sequenceValue(details.SeqNumber)
	}
	i.state = iakerbStateDone
	return nil
}

// Context returns the established IAKERB security context.
func (i *IAKERBInitiator) Context() (*Context, error) {
	if i == nil || i.context == nil || i.state != iakerbStateDone {
		return nil, fmt.Errorf("IAKERB initiator: context is not established")
	}
	return i.context, nil
}

// Wrap protects a message after IAKERB establishment.
func (i *IAKERBInitiator) Wrap(data []byte, sealed bool) ([]byte, error) {
	ctx, err := i.Context()
	if err != nil {
		return nil, err
	}
	return ctx.Wrap(data, sealed)
}

// Unwrap verifies a message after IAKERB establishment.
func (i *IAKERBInitiator) Unwrap(token []byte) ([]byte, error) {
	ctx, err := i.Context()
	if err != nil {
		return nil, err
	}
	return ctx.Unwrap(token)
}

// IAKERBAcceptor proxies IAKERB KDC requests and accepts the final AP token.
// It is single-conversation: each instance owns one transcript, hop counter,
// and proxy state, so callers must use a separate acceptor per client context.
type IAKERBAcceptor struct {
	keytab       *keytab.Keytab
	KDC          *client.Client
	Realm        string
	conversation []byte
	acceptor     *Acceptor
	hops         int
	// AllowedRealms restricts proxying to these realms. A nil allowlist
	// permits only realms configured by the acceptor's KDC client.
	AllowedRealms []string
}

// NewIAKERBAcceptor creates an IAKERB proxy backed by a service keytab.
func NewIAKERBAcceptor(kt *keytab.Keytab, kdc *client.Client, realm string) (*IAKERBAcceptor, error) {
	return NewIAKERBAcceptorWithOptions(kt, kdc, realm, AcceptorOptions{})
}

// NewIAKERBAcceptorWithOptions creates an IAKERB proxy with optional replay
// cache configuration for its final AP acceptance.
func NewIAKERBAcceptorWithOptions(kt *keytab.Keytab, kdc *client.Client, realm string, options AcceptorOptions) (*IAKERBAcceptor, error) {
	if kt == nil || kdc == nil {
		return nil, fmt.Errorf("IAKERB acceptor: incomplete configuration")
	}
	return &IAKERBAcceptor{
		keytab: kt, KDC: kdc, Realm: realm,
		acceptor: NewAcceptorWithOptions(kt, options),
	}, nil
}

// Accept advances the proxy or final AP exchange.
func (a *IAKERBAcceptor) Accept(callerCtx context.Context, token []byte, now time.Time) (*Context, []byte, error) {
	if a == nil || a.acceptor == nil {
		return nil, nil, fmt.Errorf("IAKERB acceptor: incomplete context")
	}
	if callerCtx == nil {
		return nil, nil, fmt.Errorf("IAKERB acceptor: nil context")
	}
	if len(token) >= 2 && token[0] == 0x60 {
		if _, _, err := parseIAKERBProxyToken(token); err == nil {
			header, request, err := parseIAKERBProxyToken(token)
			if err != nil {
				return nil, nil, err
			}
			a.conversation = append(a.conversation, token...)
			a.hops++
			if a.hops > 32 {
				return nil, nil, fmt.Errorf("IAKERB KDC proxy: maximum proxy hops exceeded")
			}
			if len(request) == 0 {
				realm := a.Realm
				if realm == "" {
					realm = string(header.TargetRealm)
				}
				out, err := BuildIAKERBProxyToken(realm, header.Cookie, nil)
				if err != nil {
					return nil, nil, err
				}
				a.conversation = append(a.conversation, out...)
				return nil, out, nil
			}
			realm := string(header.TargetRealm)
			if realm == "" {
				realm = a.Realm
			}
			if !a.realmAllowed(realm) {
				return nil, nil, fmt.Errorf("IAKERB KDC proxy: realm unknown")
			}
			reply, err := a.KDC.ExchangeRaw(callerCtx, realm, request)
			if err != nil {
				code := int32(86)
				if strings.Contains(err.Error(), "no KDC configured") ||
					strings.Contains(err.Error(), "no configuration") {
					code = 85
				}
				reply, err = asn1.Marshal(protocol.KRBError{
					PVNO: 5, MsgType: 30, STime: types.KerberosTime{Time: now.UTC(), Present: true},
					ErrorCode: code, Realm: realm,
					SName: protocol.PrincipalName{NameType: 1, NameString: []string{"krbtgt", realm}},
				})
				if err != nil {
					return nil, nil, err
				}
			}
			out, err := BuildIAKERBProxyToken(realm, header.Cookie, reply)
			if err != nil {
				return nil, nil, err
			}
			a.conversation = append(a.conversation, out...)
			return nil, out, nil
		}
	}
	ctx, _, reply, err := a.acceptor.acceptWithConversation(token, now, a.conversation)
	if err != nil {
		return nil, nil, err
	}
	return ctx, reply, nil
}

func (a *IAKERBAcceptor) realmAllowed(realm string) bool {
	if a.AllowedRealms != nil {
		for _, allowed := range a.AllowedRealms {
			if strings.EqualFold(allowed, realm) {
				return true
			}
		}
		return false
	}
	if strings.EqualFold(realm, a.Realm) {
		return true
	}
	if a.KDC == nil || a.KDC.Config == nil {
		return false
	}
	for configured := range a.KDC.Config.Realms {
		if strings.EqualFold(configured, realm) {
			return true
		}
	}
	return false
}

// MIC and VerifyMIC expose the established acceptor context operations.
func (a *IAKERBAcceptor) MIC(ctx *Context, data []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("IAKERB acceptor: nil context")
	}
	return ctx.MIC(data)
}

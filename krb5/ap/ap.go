package ap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/cammac"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/rcache"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	authenticatorUsage = 11
	ticketUsage        = 2
	apRepUsage         = 12
)

// APReq is the initiator state associated with an AP-REQ.
type APReq struct {
	DER               []byte
	SessionKey        protocol.EncryptionKey
	AuthenticatorTime time.Time
	Cusec             int32
	SubKey            *protocol.EncryptionKey
	SeqNumber         *uint32
	APOptions         types.APOptions
}

// APReqState is an alias for APReq.
type APReqState = APReq

// APReqOptions controls optional authenticator fields when building AP-REQs.
type APReqOptions struct {
	Checksum *protocol.Checksum
	// AuthorizationData supplies authenticator authorization data.
	AuthorizationData protocol.AuthorizationData
	// SubKey supplies an authenticator subkey. If nil, one is generated.
	SubKey *protocol.EncryptionKey
	// NoSubKey omits the authenticator subkey. Some protocols, including MIT
	// kprop, use the ticket session key for the authenticated context.
	NoSubKey bool
}

// AuthenticatorChecksumExtension identifies an extension carried in the
// RFC 4121 authenticator checksum. Extensions use a big-endian ID and length.
type AuthenticatorChecksumExtension struct {
	ID    uint32
	Value []byte
}

// VerifiedAPReq is the acceptor state associated with a verified AP-REQ.
type VerifiedAPReq struct {
	Client                         principal.Principal
	Server                         principal.Principal
	SessionKey                     protocol.EncryptionKey
	Flags                          types.TicketFlags
	EndTime                        types.KerberosTime
	AuthenticatorTime              time.Time
	Cusec                          int32
	SubKey                         *protocol.EncryptionKey
	SeqNumber                      *uint32
	APOptions                      types.APOptions
	Checksum                       *protocol.Checksum
	AuthenticatorAuthorizationData protocol.AuthorizationData
	// AuthorizationData contains CAMMAC elements after service verification.
	AuthorizationData protocol.AuthorizationData
}

// VerifyAPReqOptions controls replay-cache selection for AP acceptance.
// Without ReplayCache, AP verification retains its process-local default.
type VerifyAPReqOptions struct {
	ReplayCache     rcache.Cache
	ReplayCacheName string
}

// APRepDetails contains optional keying material asserted by an AP-REP.
type APRepDetails struct {
	SubKey    *protocol.EncryptionKey
	SeqNumber *uint32
}

var replayCache = struct {
	sync.Mutex
	entries    map[string]time.Time
	lastSweep  time.Time
	sweepCount int
}{entries: make(map[string]time.Time)}

func sweepReplayCache(now time.Time, skew time.Duration) {
	if !replayCache.lastSweep.IsZero() && now.Sub(replayCache.lastSweep) < time.Second {
		return
	}
	if !replayCache.lastSweep.IsZero() && len(replayCache.entries) <= replayCache.sweepCount {
		return
	}
	for key, ctime := range replayCache.entries {
		if !withinSkew(ctime, now, skew) {
			delete(replayCache.entries, key)
		}
	}
	replayCache.lastSweep = now
	replayCache.sweepCount = len(replayCache.entries)
}

// BuildAPReq constructs an AP-REQ and its initiator state.
func BuildAPReq(creds *client.Credentials, opts types.APOptions, now time.Time) (*APReq, []byte, error) {
	return BuildAPReqWithOptions(creds, opts, now, APReqOptions{})
}

// BuildAPReqWithOptions constructs an AP-REQ with optional authenticator data.
func BuildAPReqWithOptions(creds *client.Credentials, opts types.APOptions, now time.Time, options APReqOptions) (*APReq, []byte, error) {
	if creds == nil {
		return nil, nil, fmt.Errorf("build AP-REQ: nil credentials")
	}
	if len(creds.Ticket) == 0 || len(creds.Key.KeyValue) == 0 {
		return nil, nil, fmt.Errorf("build AP-REQ: incomplete credentials")
	}
	etype, err := crypto.NewRegistry().Get(creds.Key.KeyType)
	if err != nil {
		return nil, nil, err
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(creds.Ticket, &ticket); err != nil {
		return nil, nil, fmt.Errorf("build AP-REQ ticket: %w", err)
	}
	if ticket.Realm == "" || len(ticket.SName.NameString) == 0 {
		return nil, nil, fmt.Errorf("build AP-REQ: invalid ticket service")
	}
	now = now.UTC()
	cusec := int32(now.Nanosecond() / 1000)
	var subkey *protocol.EncryptionKey
	if options.SubKey != nil {
		if options.SubKey.KeyType != creds.Key.KeyType {
			return nil, nil, fmt.Errorf("build AP-REQ subkey: enctype mismatch")
		}
		subkey = copyEncryptionKeyPointer(options.SubKey)
	} else if !options.NoSubKey {
		subkeyValue := make([]byte, etype.KeySize())
		if _, err := io.ReadFull(crypto.RandomSource, subkeyValue); err != nil {
			return nil, nil, fmt.Errorf("build AP-REQ subkey: %w", err)
		}
		subkey = &protocol.EncryptionKey{KeyType: creds.Key.KeyType, KeyValue: subkeyValue}
	}
	var sequenceBytes [4]byte
	if _, err := io.ReadFull(crypto.RandomSource, sequenceBytes[:]); err != nil {
		return nil, nil, fmt.Errorf("build AP-REQ sequence number: %w", err)
	}
	sequence := binary.BigEndian.Uint32(sequenceBytes[:]) & 0x7fffffff
	authenticator := protocol.Authenticator{
		AuthenticatorVNO: 5,
		CRealm:           creds.Client.Realm,
		CName:            protocol.PrincipalName{NameType: int32(creds.Client.NameType), NameString: append([]string(nil), creds.Client.Components...)},
		Cusec:            cusec,
		Ctime:            types.KerberosTime{Time: now, Microseconds: cusec, Present: true},
		SubKey:           subkey,
		SeqNumber:        &sequence,
	}
	if options.Checksum != nil {
		checksum := *options.Checksum
		checksum.Checksum = append([]byte(nil), checksum.Checksum...)
		authenticator.Checksum = &checksum
	}
	if options.AuthorizationData != nil {
		authenticator.AuthorizationData = append(protocol.AuthorizationData(nil), options.AuthorizationData...)
	}
	authenticatorDER, err := asn1.Marshal(authenticator)
	if err != nil {
		return nil, nil, fmt.Errorf("build AP-REQ authenticator: %w", err)
	}
	ciphertext, err := etype.Encrypt(creds.Key.KeyValue, authenticatorUsage, authenticatorDER)
	if err != nil {
		return nil, nil, fmt.Errorf("build AP-REQ authenticator encryption: %w", err)
	}
	apReq := protocol.APReq{
		PVNO: 5, MsgType: 14, APOptions: opts, Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: creds.Key.KeyType, Cipher: ciphertext},
	}
	der, err := asn1.Marshal(apReq)
	if err != nil {
		return nil, nil, fmt.Errorf("build AP-REQ: %w", err)
	}
	state := &APReq{
		DER: append([]byte(nil), der...), SessionKey: copyEncryptionKey(creds.Key),
		AuthenticatorTime: now, Cusec: cusec, SubKey: copyEncryptionKeyPointer(subkey),
		SeqNumber: uint32Pointer(sequence), APOptions: opts,
	}
	return state, der, nil
}

// VerifyAPReq verifies an AP-REQ using service keys from a keytab.
func VerifyAPReq(kt *keytab.Keytab, der []byte, now time.Time, skew time.Duration) (*VerifiedAPReq, error) {
	return VerifyAPReqWithOptions(kt, der, now, skew, VerifyAPReqOptions{})
}

// VerifyAPReqWithOptions verifies an AP-REQ and optionally uses a configured
// persistent replay cache. ReplayCacheName is resolved using rcache.Resolve.
func VerifyAPReqWithOptions(kt *keytab.Keytab, der []byte, now time.Time, skew time.Duration, options VerifyAPReqOptions) (*VerifiedAPReq, error) {
	if kt == nil {
		return nil, fmt.Errorf("verify AP-REQ: nil keytab")
	}
	var request protocol.APReq
	if err := asn1.Unmarshal(der, &request); err != nil {
		return nil, fmt.Errorf("verify AP-REQ: %w", err)
	}
	if request.PVNO != 5 || request.MsgType != 14 {
		return nil, fmt.Errorf("verify AP-REQ: unexpected message")
	}
	entry, err := findServiceEntry(kt, request.Ticket)
	if err != nil {
		return nil, err
	}
	backend, err := resolveReplayCache(options)
	if err != nil {
		return nil, err
	}
	return verifyAPReqWithTicketKey(request, protocol.EncryptionKey{
		KeyType: entry.Enctype, KeyValue: entry.Key,
	}, now, skew, backend)
}

// VerifyAPReqWithSessionKey verifies a user-to-user AP-REQ using the peer's
// TGT session key. The request must set APUseSessionKey, as required by
// RFC 4120 section 5.5.1.
func VerifyAPReqWithSessionKey(key protocol.EncryptionKey, der []byte, now time.Time, skew time.Duration) (*VerifiedAPReq, error) {
	return VerifyAPReqWithSessionKeyWithOptions(key, der, now, skew, VerifyAPReqOptions{})
}

// VerifyAPReqWithSessionKeyWithOptions is the option-bearing form of
// VerifyAPReqWithSessionKey.
func VerifyAPReqWithSessionKeyWithOptions(key protocol.EncryptionKey, der []byte, now time.Time, skew time.Duration, options VerifyAPReqOptions) (*VerifiedAPReq, error) {
	if key.KeyType == 0 || len(key.KeyValue) == 0 {
		return nil, fmt.Errorf("verify AP-REQ with session key: incomplete key")
	}
	var request protocol.APReq
	if err := asn1.Unmarshal(der, &request); err != nil {
		return nil, fmt.Errorf("verify AP-REQ with session key: %w", err)
	}
	if request.PVNO != 5 || request.MsgType != 14 {
		return nil, fmt.Errorf("verify AP-REQ with session key: unexpected message")
	}
	if request.APOptions&types.APUseSessionKey == 0 {
		return nil, fmt.Errorf("verify AP-REQ with session key: APUseSessionKey not set")
	}
	if request.Ticket.EncPart.EType != key.KeyType {
		return nil, fmt.Errorf("verify AP-REQ with session key: %w", krberrors.ErrIntegrity)
	}
	backend, err := resolveReplayCache(options)
	if err != nil {
		return nil, err
	}
	return verifyAPReqWithTicketKey(request, key, now, skew, backend)
}

func resolveReplayCache(options VerifyAPReqOptions) (rcache.Cache, error) {
	if options.ReplayCache != nil && options.ReplayCacheName != "" {
		return nil, fmt.Errorf("verify AP-REQ: both replay cache and replay cache name configured")
	}
	if options.ReplayCache != nil {
		return options.ReplayCache, nil
	}
	if options.ReplayCacheName == "" {
		return nil, nil
	}
	backend, err := rcache.Resolve(options.ReplayCacheName)
	if err != nil {
		return nil, fmt.Errorf("verify AP-REQ replay cache: %w", err)
	}
	return backend, nil
}

func verifyAPReqWithTicketKey(request protocol.APReq, ticketKey protocol.EncryptionKey, now time.Time, skew time.Duration, persistentCache rcache.Cache) (*VerifiedAPReq, error) {
	etype, err := crypto.NewRegistry().Get(ticketKey.KeyType)
	if err != nil {
		return nil, err
	}
	ticketPlain, err := etype.Decrypt(ticketKey.KeyValue, ticketUsage, request.Ticket.EncPart.Cipher)
	if err != nil {
		return nil, fmt.Errorf("verify AP-REQ ticket: %w", err)
	}
	var ticketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(ticketPlain, &ticketPart); err != nil {
		return nil, fmt.Errorf("verify AP-REQ ticket: %w", krberrors.ErrIntegrity)
	}
	var protectedAuthData protocol.AuthorizationData
	protectedAuthData, err = cammac.VerifyService(ticketPart.AuthorizationData, ticketKey)
	if err != nil && !errors.Is(err, cammac.ErrNotFound) {
		return nil, fmt.Errorf("verify AP-REQ CAMMAC: %w", err)
	}
	if errors.Is(err, cammac.ErrNotFound) {
		protectedAuthData = nil
	}
	if ticketPart.Flags&types.TicketInvalid != 0 {
		return nil, fmt.Errorf("verify AP-REQ ticket: %w", krberrors.ErrTicketInvalid)
	}
	now = now.UTC()
	if !ticketValid(ticketPart, now) {
		return nil, fmt.Errorf("verify AP-REQ ticket: %w", krberrors.ErrTicketExpired)
	}
	if request.Authenticator.EType != ticketPart.Key.KeyType {
		return nil, fmt.Errorf("verify AP-REQ authenticator: %w", krberrors.ErrIntegrity)
	}
	sessionEType, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
	if err != nil {
		return nil, err
	}
	authPlain, err := sessionEType.Decrypt(ticketPart.Key.KeyValue, authenticatorUsage, request.Authenticator.Cipher)
	if err != nil {
		return nil, fmt.Errorf("verify AP-REQ authenticator: %w", err)
	}
	var authenticator protocol.Authenticator
	if err := asn1.Unmarshal(authPlain, &authenticator); err != nil {
		return nil, fmt.Errorf("verify AP-REQ authenticator: %w", krberrors.ErrIntegrity)
	}
	if authenticator.AuthenticatorVNO != 5 ||
		authenticator.CRealm != ticketPart.CRealm ||
		!sameProtocolPrincipal(authenticator.CName, ticketPart.CName) {
		return nil, fmt.Errorf("verify AP-REQ client principal mismatch")
	}
	if skew < 0 {
		skew = -skew
	}
	replayCache.Lock()
	sweepReplayCache(now, skew)
	replayCache.Unlock()
	if !withinSkew(authenticator.Ctime.Time, now, skew) {
		return nil, fmt.Errorf("verify AP-REQ authenticator: %w", krberrors.ErrClockSkew)
	}
	if persistentCache != nil {
		tag := rcache.TagFromCiphertext(request.Authenticator.Cipher, sessionEType.ChecksumSize())
		if err := persistentCache.Store(tag, authenticator.Ctime.Time, skew); err != nil {
			if errors.Is(err, krberrors.ErrReplay) {
				return nil, fmt.Errorf("verify AP-REQ: %w", krberrors.ErrReplay)
			}
			return nil, fmt.Errorf("verify AP-REQ replay cache: %w", err)
		}
	} else {
		replayKey := fmt.Sprintf("%x", sha256.Sum256(request.Authenticator.Cipher))
		replayCache.Lock()
		_, replayed := replayCache.entries[replayKey]
		if !replayed {
			replayCache.entries[replayKey] = authenticator.Ctime.Time
		}
		replayCache.Unlock()
		if replayed {
			return nil, fmt.Errorf("verify AP-REQ: %w", krberrors.ErrReplay)
		}
	}
	var authChecksum *protocol.Checksum
	if authenticator.Checksum != nil {
		checksum := *authenticator.Checksum
		checksum.Checksum = append([]byte(nil), checksum.Checksum...)
		authChecksum = &checksum
	}
	return &VerifiedAPReq{
		Client: principal.Principal{
			Realm: authenticator.CRealm, NameType: principal.NameType(authenticator.CName.NameType),
			Components: append([]string(nil), authenticator.CName.NameString...),
		},
		Server: principal.Principal{
			Realm: request.Ticket.Realm, NameType: principal.NameType(request.Ticket.SName.NameType),
			Components: append([]string(nil), request.Ticket.SName.NameString...),
		},
		SessionKey:                     copyEncryptionKey(ticketPart.Key),
		Flags:                          ticketPart.Flags,
		EndTime:                        ticketPart.EndTime,
		AuthenticatorTime:              authenticator.Ctime.Time,
		Cusec:                          authenticator.Cusec,
		SubKey:                         copyEncryptionKeyPointer(authenticator.SubKey),
		SeqNumber:                      uint32PointerValue(authenticator.SeqNumber),
		APOptions:                      request.APOptions,
		Checksum:                       authChecksum,
		AuthenticatorAuthorizationData: append(protocol.AuthorizationData(nil), authenticator.AuthorizationData...),
		AuthorizationData:              protectedAuthData,
	}, nil
}

// BuildAPRep constructs an AP-REP echoing the request authenticator time.
func BuildAPRep(request *VerifiedAPReq) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("build AP-REP: nil request")
	}
	return buildAPRepWithTimeAndSequence(request, request.AuthenticatorTime, nil)
}

func buildAPRepWithTime(request *VerifiedAPReq, ctime time.Time) ([]byte, error) {
	return buildAPRepWithTimeAndSequence(request, ctime, nil)
}

// BuildAPRepWithSequence constructs an AP-REP with an explicit acceptor
// sequence number. It is used by protocols such as kprop which enable
// sequence-only authenticated message contexts.
func BuildAPRepWithSequence(request *VerifiedAPReq, sequence uint32) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("build AP-REP: nil request")
	}
	return buildAPRepWithTimeAndSequence(request, request.AuthenticatorTime, &sequence)
}

func buildAPRepWithTimeAndSequence(request *VerifiedAPReq, ctime time.Time, sequence *uint32) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(request.SessionKey.KeyType)
	if err != nil {
		return nil, err
	}
	cusec := request.Cusec
	part := protocol.EncAPRepPart{
		Ctime:     types.KerberosTime{Time: ctime.UTC(), Microseconds: cusec, Present: true},
		Cusec:     cusec,
		SeqNumber: sequence,
	}
	plain, err := asn1.Marshal(part)
	if err != nil {
		return nil, fmt.Errorf("build AP-REP encrypted part: %w", err)
	}
	ciphertext, err := etype.Encrypt(request.SessionKey.KeyValue, apRepUsage, plain)
	if err != nil {
		return nil, fmt.Errorf("build AP-REP encrypted part: %w", err)
	}
	der, err := asn1.Marshal(protocol.APRep{
		PVNO: 5, MsgType: 15,
		EncPart: protocol.EncryptedData{EType: request.SessionKey.KeyType, Cipher: ciphertext},
	})
	if err != nil {
		return nil, fmt.Errorf("build AP-REP: %w", err)
	}
	return der, nil
}

// VerifyAPRep verifies an AP-REP against the initiator AP-REQ state.
func VerifyAPRep(request *APReq, der []byte) error {
	details, err := VerifyAPRepWithDetails(request, der)
	if err != nil {
		return err
	}
	if details.SubKey != nil {
		request.SubKey = copyEncryptionKeyPointer(details.SubKey)
	}
	return nil
}

// VerifyAPRepWithDetails verifies an AP-REP and returns its optional subkey
// and acceptor sequence number without changing the initiator state.
func VerifyAPRepWithDetails(request *APReq, der []byte) (APRepDetails, error) {
	if request == nil {
		return APRepDetails{}, fmt.Errorf("verify AP-REP: nil request")
	}
	if request.APOptions&types.APMutualRequired == 0 {
		return APRepDetails{}, fmt.Errorf("verify AP-REP: mutual authentication was not requested")
	}
	var reply protocol.APRep
	if err := asn1.Unmarshal(der, &reply); err != nil {
		return APRepDetails{}, fmt.Errorf("verify AP-REP: %w", err)
	}
	if reply.PVNO != 5 || reply.MsgType != 15 || reply.EncPart.EType != request.SessionKey.KeyType {
		return APRepDetails{}, fmt.Errorf("verify AP-REP: %w", krberrors.ErrIntegrity)
	}
	etype, err := crypto.NewRegistry().Get(request.SessionKey.KeyType)
	if err != nil {
		return APRepDetails{}, err
	}
	plain, err := etype.Decrypt(request.SessionKey.KeyValue, apRepUsage, reply.EncPart.Cipher)
	if err != nil {
		return APRepDetails{}, fmt.Errorf("verify AP-REP encrypted part: %w", err)
	}
	var part protocol.EncAPRepPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		return APRepDetails{}, fmt.Errorf("verify AP-REP encrypted part: %w", krberrors.ErrIntegrity)
	}
	if !part.Ctime.Present || !part.Ctime.Time.Equal(request.AuthenticatorTime.Truncate(time.Second)) ||
		part.Cusec != request.Cusec {
		return APRepDetails{}, fmt.Errorf("verify AP-REP: authenticator time mismatch")
	}
	return APRepDetails{
		SubKey:    copyEncryptionKeyPointer(part.SubKey),
		SeqNumber: uint32PointerValue(part.SeqNumber),
	}, nil
}

func findServiceEntry(kt *keytab.Keytab, ticket protocol.Ticket) (keytab.Entry, error) {
	target := principal.Principal{
		Realm: ticket.Realm, NameType: principal.NameType(ticket.SName.NameType),
		Components: ticket.SName.NameString,
	}
	var selected keytab.Entry
	found := false
	for _, entry := range kt.EntriesSnapshot() {
		if !servicePrincipalEqual(entry.Principal, target) || entry.Enctype != ticket.EncPart.EType {
			continue
		}
		if ticket.EncPart.KVNO != nil && entry.KVNO != *ticket.EncPart.KVNO {
			continue
		}
		if !found || entry.KVNO > selected.KVNO {
			selected = entry
			found = true
		}
	}
	if !found {
		return keytab.Entry{}, fmt.Errorf("verify AP-REQ: service key not found")
	}
	return selected, nil
}

func ticketValid(part protocol.EncTicketPart, now time.Time) bool {
	if part.StartTime != nil && now.Before(part.StartTime.Time) {
		return false
	}
	return !now.After(part.EndTime.Time)
}

func withinSkew(value, now time.Time, skew time.Duration) bool {
	difference := value.Sub(now)
	if difference < 0 {
		difference = -difference
	}
	return difference <= skew
}

func sameProtocolPrincipal(left, right protocol.PrincipalName) bool {
	return left.NameType == right.NameType && slicesEqual(left.NameString, right.NameString)
}

func principalEqual(left, right principal.Principal) bool {
	return left.Realm == right.Realm && left.NameType == right.NameType &&
		slicesEqual(left.Components, right.Components)
}

func servicePrincipalEqual(left, right principal.Principal) bool {
	return left.Realm == right.Realm && slicesEqual(left.Components, right.Components)
}

func slicesEqual(left, right []string) bool {
	return len(left) == len(right) && func() bool {
		for i := range left {
			if left[i] != right[i] {
				return false
			}
		}
		return true
	}()
}

func joinPrincipalComponents(components []string) string {
	return string(bytes.Join(func() [][]byte {
		result := make([][]byte, len(components))
		for i := range components {
			result[i] = []byte(components[i])
		}
		return result
	}(), []byte{0}))
}

func copyEncryptionKey(value protocol.EncryptionKey) protocol.EncryptionKey {
	return protocol.EncryptionKey{KeyType: value.KeyType, KeyValue: append([]byte(nil), value.KeyValue...)}
}

func copyEncryptionKeyPointer(value *protocol.EncryptionKey) *protocol.EncryptionKey {
	if value == nil {
		return nil
	}
	result := copyEncryptionKey(*value)
	return &result
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}

func uint32PointerValue(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

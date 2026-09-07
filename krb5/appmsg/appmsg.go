// Package appmsg implements the KRB-SAFE and KRB-PRIV application messages.
package appmsg

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/fast"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/rcache"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	safeKeyUsage = 15
	privKeyUsage = 13
	defaultSkew  = 5 * time.Minute
)

// Options controls application-message protection and validation.
type Options struct {
	Key            protocol.EncryptionKey
	LocalAddress   *protocol.HostAddress
	RemoteAddress  *protocol.HostAddress
	DoTime         bool
	DoSequence     bool
	SequenceNumber uint32
	ClockSkew      time.Duration
	Now            func() time.Time
	// ReplayCache is consulted only when DoTime is set.
	ReplayCache rcache.Cache
}

func MakeSafe(data []byte, opts *Options) ([]byte, error) {
	etype, err := validateOptions(opts, true)
	if err != nil {
		return nil, err
	}
	body := safeBody(data, opts)
	message := protocol.KRBSafe{PVNO: 5, MsgType: 20, SafeBody: body}
	zeroDER, err := asn1.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("appmsg: encode KRB-SAFE checksum input: %w", err)
	}
	checksum, err := etype.Checksum(opts.Key.KeyValue, safeKeyUsage, zeroDER)
	if err != nil {
		return nil, fmt.Errorf("appmsg: KRB-SAFE checksum: %w", err)
	}
	message.Checksum = protocol.Checksum{
		ChecksumType: fast.ChecksumType(opts.Key.KeyType),
		Checksum:     checksum,
	}
	if message.Checksum.ChecksumType == 0 {
		return nil, fmt.Errorf("appmsg: unsupported KRB-SAFE checksum enctype %d", opts.Key.KeyType)
	}
	return asn1.Marshal(message)
}

func ReadSafe(der []byte, opts *Options) ([]byte, error) {
	etype, err := validateOptions(opts, false)
	if err != nil {
		return nil, err
	}
	var message protocol.KRBSafe
	if err := asn1.Unmarshal(der, &message); err != nil {
		return nil, fmt.Errorf("appmsg: decode KRB-SAFE: %w", err)
	}
	if message.PVNO != 5 || message.MsgType != 20 {
		return nil, fmt.Errorf("appmsg: invalid KRB-SAFE message type")
	}
	expectedType := fast.ChecksumType(opts.Key.KeyType)
	if expectedType == 0 || message.Checksum.ChecksumType != expectedType ||
		len(message.Checksum.Checksum) == 0 {
		return nil, appError(krberr.KRBAPErrInappCksum, "invalid KRB-SAFE checksum type")
	}
	received := append([]byte(nil), message.Checksum.Checksum...)
	message.Checksum = protocol.Checksum{}
	checksumDER, err := asn1.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("appmsg: encode KRB-SAFE checksum input: %w", err)
	}
	if err := etype.VerifyChecksum(opts.Key.KeyValue, safeKeyUsage, checksumDER, received); err != nil {
		return nil, fmt.Errorf("appmsg: KRB-SAFE integrity: %w", err)
	}
	if err := validateAddresses(message.SafeBody.SAddress, message.SafeBody.RAddress, opts); err != nil {
		return nil, err
	}
	if err := validateReplayFields(message.SafeBody.Timestamp, message.SafeBody.Usec,
		message.SafeBody.SeqNumber, opts); err != nil {
		return nil, err
	}
	if err := checkReplay(rcache.TagFromChecksum(received), message.SafeBody.Timestamp, opts); err != nil {
		return nil, err
	}
	return append([]byte(nil), message.SafeBody.UserData...), nil
}

func MakePriv(data []byte, opts *Options) ([]byte, error) {
	etype, err := validateOptions(opts, true)
	if err != nil {
		return nil, err
	}
	body := privBody(data, opts)
	plaintext, err := asn1.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("appmsg: encode KRB-PRIV encrypted part: %w", err)
	}
	ciphertext, err := etype.Encrypt(opts.Key.KeyValue, privKeyUsage, plaintext)
	if err != nil {
		return nil, fmt.Errorf("appmsg: KRB-PRIV encryption: %w", err)
	}
	return asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: opts.Key.KeyType, Cipher: ciphertext},
	})
}

func ReadPriv(der []byte, opts *Options) ([]byte, error) {
	etype, err := validateOptions(opts, false)
	if err != nil {
		return nil, err
	}
	var message protocol.KRBPriv
	if err := asn1.Unmarshal(der, &message); err != nil {
		return nil, fmt.Errorf("appmsg: decode KRB-PRIV: %w", err)
	}
	if message.PVNO != 5 || message.MsgType != 21 {
		return nil, fmt.Errorf("appmsg: invalid KRB-PRIV message type")
	}
	if message.EncPart.EType != opts.Key.KeyType {
		return nil, fmt.Errorf("appmsg: KRB-PRIV enctype %d does not match key enctype %d",
			message.EncPart.EType, opts.Key.KeyType)
	}
	plaintext, err := etype.Decrypt(opts.Key.KeyValue, privKeyUsage, message.EncPart.Cipher)
	if err != nil {
		return nil, fmt.Errorf("appmsg: KRB-PRIV decryption: %w", err)
	}
	var body protocol.EncKRBPrivPart
	if err := asn1.Unmarshal(plaintext, &body); err != nil {
		return nil, fmt.Errorf("appmsg: decode KRB-PRIV encrypted part: %w", err)
	}
	if err := validateAddresses(body.SAddress, body.RAddress, opts); err != nil {
		return nil, err
	}
	if err := validateReplayFields(body.Timestamp, body.Usec, body.SeqNumber, opts); err != nil {
		return nil, err
	}
	if err := checkReplay(rcache.TagFromCiphertext(message.EncPart.Cipher, etype.ChecksumSize()),
		body.Timestamp, opts); err != nil {
		return nil, err
	}
	return append([]byte(nil), body.UserData...), nil
}

func validateOptions(opts *Options, requireLocal bool) (crypto.EType, error) {
	if opts == nil {
		return nil, fmt.Errorf("appmsg: nil options")
	}
	if requireLocal && opts.LocalAddress == nil {
		return nil, appError(krberr.KRBAPErrBadAddr, "local address is required")
	}
	if len(opts.Key.KeyValue) == 0 {
		return nil, fmt.Errorf("appmsg: missing encryption key")
	}
	etype, err := crypto.NewRegistry().Get(opts.Key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("appmsg: encryption key: %w", err)
	}
	if opts.ClockSkew < 0 {
		return nil, fmt.Errorf("appmsg: negative clock skew")
	}
	return etype, nil
}

func safeBody(data []byte, opts *Options) protocol.SafeBody {
	body := protocol.SafeBody{
		UserData: append([]byte(nil), data...),
		SAddress: *copyAddress(opts.LocalAddress),
		RAddress: copyAddress(opts.RemoteAddress),
	}
	if opts.DoTime {
		now := nowFunc(opts)().UTC()
		usec := int32(now.Nanosecond() / 1000)
		body.Timestamp = &types.KerberosTime{Time: now, Present: true}
		body.Usec = &usec
	}
	if opts.DoSequence {
		seq := opts.SequenceNumber
		body.SeqNumber = &seq
	}
	return body
}

func privBody(data []byte, opts *Options) protocol.EncKRBPrivPart {
	body := protocol.EncKRBPrivPart{
		UserData: append([]byte(nil), data...),
		SAddress: *copyAddress(opts.LocalAddress),
		RAddress: copyAddress(opts.RemoteAddress),
	}
	if opts.DoTime {
		now := nowFunc(opts)().UTC()
		usec := int32(now.Nanosecond() / 1000)
		body.Timestamp = &types.KerberosTime{Time: now, Present: true}
		body.Usec = &usec
	}
	if opts.DoSequence {
		seq := opts.SequenceNumber
		body.SeqNumber = &seq
	}
	return body
}

func validateAddresses(sender protocol.HostAddress, receiver *protocol.HostAddress, opts *Options) error {
	if opts.RemoteAddress != nil && !sameAddress(sender, *opts.RemoteAddress) {
		return appError(krberr.KRBAPErrBadAddr, "sender address mismatch")
	}
	if receiver != nil && opts.LocalAddress != nil && !sameAddress(*receiver, *opts.LocalAddress) {
		return appError(krberr.KRBAPErrBadAddr, "receiver address mismatch")
	}
	return nil
}

func validateReplayFields(timestamp *types.KerberosTime, usec *int32, seq *uint32, opts *Options) error {
	if opts.DoTime {
		if timestamp == nil || !timestamp.Present {
			return appError(krberr.KRBAPErrSkew, "missing timestamp")
		}
		skew := effectiveSkew(opts)
		messageTime := timestamp.Time
		if usec != nil {
			messageTime = messageTime.Add(time.Duration(*usec) * time.Microsecond)
		}
		delta := messageTime.Sub(nowFunc(opts)())
		if delta < 0 {
			delta = -delta
		}
		if delta > skew {
			return appError(krberr.KRBAPErrSkew, "timestamp outside clock skew")
		}
	}
	if opts.DoSequence {
		if seq == nil || *seq != opts.SequenceNumber {
			return appError(krberr.KRBAPErrBadOrder, "unexpected sequence number")
		}
	}
	return nil
}

func checkReplay(tag []byte, timestamp *types.KerberosTime, opts *Options) error {
	if !opts.DoTime || opts.ReplayCache == nil {
		return nil
	}
	if timestamp == nil || !timestamp.Present {
		return appError(krberr.KRBAPErrSkew, "missing timestamp")
	}
	if err := opts.ReplayCache.Store(tag, timestamp.Time, effectiveSkew(opts)); err != nil {
		if stderrors.Is(err, rcache.ErrReplay) {
			return appError(krberr.KRBAPErrRepeat, "replayed application message")
		}
		return fmt.Errorf("appmsg: replay cache: %w", err)
	}
	return nil
}

func effectiveSkew(opts *Options) time.Duration {
	if opts.ClockSkew == 0 {
		return defaultSkew
	}
	return opts.ClockSkew
}

func sameAddress(left, right protocol.HostAddress) bool {
	return left.AddrType == right.AddrType && bytes.Equal(left.Address, right.Address)
}

func copyAddress(value *protocol.HostAddress) *protocol.HostAddress {
	if value == nil {
		return nil
	}
	return &protocol.HostAddress{AddrType: value.AddrType, Address: append([]byte(nil), value.Address...)}
}

func nowFunc(opts *Options) func() time.Time {
	if opts.Now != nil {
		return opts.Now
	}
	return time.Now
}

func appError(code krberr.ErrorCode, message string) error {
	return fmt.Errorf("appmsg: %s: %w", message,
		krberr.NewKRBError(code, "", "", time.Time{}, 0, nil))
}

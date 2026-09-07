package appmsg

import (
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/rcache"
	"github.com/Exonical/go-kerberos/krb5/types"
)

var (
	testKey = protocol.EncryptionKey{
		KeyType:  crypto.EnctypeAES128SHA1,
		KeyValue: []byte("0123456789abcdef"),
	}
	testSender   = &protocol.HostAddress{AddrType: 2, Address: []byte{192, 0, 2, 1}}
	testReceiver = &protocol.HostAddress{AddrType: 2, Address: []byte{192, 0, 2, 2}}
	testNow      = time.Date(2025, time.January, 2, 3, 4, 5, 678901000, time.UTC)
)

func TestSafeAndPrivRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		time bool
		seq  bool
	}{
		{name: "plain"},
		{name: "replay-fields", time: true, seq: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeOpts := messageOptions(tc.time, tc.seq, testSender, testReceiver, 7, testNow)
			readOpts := messageOptions(tc.time, tc.seq, testReceiver, testSender, 7, testNow)
			safe, err := MakeSafe([]byte("safe payload"), makeOpts)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadSafe(safe, readOpts)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "safe payload" {
				t.Fatalf("safe payload = %q", got)
			}
			priv, err := MakePriv([]byte("private payload"), makeOpts)
			if err != nil {
				t.Fatal(err)
			}
			got, err = ReadPriv(priv, readOpts)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "private payload" {
				t.Fatalf("private payload = %q", got)
			}
			if !tc.time && !tc.seq {
				var safeMessage protocol.KRBSafe
				if err := asn1.Unmarshal(safe, &safeMessage); err != nil {
					t.Fatal(err)
				}
				if safeMessage.SafeBody.Timestamp != nil || safeMessage.SafeBody.SeqNumber != nil {
					t.Fatal("plain KRB-SAFE unexpectedly contains replay fields")
				}
			}
		})
	}
}

func TestSafeTamperAndChecksumValidation(t *testing.T) {
	opts := messageOptions(false, false, testSender, nil, 0, testNow)
	der, err := MakeSafe([]byte("safe payload"), opts)
	if err != nil {
		t.Fatal(err)
	}
	var message protocol.KRBSafe
	if err := asn1.Unmarshal(der, &message); err != nil {
		t.Fatal(err)
	}
	message.SafeBody.UserData[0] ^= 1
	tampered, err := asn1.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSafe(tampered, messageOptions(false, false, nil, testSender, 0, testNow)); !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("tampered safe error = %v, want integrity error", err)
	}
	wrongKey := messageOptions(false, false, nil, testSender, 0, testNow)
	wrongKey.Key.KeyValue = []byte("fedcba9876543210")
	if _, err := ReadSafe(der, wrongKey); !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("wrong-key safe error = %v, want integrity error", err)
	}

	message, err = decodeSafe(der)
	if err != nil {
		t.Fatal(err)
	}
	message.Checksum.ChecksumType = 1
	unkeyed, err := asn1.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var typed *krberrors.KRBError
	if _, err := ReadSafe(unkeyed, messageOptions(false, false, nil, testSender, 0, testNow)); !errors.As(err, &typed) ||
		typed.Code != krberrors.KRBAPErrInappCksum {
		t.Fatalf("unkeyed checksum error = %v, want KRB_AP_ERR_INAPP_CKSUM", err)
	}
}

func TestPrivTamperAndWrongKey(t *testing.T) {
	opts := messageOptions(false, false, testSender, nil, 0, testNow)
	der, err := MakePriv([]byte("private payload"), opts)
	if err != nil {
		t.Fatal(err)
	}
	var message protocol.KRBPriv
	if err := asn1.Unmarshal(der, &message); err != nil {
		t.Fatal(err)
	}
	message.EncPart.Cipher[0] ^= 1
	tampered, err := asn1.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	readOpts := messageOptions(false, false, nil, testSender, 0, testNow)
	if _, err := ReadPriv(tampered, readOpts); !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("tampered priv error = %v, want integrity error", err)
	}
	wrong := *readOpts
	wrong.Key.KeyValue = []byte("fedcba9876543210")
	if _, err := ReadPriv(der, &wrong); !errors.Is(err, krberrors.ErrIntegrity) {
		t.Fatalf("wrong-key priv error = %v, want integrity error", err)
	}
}

func TestReplayAndAddressValidation(t *testing.T) {
	makeOpts := messageOptions(true, true, testSender, testReceiver, 7, testNow)
	safe, err := MakeSafe([]byte("payload"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	var typed *krberrors.KRBError
	wrongAddress := messageOptions(true, true,
		testReceiver, &protocol.HostAddress{AddrType: 2, Address: []byte{192, 0, 2, 9}},
		7, testNow)
	if _, err := ReadSafe(safe, wrongAddress); !errors.As(err, &typed) ||
		typed.Code != krberrors.KRBAPErrBadAddr {
		t.Fatalf("address error = %v, want KRB_AP_ERR_BADADDR", err)
	}
	wrongSequence := messageOptions(true, true, testReceiver, testSender, 8, testNow)
	if _, err := ReadSafe(safe, wrongSequence); !errors.As(err, &typed) ||
		typed.Code != krberrors.KRBAPErrBadOrder {
		t.Fatalf("sequence error = %v, want KRB_AP_ERR_BADORDER", err)
	}
	skewed := messageOptions(true, true, testReceiver, testSender, 7, testNow.Add(10*time.Minute))
	if _, err := ReadSafe(safe, skewed); !errors.As(err, &typed) ||
		typed.Code != krberrors.KRBAPErrSkew {
		t.Fatalf("skew error = %v, want KRB_AP_ERR_SKEW", err)
	}
}

func TestPrivAcceptsKpasswdStyleMessage(t *testing.T) {
	now := testNow.UTC()
	plain, err := asn1.Marshal(protocol.EncKRBPrivPart{
		UserData:  []byte("kpasswd payload"),
		Timestamp: &types.KerberosTime{Time: now, Present: true},
		SAddress:  protocol.HostAddress{},
	})
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(testKey.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := etype.Encrypt(testKey.KeyValue, privKeyUsage, plain)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: testKey.KeyType, Cipher: ciphertext},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := &Options{Key: testKey, DoTime: true, Now: func() time.Time { return now }}
	got, err := ReadPriv(der, opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "kpasswd payload" {
		t.Fatalf("payload = %q", got)
	}
}

func TestMakeRequiresLocalAddress(t *testing.T) {
	opts := messageOptions(false, false, nil, nil, 0, testNow)
	var typed *krberrors.KRBError
	if _, err := MakeSafe([]byte("payload"), opts); !errors.As(err, &typed) ||
		typed.Code != krberrors.KRBAPErrBadAddr {
		t.Fatalf("MakeSafe error = %v, want KRB_AP_ERR_BADADDR", err)
	}
	if _, err := MakePriv([]byte("payload"), opts); !errors.As(err, &typed) ||
		typed.Code != krberrors.KRBAPErrBadAddr {
		t.Fatalf("MakePriv error = %v, want KRB_AP_ERR_BADADDR", err)
	}
}

func TestReplayCacheRejectsDuplicateSafeAndPriv(t *testing.T) {
	makeOpts := messageOptions(true, false, testSender, nil, 0, testNow)
	safe, err := MakeSafe([]byte("replayed safe"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := MakePriv([]byte("replayed priv"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		read func(*Options) error
	}{
		{
			name: "safe",
			read: func(opts *Options) error {
				_, err := ReadSafe(safe, opts)
				return err
			},
		},
		{
			name: "priv",
			read: func(opts *Options) error {
				_, err := ReadPriv(priv, opts)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := messageOptions(true, false, nil, testSender, 0, testNow)
			opts.ReplayCache = &rcache.Memory{}
			if err := test.read(opts); err != nil {
				t.Fatal(err)
			}
			var typed *krberrors.KRBError
			if err := test.read(opts); !errors.As(err, &typed) ||
				typed.Code != krberrors.KRBAPErrRepeat {
				t.Fatalf("duplicate error = %v, want KRB_AP_ERR_REPEAT", err)
			}
		})
	}
}

func TestReplayCacheAllowsDistinctMessagesAndDisabledChecks(t *testing.T) {
	makeOpts := messageOptions(true, false, testSender, nil, 0, testNow)
	cache := &rcache.Memory{}
	readOpts := messageOptions(true, false, nil, testSender, 0, testNow)
	readOpts.ReplayCache = cache
	first, err := MakeSafe([]byte("first"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MakeSafe([]byte("second"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSafe(first, readOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSafe(second, readOpts); err != nil {
		t.Fatal(err)
	}
	privFirst, err := MakePriv([]byte("first private"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	privSecond, err := MakePriv([]byte("second private"), makeOpts)
	if err != nil {
		t.Fatal(err)
	}
	privCache := &rcache.Memory{}
	privRead := messageOptions(true, false, nil, testSender, 0, testNow)
	privRead.ReplayCache = privCache
	if _, err := ReadPriv(privFirst, privRead); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPriv(privSecond, privRead); err != nil {
		t.Fatal(err)
	}

	plainMake := messageOptions(false, false, testSender, nil, 0, testNow)
	plain, err := MakeSafe([]byte("plain"), plainMake)
	if err != nil {
		t.Fatal(err)
	}
	plainRead := messageOptions(false, false, nil, testSender, 0, testNow)
	plainRead.ReplayCache = &rcache.Memory{}
	for i := 0; i < 2; i++ {
		if _, err := ReadSafe(plain, plainRead); err != nil {
			t.Fatalf("plain read %d: %v", i, err)
		}
	}
	noCacheRead := messageOptions(true, false, nil, testSender, 0, testNow)
	for i := 0; i < 2; i++ {
		if _, err := ReadSafe(first, noCacheRead); err != nil {
			t.Fatalf("no-cache read %d: %v", i, err)
		}
	}
}

func messageOptions(doTime, doSequence bool, local, remote *protocol.HostAddress,
	sequence uint32, now time.Time) *Options {
	return &Options{
		Key:            testKey,
		LocalAddress:   local,
		RemoteAddress:  remote,
		DoTime:         doTime,
		DoSequence:     doSequence,
		SequenceNumber: sequence,
		Now:            func() time.Time { return now },
	}
}

func decodeSafe(der []byte) (protocol.KRBSafe, error) {
	var message protocol.KRBSafe
	err := asn1.Unmarshal(der, &message)
	return message, err
}

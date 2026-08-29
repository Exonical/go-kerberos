//go:build integration

package mit_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

type radiusOTPStub struct {
	conn     *net.UDPConn
	secret   []byte
	expected string
	done     chan struct{}
}

func newRadiusOTPStub(t *testing.T, expected, secret string) *radiusOTPStub {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen RADIUS: %v", err)
	}
	stub := &radiusOTPStub{
		conn: conn, secret: []byte(secret), expected: expected,
		done: make(chan struct{}),
	}
	go stub.serve()
	t.Cleanup(func() {
		close(stub.done)
		_ = conn.Close()
	})
	return stub
}

func (s *radiusOTPStub) address() string {
	return s.conn.LocalAddr().String()
}

func (s *radiusOTPStub) serve() {
	packet := make([]byte, 4096)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, remote, err := s.conn.ReadFromUDP(packet)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		if response, ok := s.response(packet[:n]); ok {
			_, _ = s.conn.WriteToUDP(response, remote)
		}
	}
}

func (s *radiusOTPStub) response(packet []byte) ([]byte, bool) {
	if len(packet) < 20 || packet[0] != 1 {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if length < 20 || length > len(packet) {
		return nil, false
	}
	authenticator := packet[4:20]
	password := []byte(nil)
	for offset := 20; offset+2 <= length; {
		attrLen := int(packet[offset+1])
		if attrLen < 2 || offset+attrLen > length {
			return nil, false
		}
		if packet[offset] == 2 {
			password = decryptUserPassword(packet[offset+2:offset+attrLen], s.secret, authenticator)
		}
		offset += attrLen
	}
	if string(bytesTrimZero(password)) != s.expected {
		return s.accessReject(packet[:length]), true
	}
	return s.accessAccept(packet[:length]), true
}

func (s *radiusOTPStub) accessAccept(request []byte) []byte {
	return s.responsePacket(2, request)
}

func (s *radiusOTPStub) accessReject(request []byte) []byte {
	return s.responsePacket(3, request)
}

func (s *radiusOTPStub) responsePacket(code byte, request []byte) []byte {
	response := make([]byte, 20)
	response[0] = code
	response[1] = request[1]
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	copy(response[4:20], request[4:20])
	hash := md5.New()
	_, _ = hash.Write(response)
	_, _ = hash.Write(s.secret)
	copy(response[4:20], hash.Sum(nil))
	return response
}

func decryptUserPassword(ciphertext, secret, authenticator []byte) []byte {
	if len(ciphertext) == 0 || len(ciphertext)%16 != 0 {
		return nil
	}
	plain := make([]byte, len(ciphertext))
	previous := authenticator
	for offset := 0; offset < len(ciphertext); offset += 16 {
		hash := md5.New()
		_, _ = hash.Write(secret)
		_, _ = hash.Write(previous)
		mask := hash.Sum(nil)
		for i := 0; i < 16; i++ {
			plain[offset+i] = ciphertext[offset+i] ^ mask[i]
		}
		previous = ciphertext[offset : offset+16]
	}
	return plain
}

func bytesTrimZero(value []byte) []byte {
	for len(value) > 0 && value[len(value)-1] == 0 {
		value = value[:len(value)-1]
	}
	return value
}

func requireMITOTPPlugin(t *testing.T) {
	t.Helper()
	const plugin = "/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/otp.so"
	if _, err := os.Stat(plugin); err != nil {
		t.Skipf("MIT OTP plugin unavailable: %s", plugin)
	}
}

func armorCredentials(t *testing.T, path string) *client.Credentials {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open armor ccache: %v", err)
	}
	defer file.Close()
	cache, err := ccache.Read(file)
	if err != nil {
		t.Fatalf("read armor ccache: %v", err)
	}
	for _, item := range cache.Credentials {
		if len(item.Server.Components) == 2 && item.Server.Components[0] == "krbtgt" {
			return &client.Credentials{
				Client: item.Client,
				Server: item.Server,
				Key:    protocol.EncryptionKey{KeyType: item.Enctype, KeyValue: item.Key},
				Flags:  types.TicketFlags(item.TicketFlags),
				Ticket: item.Ticket,
			}
		}
	}
	t.Fatalf("armor ccache contains no TGT")
	return nil
}

func markFASTAvailable(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read armor ccache: %v", err)
	}
	cache, err := ccache.Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode armor ccache: %v", err)
	}
	if len(cache.Credentials) == 0 {
		t.Fatalf("armor ccache contains no credentials")
	}
	armorServer := cache.Credentials[0].Server.String()
	cache.Credentials = append(cache.Credentials, ccache.Credential{
		Client: cache.DefaultPrincipal,
		Server: principal.Principal{
			Realm:      "X-CACHECONF:",
			Components: []string{"krb5_ccache_conf_data", "fast_avail", armorServer},
		},
		Ticket: []byte("yes"),
	})
	var encoded bytes.Buffer
	if err := ccache.Write(&encoded, cache); err != nil {
		t.Fatalf("encode armor ccache: %v", err)
	}
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatalf("write armor ccache: %v", err)
	}
}

func TestGoClientOTPAgainstMITKDC(t *testing.T) {
	requireMITOTPPlugin(t)
	const secret = "otp-test-shared-secret"
	radius := newRadiusOTPStub(t, "123456", secret)
	realm := testenv.StartWithOTP(t, radius.address(), secret)
	armorPath := filepath.Join(realm.Dir, "armor.ccache")
	realm.Run(t, "alice-password\n", "/usr/bin/kinit", "-c", armorPath, "alice")
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q",
		`setstr alice otp "[{""type"":""DEFAULT""}]"`)
	realm.Run(t, "", "/usr/sbin/kadmin.local", "-q", "modprinc +requires_preauth alice")
	armor := armorCredentials(t, armorPath)

	configData, err := os.ReadFile(realm.Config)
	if err != nil {
		t.Fatalf("read MIT config: %v", err)
	}
	cfg, err := config.Parse(configData)
	if err != nil {
		t.Fatalf("parse MIT config: %v", err)
	}
	user := principal.Principal{
		Realm: testenv.RealmName, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	goClient := &client.Client{
		Config: cfg, Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}
	credentials, err := goClient.ASExchangeFASTOTP(context.Background(), user, armor,
		func(challenge otp.Challenge) (string, string, error) {
			return "123456", "", nil
		})
	if err != nil {
		t.Fatalf("Go OTP exchange against MIT KDC: %v", err)
	}
	if credentials.Client.String() != user.String() {
		t.Fatalf("OTP credentials client = %s, want %s", credentials.Client, user)
	}
}

func TestMITClientOTPAgainstGoKDC(t *testing.T) {
	requireMITOTPPlugin(t)
	k := startGoKDC(t)
	armorPath := filepath.Join(filepath.Dir(k.cache), "otp-armor.ccache")
	otpPath := filepath.Join(filepath.Dir(k.cache), "otp.ccache")
	k.run(t, "alice-password\n", "/usr/bin/kinit", "-c", armorPath, "alice")
	markFASTAvailable(t, armorPath)
	k.server.OTPValidator = func(_ principal.Principal, value string) error {
		if value != "123456" {
			return fmt.Errorf("unexpected OTP %q", value)
		}
		return nil
	}
	output, err := k.runResult("123456\n", "/usr/bin/kinit", "-T", armorPath, "-c", otpPath, "alice")
	if err != nil {
		t.Fatalf("MIT OTP kinit against Go KDC: %v\n%s", err, output)
	}
	klist, err := k.runResult("", "/usr/bin/klist", "-c", otpPath)
	if err != nil || !strings.Contains(klist, "krbtgt/"+goKDCRealm+"@"+goKDCRealm) {
		t.Fatalf("MIT OTP kinit did not obtain a TGT")
	}
}

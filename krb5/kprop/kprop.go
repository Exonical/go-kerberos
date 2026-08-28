// Package kprop implements the MIT krb5 kprop/kpropd dump transfer protocol.
package kprop

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	ProtocolVersion = "kprop5_01"
	SendAuthVersion = "KRB5_SENDAUTH_V1.0"
	ServiceName     = "host"
	DefaultPort     = 754
	BlockSize       = 32768
	SafeUsage       = 15
	PrivUsage       = 13
	maxFrameSize    = 64 << 20
)

var ErrRemote = errors.New("kprop: remote error")

// Client performs a kprop transfer using supplied service credentials.
type Client struct {
	Credentials *client.Credentials
}

// Send transfers dump over conn.
func (c *Client) Send(ctx context.Context, conn net.Conn, dump io.Reader, size uint64) error {
	if c == nil {
		return errors.New("kprop: nil client")
	}
	return Send(ctx, conn, c.Credentials, dump, size)
}

// ServiceCredentials obtains a host/<replica> service ticket from an existing
// TGT using the repository's normal TGS exchange.
func ServiceCredentials(ctx context.Context, kerberos *client.Client, tgt *client.Credentials, replicaHost string, realm string) (*client.Credentials, error) {
	if kerberos == nil || tgt == nil || replicaHost == "" {
		return nil, errors.New("kprop: incomplete service credential request")
	}
	if realm == "" {
		realm = tgt.Client.Realm
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{ServiceName, replicaHost},
	}
	return kerberos.TGSExchange(ctx, tgt, service)
}

// EncodeDatabaseSize returns MIT's canonical database-size representation.
func EncodeDatabaseSize(size uint64) []byte { return encodeDatabaseSize(size) }

// DecodeDatabaseSize decodes MIT's canonical database-size representation.
func DecodeDatabaseSize(data []byte) (uint64, error) {
	size, _, err := decodeDatabaseSize(data)
	return size, err
}

// ReadFrame reads one krb5_write_message frame.
func ReadFrame(ctx context.Context, conn net.Conn) ([]byte, error) {
	return readContextFrame(ctx, conn)
}

// WriteFrame writes one krb5_write_message frame.
func WriteFrame(ctx context.Context, conn net.Conn, payload []byte) error {
	return writeContextFrame(ctx, conn, payload)
}

// Send performs one MIT kprop transfer over an already connected connection.
func Send(ctx context.Context, conn net.Conn, creds *client.Credentials, dump io.Reader, size uint64) error {
	if conn == nil || creds == nil || dump == nil {
		return errors.New("kprop: nil connection, credentials, or dump")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	state, apDER, err := ap.BuildAPReqWithOptions(creds, types.APMutualRequired, now, ap.APReqOptions{NoSubKey: true})
	if err != nil {
		return fmt.Errorf("kprop AP-REQ: %w", err)
	}
	if err := writeContextFrame(ctx, conn, []byte(SendAuthVersion+"\x00")); err != nil {
		return fmt.Errorf("kprop sendauth version: %w", err)
	}
	if err := writeContextFrame(ctx, conn, []byte(ProtocolVersion+"\x00")); err != nil {
		return fmt.Errorf("kprop application version: %w", err)
	}
	status, err := readContextByte(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop sendauth status: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("kprop sendauth rejected: status %x", status)
	}
	if err := writeContextFrame(ctx, conn, apDER); err != nil {
		return fmt.Errorf("kprop AP-REQ: %w", err)
	}
	reply, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop AP exchange: %w", err)
	}
	if err := checkError(reply); err != nil {
		return err
	}
	if len(reply) != 0 {
		return errors.New("kprop: expected empty AP authentication response")
	}
	apReply, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop AP-REP: %w", err)
	}
	apDetails, err := ap.VerifyAPRepWithDetails(state, apReply)
	if err != nil {
		return fmt.Errorf("kprop AP-REP: %w", err)
	}
	if apDetails.SeqNumber == nil {
		return errors.New("kprop: AP-REP did not contain sequence number")
	}
	if state.SeqNumber == nil {
		return errors.New("kprop: AP-REQ did not contain sequence number")
	}
	key := state.SubKey
	if key == nil {
		key = &state.SessionKey
	}
	localAddr := hostAddress(conn.LocalAddr())
	seq := *state.SeqNumber
	safe, err := makeSafe(key, encodeDatabaseSize(size), seq, localAddr)
	if err != nil {
		return fmt.Errorf("kprop database size: %w", err)
	}
	if err := writeContextFrame(ctx, conn, safe); err != nil {
		return fmt.Errorf("kprop database size: %w", err)
	}
	seq++
	iv := make([]byte, 16)
	var sent uint64
	buf := make([]byte, BlockSize)
	for sent < size {
		want := uint64(len(buf))
		if remain := size - sent; remain < want {
			want = remain
		}
		n, readErr := io.ReadFull(dump, buf[:int(want)])
		if readErr != nil {
			return fmt.Errorf("kprop dump at %d: %w", sent, readErr)
		}
		if n == 0 {
			return errors.New("kprop: dump reader returned no data")
		}
		priv, nextIV, err := makePriv(key, buf[:n], seq, localAddr, iv)
		if err != nil {
			return fmt.Errorf("kprop dump block at %d: %w", sent, err)
		}
		if err := writeContextFrame(ctx, conn, priv); err != nil {
			return fmt.Errorf("kprop dump block at %d: %w", sent, err)
		}
		iv = nextIV
		seq++
		sent += uint64(n)
	}
	final, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop final response: %w", err)
	}
	if err := checkError(final); err != nil {
		return err
	}
	echo, _, err := verifySafe(key, final, *apDetails.SeqNumber, hostAddress(nil))
	if err != nil {
		return fmt.Errorf("kprop final response: %w", err)
	}
	if echo != size {
		return fmt.Errorf("kprop: server echoed size %d, want %d", echo, size)
	}
	return nil
}

// DialAndSend dials address and performs a transfer.
func DialAndSend(ctx context.Context, address string, creds *client.Credentials, dump io.Reader, size uint64) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("kprop dial: %w", err)
	}
	defer conn.Close()
	return Send(ctx, conn, creds, dump, size)
}

// Server handles MIT kpropd connections.
type Server struct {
	Keytab    *keytab.Keytab
	Realm     string
	Authorize func(principal.Principal) error
	Load      func(io.Reader, uint64) error
	Now       func() time.Time
	ErrorLog  func(error)
}

// Serve accepts kpropd connections until listener failure.
func (s *Server) Serve(listener net.Listener) error {
	if s == nil || s.Keytab == nil || s.Load == nil {
		return errors.New("kprop: incomplete server configuration")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := s.ServeConn(context.Background(), conn); err != nil && s.ErrorLog != nil {
				s.ErrorLog(err)
			}
		}()
	}
}

// ServeConn handles one kprop connection.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	if s == nil || s.Keytab == nil || s.Load == nil || conn == nil {
		return errors.New("kprop: incomplete server configuration")
	}
	defer conn.Close()
	first, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop sendauth version: %w", err)
	}
	second, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop application version: %w", err)
	}
	if string(first) != SendAuthVersion+"\x00" {
		_ = writeContextByte(ctx, conn, 1)
		return errors.New("kprop: invalid sendauth version")
	}
	if string(second) != ProtocolVersion+"\x00" {
		_ = writeContextByte(ctx, conn, 2)
		return errors.New("kprop: invalid application version")
	}
	if err := writeContextByte(ctx, conn, 0); err != nil {
		return err
	}
	requestDER, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop AP-REQ: %w", err)
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	request, err := ap.VerifyAPReq(s.Keytab, requestDER, now, 5*time.Minute)
	if err != nil {
		_ = s.writeError(ctx, conn, 60, err.Error())
		return fmt.Errorf("kprop AP-REQ: %w", err)
	}
	if request.APOptions&types.APMutualRequired == 0 {
		_ = s.writeError(ctx, conn, 60, "mutual authentication required")
		return errors.New("kprop: AP-REQ did not request mutual authentication")
	}
	if s.Authorize != nil {
		if err := s.Authorize(request.Client); err != nil {
			_ = s.writeError(ctx, conn, 45, err.Error())
			return fmt.Errorf("kprop authorization: %w", err)
		}
	}
	if err := writeContextFrame(ctx, conn, nil); err != nil {
		return fmt.Errorf("kprop AP authentication response: %w", err)
	}
	var serverSeq uint32
	if _, err := io.ReadFull(crypto.RandomSource, uint32Bytes(&serverSeq)); err != nil {
		return fmt.Errorf("kprop AP-REP sequence: %w", err)
	}
	serverSeq &= uint32(0x7fffffff)
	apReply, err := ap.BuildAPRepWithSequence(request, serverSeq)
	if err != nil {
		return fmt.Errorf("kprop AP-REP: %w", err)
	}
	if err := writeContextFrame(ctx, conn, apReply); err != nil {
		return fmt.Errorf("kprop AP-REP: %w", err)
	}
	if request.SeqNumber == nil {
		return errors.New("kprop: AP-REQ did not contain sequence number")
	}
	key := request.SubKey
	if key == nil {
		key = &request.SessionKey
	}
	localAddr := hostAddress(conn.LocalAddr())
	peerSeq := *request.SeqNumber
	sizeFrame, err := readContextFrame(ctx, conn)
	if err != nil {
		return fmt.Errorf("kprop database size: %w", err)
	}
	size, gotSeq, err := verifySafe(key, sizeFrame, peerSeq, localAddr)
	if err != nil {
		_ = s.writeError(ctx, conn, 60, err.Error())
		return fmt.Errorf("kprop database size: %w", err)
	}
	if gotSeq != peerSeq {
		return errors.New("kprop: unexpected database-size sequence")
	}
	peerSeq++
	iv := make([]byte, 16)
	file, err := os.CreateTemp("", "go-kprop-*")
	if err != nil {
		return fmt.Errorf("kprop temporary dump: %w", err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	var received uint64
	for received < size {
		frame, err := readContextFrame(ctx, conn)
		if err != nil {
			return fmt.Errorf("kprop dump block at %d: %w", received, err)
		}
		if err := checkError(frame); err != nil {
			return err
		}
		data, nextIV, gotSeq, err := openPriv(key, frame, peerSeq, localAddr, iv)
		if err != nil {
			_ = s.writeError(ctx, conn, 60, err.Error())
			return fmt.Errorf("kprop dump block at %d: %w", received, err)
		}
		if gotSeq != peerSeq || uint64(len(data)) > size-received {
			return errors.New("kprop: invalid dump block sequence or size")
		}
		if _, err := file.Write(data); err != nil {
			return fmt.Errorf("kprop dump block: %w", err)
		}
		iv = nextIV
		peerSeq++
		received += uint64(len(data))
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("kprop dump sync: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("kprop dump rewind: %w", err)
	}
	if err := s.Load(file, size); err != nil {
		_ = s.writeError(ctx, conn, 60, err.Error())
		return fmt.Errorf("kprop load: %w", err)
	}
	final, err := makeSafe(key, encodeDatabaseSize(received), serverSeq, localAddr)
	if err != nil {
		return fmt.Errorf("kprop final response: %w", err)
	}
	if err := writeContextFrame(ctx, conn, final); err != nil {
		return fmt.Errorf("kprop final response: %w", err)
	}
	return nil
}

func (s *Server) writeError(ctx context.Context, conn net.Conn, code int32, text string) error {
	if code > 127 {
		code = 60
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	realm := s.Realm
	if realm == "" {
		realm = "UNKNOWN"
	}
	name := protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{ServiceName}}
	etext := text + "\x00"
	der, err := asn1.Marshal(protocol.KRBError{
		PVNO: 5, MsgType: 30, STime: types.KerberosTime{Time: now, Present: true},
		ErrorCode: code, Realm: realm, SName: name, EText: &etext,
	})
	if err != nil {
		return err
	}
	return writeContextFrame(ctx, conn, der)
}

func makeSafe(key *protocol.EncryptionKey, data []byte, seq uint32, addr protocol.HostAddress) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	body := protocol.SafeBody{UserData: append([]byte(nil), data...), SeqNumber: &seq, SAddress: addr}
	message := protocol.KRBSafe{PVNO: 5, MsgType: 20, SafeBody: body}
	encoded, err := asn1.Marshal(message)
	if err != nil {
		return nil, err
	}
	checksum, err := etype.Checksum(key.KeyValue, SafeUsage, encoded)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(protocol.KRBSafe{
		PVNO: 5, MsgType: 20, SafeBody: body,
		Checksum: protocol.Checksum{ChecksumType: checksumType(key.KeyType), Checksum: checksum},
	})
}

func verifySafe(key *protocol.EncryptionKey, der []byte, expectedSeq uint32, local protocol.HostAddress) (uint64, uint32, error) {
	var msg protocol.KRBSafe
	if err := asn1.Unmarshal(der, &msg); err != nil {
		return 0, 0, err
	}
	if msg.PVNO != 5 || msg.MsgType != 20 || msg.SafeBody.SeqNumber == nil {
		return 0, 0, errors.New("kprop: malformed KRB-SAFE")
	}
	if *msg.SafeBody.SeqNumber != expectedSeq {
		return 0, *msg.SafeBody.SeqNumber, fmt.Errorf("kprop: sequence %d, want %d", *msg.SafeBody.SeqNumber, expectedSeq)
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return 0, 0, err
	}
	checksumMessage := msg
	checksumMessage.Checksum = protocol.Checksum{}
	messageDER, err := asn1.Marshal(checksumMessage)
	if err != nil {
		return 0, 0, err
	}
	if msg.Checksum.ChecksumType != checksumType(key.KeyType) ||
		etype.VerifyChecksum(key.KeyValue, SafeUsage, messageDER, msg.Checksum.Checksum) != nil {
		return 0, 0, krberrors.ErrIntegrity
	}
	size, _, err := decodeDatabaseSize(msg.SafeBody.UserData)
	if err != nil {
		return 0, *msg.SafeBody.SeqNumber, err
	}
	return size, *msg.SafeBody.SeqNumber, nil
}

func makePriv(key *protocol.EncryptionKey, data []byte, seq uint32, addr protocol.HostAddress, iv []byte) ([]byte, []byte, error) {
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, nil, err
	}
	body, err := asn1.Marshal(protocol.EncKRBPrivPart{UserData: data, SeqNumber: &seq, SAddress: addr})
	if err != nil {
		return nil, nil, err
	}
	ciphertext, nextIV, err := crypto.EncryptWithIV(etype, key.KeyValue, PrivUsage, body, iv)
	if err != nil {
		return nil, nil, err
	}
	der, err := asn1.Marshal(protocol.KRBPriv{PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: key.KeyType, Cipher: ciphertext}})
	return der, nextIV, err
}

func openPriv(key *protocol.EncryptionKey, der []byte, expected uint32, local protocol.HostAddress, iv []byte) ([]byte, []byte, uint32, error) {
	var msg protocol.KRBPriv
	if err := asn1.Unmarshal(der, &msg); err != nil {
		return nil, nil, 0, err
	}
	if msg.PVNO != 5 || msg.MsgType != 21 || msg.EncPart.EType != key.KeyType {
		return nil, nil, 0, errors.New("kprop: malformed KRB-PRIV")
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, nil, 0, err
	}
	plain, nextIV, err := crypto.DecryptWithIV(etype, key.KeyValue, PrivUsage, msg.EncPart.Cipher, iv)
	if err != nil {
		return nil, nil, 0, err
	}
	var body protocol.EncKRBPrivPart
	if err := asn1.Unmarshal(plain, &body); err != nil || body.SeqNumber == nil {
		return nil, nil, 0, errors.New("kprop: malformed encrypted KRB-PRIV")
	}
	if *body.SeqNumber != expected {
		return nil, nil, *body.SeqNumber, fmt.Errorf("kprop: sequence %d, want %d", *body.SeqNumber, expected)
	}
	_ = local // MIT kpropd deliberately does not compare peer addresses.
	return append([]byte(nil), body.UserData...), nextIV, *body.SeqNumber, nil
}

func writeContextFrame(ctx context.Context, conn net.Conn, payload []byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if len(payload) > maxFrameSize {
		return errors.New("kprop: frame too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(conn, header[:]); err != nil {
		return err
	}
	return writeAll(conn, payload)
}

func writeContextByte(ctx context.Context, conn net.Conn, value byte) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return writeAll(conn, []byte{value})
}

func readContextFrame(ctx context.Context, conn net.Conn) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > maxFrameSize {
		return nil, errors.New("kprop: frame too large")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readContextByte(ctx context.Context, conn net.Conn) (byte, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	var value [1]byte
	if _, err := io.ReadFull(conn, value[:]); err != nil {
		return 0, err
	}
	return value[0], nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func checkError(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var msg protocol.KRBError
	if err := asn1.Unmarshal(data, &msg); err != nil || msg.MsgType != 30 {
		return nil
	}
	text := ""
	if msg.EText != nil {
		text = strings.TrimSuffix(*msg.EText, "\x00")
	}
	return fmt.Errorf("%w (%d): %s", ErrRemote, msg.ErrorCode, text)
}

func encodeDatabaseSize(size uint64) []byte {
	if size > 0 && size <= math.MaxUint32 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(size))
		return b[:]
	}
	var b [12]byte
	binary.BigEndian.PutUint64(b[4:], size)
	return b[:]
}

func decodeDatabaseSize(data []byte) (uint64, uint32, error) {
	if len(data) != 4 && len(data) != 12 {
		return 0, 0, errors.New("kprop: invalid database-size length")
	}
	if len(data) == 4 {
		return uint64(binary.BigEndian.Uint32(data)), 0, nil
	}
	if binary.BigEndian.Uint32(data[:4]) != 0 {
		return 0, 0, errors.New("kprop: invalid extended database-size prefix")
	}
	size := binary.BigEndian.Uint64(data[4:])
	if size > 0 && size <= math.MaxUint32 {
		return 0, 0, errors.New("kprop: noncanonical extended database size")
	}
	return size, 0, nil
}

func hostAddress(addr net.Addr) protocol.HostAddress {
	if addr == nil {
		return protocol.HostAddress{}
	}
	var ip net.IP
	switch value := addr.(type) {
	case *net.TCPAddr:
		ip = value.IP
	case *net.UDPAddr:
		ip = value.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			ip = net.ParseIP(host)
		}
	}
	if ip4 := ip.To4(); ip4 != nil {
		return protocol.HostAddress{AddrType: 2, Address: append([]byte(nil), ip4...)}
	}
	if ip16 := ip.To16(); ip16 != nil {
		return protocol.HostAddress{AddrType: 24, Address: append([]byte(nil), ip16...)}
	}
	return protocol.HostAddress{}
}

func checksumType(id int32) int32 {
	switch id {
	case crypto.EnctypeAES128SHA1:
		return crypto.ChecksumHMACSHA196AES128
	case crypto.EnctypeAES256SHA1:
		return crypto.ChecksumHMACSHA196AES256
	case crypto.EnctypeAES128SHA256:
		return crypto.ChecksumHMACSHA256128AES128
	case crypto.EnctypeAES256SHA384:
		return crypto.ChecksumHMACSHA384192AES256
	default:
		return 0
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("kprop: nil context")
	}
	return ctx.Err()
}

func uint32Bytes(v *uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], *v)
	return b[:]
}

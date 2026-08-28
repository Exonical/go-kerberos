package kpasswd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	// RFC 3244 result codes, as defined by MIT's krb5_chpw_result_code_string.
	ResultSuccess       uint16 = 0
	ResultMalformed     uint16 = 1
	ResultHardError     uint16 = 2
	ResultAuthError     uint16 = 3
	ResultSoftError     uint16 = 4
	ResultAccessDenied  uint16 = 5
	ResultBadVersion    uint16 = 6
	ResultInitialNeeded uint16 = 7

	kpasswdAPErrModified = 41
)

// Server implements the RFC 3244 password-change service over UDP and TCP.
type Server struct {
	Realm     string
	DB        *kdb.Database
	ACL       func(client principal.Principal, operation string, target principal.Principal) bool
	Now       func() time.Time
	ErrorLog  func(error)
	MaxPacket int
}

// ListenAndServe serves password-change requests until ctx is cancelled or
// one of the supplied listeners fails. Either listener may be nil.
func (s *Server) ListenAndServe(ctx context.Context, udpConn net.PacketConn, tcpListener net.Listener) error {
	if ctx == nil {
		return fmt.Errorf("kpasswd server: nil context")
	}
	if s == nil || s.DB == nil || s.Realm == "" {
		return fmt.Errorf("kpasswd server: incomplete configuration")
	}
	if udpConn == nil && tcpListener == nil {
		return fmt.Errorf("kpasswd server: no listeners")
	}
	errCh := make(chan error, 2)
	if udpConn != nil {
		go s.serveUDP(ctx, udpConn, errCh)
	}
	if tcpListener != nil {
		go s.serveTCP(ctx, tcpListener, errCh)
	}
	select {
	case <-ctx.Done():
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
		return nil
	case err := <-errCh:
		if udpConn != nil {
			_ = udpConn.Close()
		}
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
		return err
	}
}

func (s *Server) serveUDP(ctx context.Context, conn net.PacketConn, errCh chan<- error) {
	max := s.maxPacket()
	buffer := make([]byte, max)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			errCh <- fmt.Errorf("kpasswd UDP read: %w", err)
			return
		}
		response := s.HandleMessage(buffer[:n])
		if len(response) == 0 {
			continue
		}
		if _, err := conn.WriteTo(response, addr); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("kpasswd UDP write: %w", err)
			return
		}
	}
}

func (s *Server) serveTCP(ctx context.Context, listener net.Listener, errCh chan<- error) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			errCh <- fmt.Errorf("kpasswd TCP accept: %w", err)
			return
		}
		go s.handleTCP(ctx, conn)
	}
}

func (s *Server) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	request, err := transport.ReadTCPFrame(conn, uint32(s.maxPacket()))
	if err != nil {
		return
	}
	response := s.HandleMessage(request)
	if len(response) == 0 {
		return
	}
	if err := transport.WriteTCPFrame(conn, response); err != nil && s.ErrorLog != nil {
		s.ErrorLog(fmt.Errorf("kpasswd TCP write: %w", err))
	}
}

func (s *Server) maxPacket() int {
	if s.MaxPacket > 0 && s.MaxPacket <= kpasswdMaxPacket {
		return s.MaxPacket
	}
	return kpasswdMaxPacket
}

// HandleMessage processes one RFC 3244 datagram payload.
func (s *Server) HandleMessage(request []byte) []byte {
	if s == nil {
		return nil
	}
	if s.DB == nil || s.Realm == "" {
		return s.errorReply(0, ResultHardError, "kpasswd server is not configured")
	}
	parsed, err := parsePasswordRequest(request)
	if err != nil {
		return s.errorReply(parsed.version, resultCode(err), err.Error())
	}
	verified, err := s.verifyRequest(parsed.apReq)
	if err != nil {
		s.logError(fmt.Errorf("kpasswd AP-REQ: %w", err))
		return s.errorReply(parsed.version, ResultAuthError, "Failed reading application request")
	}
	userData, err := s.decryptUserData(verified, parsed.priv)
	if err != nil {
		s.logError(fmt.Errorf("kpasswd KRB-PRIV: %w", err))
		return s.reply(verified, ResultHardError, "Failed decrypting request")
	}
	target, password, err := decodeRequestData(parsed.version, userData, verified.Client)
	if err != nil {
		return s.reply(verified, ResultMalformed, err.Error())
	}
	if verified.Flags&types.TicketInitial == 0 && principalEqual(target, verified.Client) {
		return s.reply(verified, ResultInitialNeeded, "Ticket must be derived from a password")
	}
	operation := "change-password"
	if parsed.version == setPasswordVersion {
		operation = "set-password"
	}
	if !s.authorized(verified.Client, operation, target) {
		return s.reply(verified, ResultAccessDenied, "Unauthorized request")
	}
	policy := (*kdb.PolicyRecord)(nil)
	record, ok, err := s.DB.Lookup(target)
	if err != nil || !ok {
		return s.reply(verified, ResultHardError, "Principal not found")
	}
	if record.Policy != "" {
		value, policyErr := s.DB.GetPolicy(record.Policy)
		if policyErr != nil {
			return s.reply(verified, ResultHardError, policyErr.Error())
		}
		policy = &value
	}
	bypassMinLife := operation == "set-password" && !principalEqual(target, verified.Client)
	err = s.DB.ChangePasswordWithPolicy(target, password, s.now(), policy, bypassMinLife)
	if err != nil {
		return s.reply(verified, policyResultCode(err), err.Error())
	}
	return s.reply(verified, ResultSuccess, "")
}

type passwordRequest struct {
	version uint16
	apReq   []byte
	priv    []byte
}

func parsePasswordRequest(data []byte) (passwordRequest, error) {
	var out passwordRequest
	if len(data) > kpasswdMaxPacket {
		return out, fmt.Errorf("Request exceeded maximum length")
	}
	if len(data) < 6 {
		return out, fmt.Errorf("Request was truncated")
	}
	if int(binary.BigEndian.Uint16(data[:2])) != len(data) {
		return out, fmt.Errorf("Request length was inconsistent")
	}
	out.version = binary.BigEndian.Uint16(data[2:4])
	if out.version != kpasswdVersion && out.version != setPasswordVersion {
		return out, fmt.Errorf("%w: %d", errBadVersion, out.version)
	}
	apLength := int(binary.BigEndian.Uint16(data[4:6]))
	if apLength == 0 || apLength > len(data)-6 {
		return out, fmt.Errorf("Request was truncated in AP-REQ")
	}
	out.apReq = append([]byte(nil), data[6:6+apLength]...)
	priv := data[6+apLength:]
	if len(priv) == 0 {
		return out, fmt.Errorf("Request was truncated in KRB-PRIV")
	}
	out.priv = append([]byte(nil), priv...)
	return out, nil
}

func (s *Server) decryptUserData(request *ap.VerifiedAPReq, data []byte) ([]byte, error) {
	key := request.SubKey
	if key == nil {
		key = &request.SessionKey
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	var priv protocol.KRBPriv
	if err := asn1.Unmarshal(data, &priv); err != nil {
		return nil, err
	}
	if priv.PVNO != 5 || priv.MsgType != 21 || priv.EncPart.EType != key.KeyType {
		return nil, fmt.Errorf("invalid KRB-PRIV")
	}
	plain, err := etype.Decrypt(key.KeyValue, kpasswdPrivUsage, priv.EncPart.Cipher)
	if err != nil {
		return nil, err
	}
	var part protocol.EncKRBPrivPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		return nil, err
	}
	if part.Timestamp != nil && part.Timestamp.Present {
		if !kpasswdWithinSkew(part.Timestamp.Time, s.now(), 5*time.Minute) {
			return nil, fmt.Errorf("invalid KRB-PRIV timestamp")
		}
	}
	return append([]byte(nil), part.UserData...), nil
}

func decodeRequestData(version uint16, data []byte, client principal.Principal) (principal.Principal, string, error) {
	if version == kpasswdVersion {
		if len(data) == 0 {
			return principal.Principal{}, "", fmt.Errorf("empty password")
		}
		return client, string(data), nil
	}
	var value protocol.ChangePasswdData
	if err := asn1.Unmarshal(data, &value); err != nil {
		return principal.Principal{}, "", fmt.Errorf("Failed decoding ChangePasswdData")
	}
	if len(value.NewPassword) == 0 {
		return principal.Principal{}, "", fmt.Errorf("empty password")
	}
	target := client
	if value.TargetName != nil {
		if len(value.TargetName.NameString) == 0 {
			return principal.Principal{}, "", fmt.Errorf("invalid target principal")
		}
		realm := client.Realm
		if value.TargetRealm != nil {
			realm = *value.TargetRealm
		}
		target = principal.Principal{
			Realm: realm, NameType: principal.NameType(value.TargetName.NameType),
			Components: append([]string(nil), value.TargetName.NameString...),
		}
	}
	return target, string(value.NewPassword), nil
}

func (s *Server) verifyRequest(data []byte) (*ap.VerifiedAPReq, error) {
	service := principal.Principal{
		Realm: s.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	}
	record, ok, err := s.DB.Lookup(service)
	if err != nil || !ok {
		return nil, fmt.Errorf("lookup changepw principal")
	}
	kt := &keytab.Keytab{}
	for enctype, key := range record.Keys {
		kt.Entries = append(kt.Entries, keytab.Entry{
			Principal: service, KVNO: key.KVNO, Enctype: enctype,
			Key: append([]byte(nil), key.Key...),
		})
	}
	return ap.VerifyAPReq(kt, data, s.now(), 5*time.Minute)
}

func (s *Server) authorized(client principal.Principal, operation string, target principal.Principal) bool {
	if principalEqual(client, target) &&
		(operation == "change-password" || operation == "set-password") {
		return true
	}
	return s.ACL != nil && s.ACL(client, operation, target)
}

func (s *Server) reply(request *ap.VerifiedAPReq, code uint16, message string) []byte {
	apRep, err := ap.BuildAPRep(request)
	if err != nil {
		return nil
	}
	key := request.SubKey
	if key == nil {
		key = &request.SessionKey
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil
	}
	userData := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(userData[:2], code)
	copy(userData[2:], message)
	now := s.now()
	timestamp := types.KerberosTime{Time: now, Present: true}
	seq := request.SeqNumber
	plain, err := asn1.Marshal(protocol.EncKRBPrivPart{
		UserData: userData, Timestamp: &timestamp, SeqNumber: seq,
		SAddress: protocol.HostAddress{},
	})
	if err != nil {
		return nil
	}
	cipher, err := etype.Encrypt(key.KeyValue, kpasswdPrivUsage, plain)
	if err != nil {
		return nil
	}
	priv, err := asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: key.KeyType, Cipher: cipher},
	})
	if err != nil {
		return nil
	}
	packet, err := buildPasswordPacket(kpasswdVersion, apRep, priv)
	if err != nil {
		return nil
	}
	return packet
}

func (s *Server) errorReply(version, code uint16, message string) []byte {
	now := s.now()
	realm := s.Realm
	name := protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"kadmin", "changepw"}}
	data := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(data[:2], code)
	copy(data[2:], message)
	reply, err := asn1.Marshal(protocol.KRBError{
		PVNO: 5, MsgType: 30, STime: types.KerberosTime{Time: now, Present: true},
		ErrorCode: kpasswdAPErrModified, Realm: realm, SName: name, EData: data,
	})
	if err != nil {
		return nil
	}
	return reply
}

func resultCode(err error) uint16 {
	if err == nil {
		return ResultSuccess
	}
	if errors.Is(err, errBadVersion) {
		return ResultBadVersion
	}
	return ResultMalformed
}

var errBadVersion = errors.New("bad password protocol version")

func policyResultCode(err error) uint16 {
	if errors.Is(err, kdb.ErrPasswordTooShort) ||
		errors.Is(err, kdb.ErrPasswordClasses) ||
		errors.Is(err, kdb.ErrPasswordTooSoon) ||
		errors.Is(err, kdb.ErrPasswordReuse) {
		return ResultSoftError
	}
	return ResultHardError
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) logError(err error) {
	if s.ErrorLog != nil {
		s.ErrorLog(err)
	}
}

func principalEqual(left, right principal.Principal) bool {
	if left.Realm != right.Realm || left.NameType != right.NameType ||
		len(left.Components) != len(right.Components) {
		return false
	}
	for i := range left.Components {
		if left.Components[i] != right.Components[i] {
			return false
		}
	}
	return true
}

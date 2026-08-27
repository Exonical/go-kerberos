// Package kdc implements a small in-memory Kerberos V5 KDC.
package kdc

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	paTGSReq              = 1
	paEncTimestamp        = 2
	kdcErrCPrincipal      = 6
	kdcErrSPrincipal      = 7
	kdcErrPreauthFailed   = 24
	kdcErrPreauthRequired = 25
	kdcErrGeneric         = 60
	krbAPErrBadIntegrity  = 31
	krbAPErrSkew          = 37
	krbAPErrInKeyUsage    = 44
)

// Server is an in-memory Kerberos KDC.
type Server struct {
	Realm            string
	DB               kdb.Store
	Now              func() time.Time
	ClockSkew        time.Duration
	MaxTicketLife    time.Duration
	MaxRenewableLife time.Duration
}

// HandleMessage handles one DER-encoded AS-REQ or TGS-REQ.
func (s *Server) HandleMessage(data []byte) []byte {
	if s == nil || s.DB == nil || s.Realm == "" {
		return s.errorResponse(kdcErrGeneric, nil)
	}
	if len(data) == 0 {
		return s.errorResponse(kdcErrGeneric, nil)
	}
	switch data[0] {
	case 0x6a:
		var request protocol.ASReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return s.errorResponse(kdcErrGeneric, nil)
		}
		return s.handleASReq(request)
	case 0x6c:
		var request protocol.TGSReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return s.errorResponse(kdcErrGeneric, nil)
		}
		return s.handleTGSReq(request, data)
	default:
		return s.errorResponse(kdcErrGeneric, nil)
	}
}

// ListenAndServe serves Kerberos requests on the supplied UDP and TCP
// endpoints until ctx is canceled or either listener fails.
func (s *Server) ListenAndServe(ctx context.Context, udpConn net.PacketConn, tcpListener net.Listener) error {
	if s == nil {
		return fmt.Errorf("KDC listen: nil server")
	}
	if ctx == nil {
		return fmt.Errorf("KDC listen: nil context")
	}
	if udpConn == nil || tcpListener == nil {
		return fmt.Errorf("KDC listen: nil listener")
	}
	errs := make(chan error, 2)
	go func() { errs <- s.serveUDP(udpConn) }()
	go func() { errs <- s.serveTCP(tcpListener) }()
	select {
	case <-ctx.Done():
		_ = udpConn.Close()
		_ = tcpListener.Close()
		return nil
	case err := <-errs:
		_ = udpConn.Close()
		_ = tcpListener.Close()
		return err
	}
}

func (s *Server) serveUDP(conn net.PacketConn) error {
	buffer := make([]byte, transport.DefaultMaxFrameSize)
	for {
		n, address, err := conn.ReadFrom(buffer)
		if err != nil {
			if isClosedNetworkError(err) {
				return nil
			}
			return fmt.Errorf("KDC UDP read: %w", err)
		}
		response := s.HandleMessage(buffer[:n])
		if _, err := conn.WriteTo(response, address); err != nil {
			if isClosedNetworkError(err) {
				return nil
			}
			return fmt.Errorf("KDC UDP write: %w", err)
		}
	}
}

func (s *Server) serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedNetworkError(err) {
				return nil
			}
			return fmt.Errorf("KDC TCP accept: %w", err)
		}
		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	request, err := transport.ReadTCPFrame(conn, transport.DefaultMaxFrameSize)
	if err != nil {
		return
	}
	_ = transport.WriteTCPFrame(conn, s.HandleMessage(request))
}

func (s *Server) handleASReq(request protocol.ASReq) []byte {
	if request.PVNO != 5 || request.MsgType != 10 ||
		request.ReqBody.CName == nil || request.ReqBody.SName == nil ||
		request.ReqBody.Realm == "" || request.ReqBody.SName.NameString == nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	clientName := principalFromProtocol(*request.ReqBody.CName, request.ReqBody.Realm)
	clientRecord, ok := s.DB.Lookup(clientName)
	if !ok {
		return s.errorResponse(kdcErrCPrincipal, request.ReqBody.SName)
	}
	serviceName := principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	serviceRecord, ok := s.DB.Lookup(serviceName)
	if !ok {
		return s.errorResponse(kdcErrSPrincipal, request.ReqBody.SName)
	}
	etypeID, clientKey, serviceKey, ok := s.selectASKeys(request.ReqBody.EType, clientRecord, serviceRecord)
	if !ok {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	timestampPA := findPA(request.PAData, paEncTimestamp)
	if timestampPA == nil {
		methodData := protocol.MethodData{
			{PADataType: paEncTimestamp, PADataValue: []byte{}},
			{
				PADataType: 19,
				PADataValue: marshalDER(protocol.ETypeInfo2{{
					EType: etypeID,
					Salt:  stringPointer(principalSalt(clientRecord, clientName)),
				}}),
			},
		}
		return s.errorResponseWithData(kdcErrPreauthRequired, request.ReqBody.SName, marshalDER(methodData))
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	timestampCipher := timestampPA.PADataValue
	var encrypted protocol.EncryptedData
	if err := asn1.Unmarshal(timestampPA.PADataValue, &encrypted); err == nil &&
		encrypted.EType == etypeID && len(encrypted.Cipher) > 0 {
		timestampCipher = encrypted.Cipher
	}
	timestampPlain, err := etype.Decrypt(clientKey.Key, 1, timestampCipher)
	if err != nil {
		return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
	}
	var timestamp preauth.EncTimestamp
	if err := asn1.Unmarshal(timestampPlain, &timestamp); err != nil ||
		!timestamp.PATimestamp.Present || !s.withinSkew(timestamp.PATimestamp.Time) {
		return s.errorResponse(krbAPErrSkew, request.ReqBody.SName)
	}
	return s.buildASRep(request, clientName, clientRecord, serviceName, serviceRecord, etypeID, clientKey, serviceKey)
}

func (s *Server) buildASRep(request protocol.ASReq, clientName principal.Principal, clientRecord kdb.PrincipalRecord, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, clientKey, serviceKey kdb.Key) []byte {
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	sessionValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, sessionValue); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	now := s.now().UTC().Truncate(time.Second)
	authTime := types.KerberosTime{Time: now, Present: true}
	startTime := authTime
	endTime := s.ticketEnd(request.ReqBody.Till, now)
	flags := types.TicketInitial | types.TicketPreAuthent
	if request.ReqBody.KDCOptions&types.KDCForwardable != 0 {
		flags |= types.TicketForwardable
	}
	if request.ReqBody.KDCOptions&types.KDCRenewableOK != 0 {
		flags |= types.TicketRenewable
	}
	ticketPart := protocol.EncTicketPart{
		Flags:    flags,
		Key:      protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		CRealm:   clientName.Realm,
		CName:    protocol.PrincipalName{NameType: int32(clientName.NameType), NameString: clientName.Components},
		AuthTime: authTime, StartTime: &startTime, EndTime: endTime,
	}
	ticketPlain := marshalDER(ticketPart)
	ticketCipher, err := encryptWithKey(serviceKey, 2, ticketPlain)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	ticketKVNO := serviceKey.KVNO
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: request.ReqBody.Realm,
		SName:   *request.ReqBody.SName,
		EncPart: protocol.EncryptedData{EType: etypeID, KVNO: &ticketKVNO, Cipher: ticketCipher},
	}
	lastReq := protocol.LastReq{{LRType: 0, LRValue: types.KerberosTime{Time: now, Present: true}}}
	part := protocol.EncASRepPart{
		Key:     protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		LastReq: lastReq, Nonce: request.ReqBody.Nonce, Flags: flags,
		AuthTime: authTime, StartTime: &startTime, EndTime: endTime,
		SRealm: request.ReqBody.Realm, SName: *request.ReqBody.SName,
	}
	replyPlain := marshalDER(part)
	replyCipher, err := encryptWithKey(clientKey, 3, replyPlain)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	reply := protocol.ASRep{
		PVNO: 5, MsgType: 11,
		CRealm:  clientName.Realm,
		CName:   *request.ReqBody.CName,
		Ticket:  ticket,
		EncPart: protocol.EncryptedData{EType: etypeID, Cipher: replyCipher},
	}
	return marshalDER(reply)
}

func (s *Server) handleTGSReq(request protocol.TGSReq, raw []byte) []byte {
	if request.PVNO != 5 || request.MsgType != 12 || len(request.PAData) == 0 ||
		request.ReqBody.SName == nil || request.ReqBody.Realm == "" {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	pa := findPA(request.PAData, paTGSReq)
	if pa == nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	var apRequest protocol.APReq
	if err := asn1.Unmarshal(pa.PADataValue, &apRequest); err != nil ||
		apRequest.PVNO != 5 || apRequest.MsgType != 14 {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	tgtName := principal.Principal{
		Realm: apRequest.Ticket.Realm, NameType: principal.NTSrvInstance,
		Components: apRequest.Ticket.SName.NameString,
	}
	tgtRecord, ok := s.DB.Lookup(tgtName)
	if !ok {
		return s.errorResponse(kdcErrSPrincipal, request.ReqBody.SName)
	}
	ticketKey, ok := selectKVNO(tgtRecord, apRequest.Ticket.EncPart.EType, apRequest.Ticket.EncPart.KVNO)
	if !ok {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	ticketEType, err := crypto.NewRegistry().Get(ticketKey.Enctype)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	ticketPlain, err := ticketEType.Decrypt(ticketKey.Key, 2, apRequest.Ticket.EncPart.Cipher)
	if err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	var ticketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(ticketPlain, &ticketPart); err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	sessionEType, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	authPlain, err := sessionEType.Decrypt(ticketPart.Key.KeyValue, 7, apRequest.Authenticator.Cipher)
	if err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	var authenticator protocol.Authenticator
	if err := asn1.Unmarshal(authPlain, &authenticator); err != nil ||
		authenticator.AuthenticatorVNO != 5 ||
		authenticator.CRealm != ticketPart.CRealm ||
		!sameProtocolPrincipal(authenticator.CName, ticketPart.CName) {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	if !s.withinSkew(authenticator.Ctime.Time) {
		return s.errorResponse(krbAPErrSkew, request.ReqBody.SName)
	}
	if authenticator.Checksum == nil ||
		authenticator.Checksum.ChecksumType != mandatoryChecksumType(ticketPart.Key.KeyType) {
		return s.errorResponse(krbAPErrInKeyUsage, request.ReqBody.SName)
	}
	body, err := asn1.FieldContent(raw, protocol.TagTGSReq, 4)
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	if err := sessionEType.VerifyChecksum(ticketPart.Key.KeyValue, 6, body, authenticator.Checksum.Checksum); err != nil {
		return s.errorResponse(krbAPErrBadIntegrity, request.ReqBody.SName)
	}
	serviceName := principalFromProtocol(*request.ReqBody.SName, request.ReqBody.Realm)
	serviceRecord, ok := s.DB.Lookup(serviceName)
	if !ok {
		return s.errorResponse(kdcErrSPrincipal, request.ReqBody.SName)
	}
	etypeID, serviceKey, ok := selectServiceKey(request.ReqBody.EType, serviceRecord)
	if !ok {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	replyKey := ticketPart.Key
	replyUsage := uint32(8)
	if authenticator.SubKey != nil {
		replyKey = *authenticator.SubKey
		replyUsage = 9
	}
	return s.buildTGSRep(request, ticketPart, serviceName, serviceRecord, etypeID, serviceKey, replyKey, replyUsage)
}

func (s *Server) buildTGSRep(request protocol.TGSReq, ticketPart protocol.EncTicketPart, serviceName principal.Principal, serviceRecord kdb.PrincipalRecord, etypeID int32, serviceKey kdb.Key, replyKey protocol.EncryptionKey, replyUsage uint32) []byte {
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return s.errorResponse(14, request.ReqBody.SName)
	}
	sessionValue := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(crypto.RandomSource, sessionValue); err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	now := s.now().UTC().Truncate(time.Second)
	authTime := ticketPart.AuthTime
	if !authTime.Present {
		authTime = types.KerberosTime{Time: now, Present: true}
	}
	endTime := s.ticketEnd(request.ReqBody.Till, now)
	flags := ticketPart.Flags
	ticketPart = protocol.EncTicketPart{
		Flags:  flags,
		Key:    protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		CRealm: ticketPart.CRealm, CName: ticketPart.CName,
		AuthTime: authTime, EndTime: endTime,
	}
	ticketCipher, err := encryptWithKey(serviceKey, 2, marshalDER(ticketPart))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	ticketKVNO := serviceKey.KVNO
	ticket := protocol.Ticket{
		TktVNO: 5, Realm: serviceName.Realm, SName: *request.ReqBody.SName,
		EncPart: protocol.EncryptedData{EType: etypeID, KVNO: &ticketKVNO, Cipher: ticketCipher},
	}
	part := protocol.EncTGSRepPart{
		Key:     protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionValue},
		LastReq: protocol.LastReq{{LRType: 0, LRValue: types.KerberosTime{Time: now, Present: true}}},
		Nonce:   request.ReqBody.Nonce, Flags: flags, AuthTime: authTime,
		EndTime: endTime, SRealm: serviceName.Realm, SName: *request.ReqBody.SName,
	}
	replyCipher, err := encryptWithKey(kdb.Key{Enctype: replyKey.KeyType, KVNO: 0, Key: replyKey.KeyValue}, replyUsage, marshalDER(part))
	if err != nil {
		return s.errorResponse(kdcErrGeneric, request.ReqBody.SName)
	}
	reply := protocol.TGSRep{
		PVNO: 5, MsgType: 13, CRealm: ticketPart.CRealm, CName: ticketPart.CName,
		Ticket:  ticket,
		EncPart: protocol.EncryptedData{EType: replyKey.KeyType, Cipher: replyCipher},
	}
	return marshalDER(reply)
}

func (s *Server) selectASKeys(enctypes []int32, client, service kdb.PrincipalRecord) (int32, kdb.Key, kdb.Key, bool) {
	for _, enctype := range enctypes {
		clientKey, clientOK := client.Keys[enctype]
		serviceKey, serviceOK := service.Keys[enctype]
		if clientOK && serviceOK {
			clientKey.Enctype = enctype
			serviceKey.Enctype = enctype
			return enctype, clientKey, serviceKey, true
		}
	}
	return 0, kdb.Key{}, kdb.Key{}, false
}

func selectServiceKey(enctypes []int32, service kdb.PrincipalRecord) (int32, kdb.Key, bool) {
	for _, enctype := range enctypes {
		if key, ok := service.Keys[enctype]; ok {
			key.Enctype = enctype
			return enctype, key, true
		}
	}
	return 0, kdb.Key{}, false
}

func selectKVNO(record kdb.PrincipalRecord, enctype int32, kvno *uint32) (kdb.Key, bool) {
	key, ok := record.Keys[enctype]
	if !ok || (kvno != nil && key.KVNO != *kvno) {
		return kdb.Key{}, false
	}
	key.Enctype = enctype
	return key, true
}

func (s *Server) errorResponse(code int32, service *protocol.PrincipalName) []byte {
	return s.errorResponseWithData(code, service, nil)
}

func (s *Server) errorResponseWithData(code int32, service *protocol.PrincipalName, data []byte) []byte {
	now := s.now().UTC()
	if service == nil {
		service = &protocol.PrincipalName{NameType: int32(principal.NTSrvInstance), NameString: []string{"krbtgt", s.Realm}}
	}
	return marshalDER(protocol.KRBError{
		PVNO: 5, MsgType: 30,
		STime: types.KerberosTime{Time: now, Present: true}, Susec: int32(now.Nanosecond() / 1000),
		ErrorCode: code, Realm: s.Realm, SName: *service, EData: append([]byte(nil), data...),
	})
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) withinSkew(value time.Time) bool {
	skew := s.ClockSkew
	if skew < 0 {
		skew = -skew
	}
	if skew == 0 {
		skew = 5 * time.Minute
	}
	difference := value.Sub(s.now())
	if difference < 0 {
		difference = -difference
	}
	return difference <= skew
}

func (s *Server) ticketEnd(till types.KerberosTime, now time.Time) types.KerberosTime {
	lifetime := s.MaxTicketLife
	if lifetime <= 0 {
		lifetime = 10 * time.Hour
	}
	end := now.Add(lifetime)
	if till.Present && till.Time.Before(end) {
		end = till.Time
	}
	if end.Before(now) {
		end = now
	}
	return types.KerberosTime{Time: end.Truncate(time.Second), Present: true}
}

func findPA(data protocol.MethodData, kind int32) *protocol.PAData {
	for index := range data {
		if data[index].PADataType == kind {
			return &data[index]
		}
	}
	return nil
}

func principalFromProtocol(value protocol.PrincipalName, realm string) principal.Principal {
	return principal.Principal{Realm: realm, NameType: principal.NameType(value.NameType), Components: append([]string(nil), value.NameString...)}
}

func sameProtocolPrincipal(left, right protocol.PrincipalName) bool {
	if left.NameType != right.NameType || len(left.NameString) != len(right.NameString) {
		return false
	}
	for index := range left.NameString {
		if left.NameString[index] != right.NameString[index] {
			return false
		}
	}
	return true
}

func joinComponents(values []string) string {
	result := ""
	for _, value := range values {
		result += value
	}
	return result
}

func principalSalt(record kdb.PrincipalRecord, name principal.Principal) string {
	if record.Salt != "" {
		return record.Salt
	}
	return name.Realm + joinComponents(name.Components)
}

func stringPointer(value string) *string { return &value }

func mandatoryChecksumType(etype int32) int32 {
	switch etype {
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

func encryptWithKey(key kdb.Key, usage uint32, plaintext []byte) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		return nil, err
	}
	return etype.Encrypt(key.Key, usage, plaintext)
}

func marshalDER(value any) []byte {
	data, _ := asn1.Marshal(value)
	return data
}

func isClosedNetworkError(err error) bool {
	return err == net.ErrClosed || (err != nil && err.Error() == "use of closed network connection")
}

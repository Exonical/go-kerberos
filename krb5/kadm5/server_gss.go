package kadm5

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"

	"github.com/Exonical/go-kerberos/krb5/gssapi"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func (s *Server) handleGSS(_ net.Conn, call rpcCall, session *serverSession) ([]byte, *serverSession, error) {
	r := xdrReader{b: call.credential}
	version, err := r.u32()
	if err != nil || version != 1 {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	proc, err := r.u32()
	if err != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	seq, err := r.u32()
	if err != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	service, err := r.u32()
	if err != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	handle, err := r.opaque()
	if err != nil || r.done() != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if service != rpcsecGSSPrivacy && service != rpcsecGSSData {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	recordBody := call.body
	if len(recordBody) == 0 {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if proc == rpcsecGSSInit || proc == rpcsecGSSCont {
		if session == nil {
			if proc != rpcsecGSSInit || len(handle) != 0 {
				return rpcErrorReply(call.xid, 1), session, nil
			}
		} else if proc != rpcsecGSSCont || !bytesEqual(handle, session.handle) {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		bodyReader := xdrReader{b: recordBody}
		token, err := bodyReader.opaque()
		if err != nil || bodyReader.done() != nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		if proc == rpcsecGSSCont && session == nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		acceptor := gssapi.NewAcceptor(s.Keytab)
		var ctx *gssapi.Context
		var client principal.Principal
		var responseToken []byte
		if session == nil {
			ctx, client, responseToken, err = acceptor.AcceptWithPrincipal(token, nowUTC())
			if err != nil {
				return rpcErrorReply(call.xid, 1), nil, nil
			}
			servicePrincipal := ctx.TargetName()
			if !validKadmService(servicePrincipal, s.Database.GetRealm()) {
				return rpcErrorReply(call.xid, 1), nil, nil
			}
			handle = make([]byte, 16)
			if _, err := rand.Read(handle); err != nil {
				return nil, nil, err
			}
			session = &serverSession{ctx: ctx, client: client, initial: ctx.InitialTicket(), service: servicePrincipal, handle: handle, next: 1}
		} else {
			ctx, _, responseToken, err = acceptor.AcceptWithPrincipal(token, nowUTC())
			if err != nil {
				return rpcErrorReply(call.xid, 1), session, nil
			}
			session.ctx = ctx
		}
		// The client validates a MIC over the negotiated sequence window.
		window := uint32(0x7fffffff)
		verifier, err := session.ctx.MIC(seqBytes(window))
		if err != nil {
			return nil, nil, err
		}
		body := xdrWriter{}
		body.opaque(session.handle)
		body.u32(0)
		body.u32(0)
		body.u32(window)
		body.opaque(responseToken)
		return rpcReply(call.xid, rpcsecGSS, verifier, body.bytes()), session, nil
	}
	if session == nil || !bytesEqual(handle, session.handle) || proc != rpcsecGSSData {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if seq != session.next {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	protectedReader := xdrReader{b: recordBody}
	protected, err := protectedReader.opaque()
	if err != nil || protectedReader.done() != nil {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if len(protected) < 16 || len(call.verifier) < 16 {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	protectedSeq := binary.BigEndian.Uint64(protected[8:16])
	verifierSeq := binary.BigEndian.Uint64(call.verifier[8:16])
	if !session.gssSeqSet {
		if protectedSeq+1 == verifierSeq {
			session.ctx.SetReceiveSequence(protectedSeq)
		} else if verifierSeq+1 == protectedSeq {
			session.ctx.SetReceiveSequence(verifierSeq)
		} else {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		session.gssSeqSet = true
	}
	var plain []byte
	if protectedSeq+1 == verifierSeq {
		plain, err = session.ctx.Unwrap(protected)
		if err == nil {
			err = session.ctx.VerifyMIC(call.prefix, call.verifier)
		}
		if err == nil && len(plain) < 4 {
			err = errors.New("kadm5: short GSS payload")
		}
		if err == nil && binary.BigEndian.Uint32(plain[:4]) != seq {
			err = errors.New("kadm5: bad sequence")
		}
		if err != nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
	} else if verifierSeq+1 == protectedSeq {
		if err := session.ctx.VerifyMIC(call.prefix, call.verifier); err != nil {
			return rpcErrorReply(call.xid, 1), session, nil
		}
		plain, err = session.ctx.Unwrap(protected)
		if err != nil || len(plain) < 4 || binary.BigEndian.Uint32(plain[:4]) != seq {
			return rpcErrorReply(call.xid, 1), session, nil
		}
	} else {
		return rpcErrorReply(call.xid, 1), session, nil
	}
	if !knownProcedure(call.proc) {
		return rpcErrorReply(call.xid, 3), session, nil
	}
	session.next++
	result := s.dispatch(session.client, session.service, call.proc, plain[4:], session.initial)
	replyPlain := append(seqBytes(seq), result...)
	var wrapped, replyVerifier []byte
	if verifierSeq+1 == protectedSeq {
		replyVerifier, err = session.ctx.MIC(seqBytes(seq))
		if err == nil {
			wrapped, err = session.ctx.Wrap(replyPlain, true)
		}
	} else {
		wrapped, err = session.ctx.Wrap(replyPlain, true)
		if err == nil {
			replyVerifier, err = session.ctx.MIC(seqBytes(seq))
		}
	}
	if err != nil {
		return nil, session, err
	}
	body := xdrWriter{}
	body.opaque(wrapped)
	return rpcReply(call.xid, rpcsecGSS, replyVerifier, body.bytes()), session, nil
}

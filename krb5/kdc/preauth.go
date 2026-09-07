package kdc

import (
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	PAHardware      = 0x00000004
	PARequired      = 0x00000008
	PASufficient    = 0x00000010
	PAReplacesKey   = 0x00000020
	PAPseudo        = 0x00000080
	PATypedEData    = 0x00000100
	PA_HARDWARE     = PAHardware
	PA_REQUIRED     = PARequired
	PA_SUFFICIENT   = PASufficient
	PA_REPLACES_KEY = PAReplacesKey
)

type PreauthRock struct {
	Client        principal.Principal
	Service       principal.Principal
	ClientEntry   *kdb.PrincipalRecord
	ClientDBEntry *kdb.PrincipalRecord
	ClientKeys    []kdb.Key
	Request       protocol.ASReq
	RequestBody   []byte
	ArmorKey      *protocol.EncryptionKey
	State         map[string]any
}

type VerifyResult struct {
	Authenticated         bool
	HardwareAuthenticated bool
	AuthIndicators        []string
	AuthorizationData     protocol.AuthorizationData
	ReplacedReplyKey      *kdb.Key
	PreauthType           string
}

// KDCPreauthModule authenticates AS-REQ preauthentication data. Modules that
// authenticate clients without a client key must advertise PA_REPLACES_KEY
// and return ReplacedReplyKey so the KDC can encrypt a decryptable reply.
type KDCPreauthModule interface {
	Name() string
	PATypes() []int32
	Flags(paType int32) int
	Edata(rock *PreauthRock, paType int32) (protocol.PAData, error)
	Verify(rock *PreauthRock, pa protocol.PAData) (*VerifyResult, error)
}

type ReturnPadata interface {
	ReturnPadata(rock *PreauthRock, result *VerifyResult) (protocol.MethodData, error)
}

func (s *Server) customPreauthRequired() bool {
	for _, module := range s.PreauthModules {
		if module == nil {
			continue
		}
		for _, paType := range module.PATypes() {
			if module.Flags(paType)&PARequired != 0 {
				return true
			}
		}
	}
	return false
}

func (s *Server) preauthModuleHints(rock *PreauthRock) protocol.MethodData {
	var result protocol.MethodData
	for _, module := range s.PreauthModules {
		if module == nil {
			continue
		}
		for _, paType := range module.PATypes() {
			if kdcBuiltinPAType(paType) || module.Flags(paType)&PAPseudo != 0 {
				continue
			}
			hint, err := module.Edata(rock, paType)
			if err == nil && hint.PADataType == paType {
				result = append(result, hint)
			}
		}
	}
	return result
}

type preauthModuleSuccess struct {
	module KDCPreauthModule
	paType int32
	result *VerifyResult
}

func (s *Server) verifyPreauthModules(rock *PreauthRock,
	data protocol.MethodData) (*VerifyResult, []preauthModuleSuccess, error) {
	var aggregate VerifyResult
	var successes []preauthModuleSuccess
	replaced := false
	for _, pa := range data {
		if kdcBuiltinPAType(pa.PADataType) {
			continue
		}
		for _, module := range s.PreauthModules {
			if module == nil || !claimsPAType(module.PATypes(), pa.PADataType) {
				continue
			}
			result, err := module.Verify(rock, pa)
			if err != nil {
				return nil, nil, err
			}
			if result != nil && result.Authenticated {
				flags := module.Flags(pa.PADataType)
				if flags&PAHardware != 0 {
					result.HardwareAuthenticated = true
				}
				if result.PreauthType == "" {
					result.PreauthType = module.Name()
				}
				if result.ReplacedReplyKey != nil {
					if flags&PAReplacesKey == 0 || replaced {
						return nil, nil, fmt.Errorf("preauth module %q supplied an invalid replacement reply key", module.Name())
					}
					replaced = true
				}
				if flags&PARequired != 0 {
					verified, _ := rock.State["verified-required-preauth"].(map[string]bool)
					if verified == nil {
						verified = make(map[string]bool)
						rock.State["verified-required-preauth"] = verified
					}
					verified[module.Name()] = true
				}
				if !aggregate.Authenticated {
					aggregate.PreauthType = result.PreauthType
				}
				aggregate.Authenticated = true
				aggregate.HardwareAuthenticated =
					aggregate.HardwareAuthenticated || result.HardwareAuthenticated
				aggregate.AuthIndicators = append(aggregate.AuthIndicators, result.AuthIndicators...)
				aggregate.AuthorizationData = append(aggregate.AuthorizationData, result.AuthorizationData...)
				if result.ReplacedReplyKey != nil {
					aggregate.ReplacedReplyKey = result.ReplacedReplyKey
				}
				successes = append(successes, preauthModuleSuccess{
					module: module, paType: pa.PADataType, result: result,
				})
			}
		}
	}
	if !aggregate.Authenticated {
		return nil, nil, nil
	}
	return &aggregate, successes, nil
}

func (s *Server) customPreauthFailure(rock *PreauthRock,
	request protocol.ASReq, armor *fastContext) []byte {
	if !s.customPreauthRequired() || rock == nil ||
		s.customPreauthSatisfied(rock) {
		return nil
	}
	if armor != nil {
		return s.fastErrorResponse(kdcErrPreauthFailed, request.ReqBody.SName,
			nil, request.ReqBody.Nonce, armor)
	}
	return s.errorResponse(kdcErrPreauthFailed, request.ReqBody.SName)
}

func (s *Server) customPreauthSatisfied(rock *PreauthRock) bool {
	if rock == nil {
		return false
	}
	verified, _ := rock.State["verified-required-preauth"].(map[string]bool)
	for _, module := range s.PreauthModules {
		if module == nil {
			continue
		}
		required := false
		for _, paType := range module.PATypes() {
			if module.Flags(paType)&PARequired != 0 {
				required = true
				break
			}
		}
		if required && (verified == nil || !verified[module.Name()]) {
			return false
		}
	}
	return true
}

func kdcBuiltinPAType(paType int32) bool {
	switch paType {
	case paEncTimestamp, paEncryptedChallenge, paSPAKE,
		otp.PADataRequest, protocol.PADataPKASReq:
		return true
	default:
		return false
	}
}

func claimsPAType(values []int32, typ int32) bool {
	for _, value := range values {
		if value == typ {
			return true
		}
	}
	return false
}

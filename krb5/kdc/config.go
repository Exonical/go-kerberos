package kdc

import (
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/config"
)

// ApplyKDCConf applies the server behavior represented by an MIT kdc.conf
// realm.  Settings without corresponding Server knobs remain available from
// config.KDCConfig and are deliberately not guessed at here.
func (s *Server) ApplyKDCConf(profile *config.KDCConfig, realm string) error {
	if s == nil {
		return fmt.Errorf("apply kdc.conf: nil server")
	}
	if profile == nil {
		return fmt.Errorf("apply kdc.conf: nil profile")
	}
	settings, ok := profile.Realm(realm)
	if !ok {
		return fmt.Errorf("apply kdc.conf: realm %q not found", realm)
	}
	if settings.MaxLife > 0 {
		s.MaxTicketLife = settings.MaxLife
	}
	if settings.MaxRenewableLife > 0 {
		s.MaxRenewableLife = settings.MaxRenewableLife
	}
	s.UDPPorts = append([]int(nil), settings.KDCPorts...)
	s.TCPPorts = append([]int(nil), settings.KDCTCPPorts...)
	s.EncryptedChallengeIndicator = settings.EncryptedChallengeIndicator
	s.SPAKEPreauthIndicators = append([]string(nil), settings.SPAKEPreauthIndicators...)
	s.PKINITIndicators = append([]string(nil), settings.PKINITIndicators...)
	s.OTPIndicators = append([]string(nil), settings.OTPIndicators...)
	return nil
}

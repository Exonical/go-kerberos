package kdc

import (
	"fmt"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestApplyKDCConf(t *testing.T) {
	profile, err := config.ParseKDCConf([]byte(`[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 89
    max_life = 10h
    reject_bad_transit = false
    host_based_services = host ldap
    no_host_referral = nfs
[realms]
    EXAMPLE.COM = {
    max_renewable_life = 2d
        encrypted_challenge_indicator = encrypted
        spake_preauth_indicator = password
        spake_preauth_indicator = hardware
        pkinit_indicator = pkinit
        pkinit_dh_min_bits = P-256
        otp_indicator = otp
        disable_pac = true
        restrict_anonymous_to_tgt = true
        host_based_services = ftp
        no_host_referral = ldap
    }
`))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	if err := server.ApplyKDCConf(profile, "example.com"); err != nil {
		t.Fatal(err)
	}
	if server.MaxTicketLife != 10*time.Hour || server.MaxRenewableLife != 48*time.Hour ||
		len(server.UDPPorts) != 1 || server.UDPPorts[0] != 88 ||
		len(server.TCPPorts) != 1 || server.TCPPorts[0] != 89 ||
		server.EncryptedChallengeIndicator != "encrypted" ||
		fmt.Sprint(server.SPAKEPreauthIndicators) != "[password hardware]" ||
		fmt.Sprint(server.PKINITIndicators) != "[pkinit]" ||
		server.PKINITDHMinBits != "P-256" ||
		fmt.Sprint(server.OTPIndicators) != "[otp]" ||
		!server.DisablePAC || !server.RestrictAnonymousToTGT ||
		server.RejectBadTransit ||
		fmt.Sprint(server.HostBasedServices) != "[host ldap ftp]" ||
		fmt.Sprint(server.NoHostReferral) != "[nfs ldap]" {
		t.Fatalf("server settings = %#v", server)
	}
}

func TestKDCConfigRelationRuntimeGates(t *testing.T) {
	server := &Server{
		Realm:             "EXAMPLE.COM",
		HostBasedServices: []string{"host", "ldap"},
		NoHostReferral:    []string{"ldap"},
	}
	host := principal.Principal{
		Realm: "OTHER.COM", NameType: principal.NTSrvHst,
		Components: []string{"host", "server.example"},
	}
	if !server.referralAllowed(host, true, false) {
		t.Fatal("host referral unexpectedly denied")
	}
	ldap := host
	ldap.Components = append([]string(nil), host.Components...)
	ldap.Components[0] = "ldap"
	if server.referralAllowed(ldap, true, false) {
		t.Fatal("no_host_referral did not suppress referral")
	}
	unknown := host
	unknown.Components = append([]string(nil), host.Components...)
	unknown.Components[0] = "ftp"
	unknown.NameType = principal.NTUnknown
	if server.referralAllowed(unknown, true, false) {
		t.Fatal("unlisted NT-UNKNOWN referral allowed")
	}
	caseVariant := unknown
	caseVariant.Components = append([]string(nil), unknown.Components...)
	caseVariant.Components[0] = "HOST"
	if server.referralAllowed(caseVariant, true, false) {
		t.Fatal("host referral matching was case-insensitive")
	}
	server.HostBasedServices = []string{"*"}
	if !server.referralAllowed(unknown, true, false) {
		t.Fatal("wildcard host referral denied")
	}
	if server.referralAllowed(host, false, false) ||
		server.referralAllowed(host, true, true) {
		t.Fatal("referral gate ignored request options")
	}
	if server.rejectBadTransit() {
		// The zero-value server preserves MIT's default.
	} else {
		t.Fatal("reject_bad_transit default disabled")
	}
	server.RejectBadTransit = false
	server.RejectBadTransitSet = true
	if server.rejectBadTransit() {
		t.Fatal("reject_bad_transit override ignored")
	}
}

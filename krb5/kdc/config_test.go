package kdc

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
)

func TestApplyKDCConf(t *testing.T) {
	profile, err := config.ParseKDCConf([]byte(`[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 89
    max_life = 10h
[realms]
    EXAMPLE.COM = {
        max_renewable_life = 2d
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
		len(server.TCPPorts) != 1 || server.TCPPorts[0] != 89 {
		t.Fatalf("server settings = %#v", server)
	}
}

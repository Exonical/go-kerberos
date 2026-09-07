package ccache

import (
	"errors"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMSLSAFileTimeConversion(t *testing.T) {
	const filetimeEpoch = int64(11644473600) * 10000000
	got := mslsaFileTimeToUnix(filetimeEpoch + 123*10000000)
	if got != 123 {
		t.Fatalf("FILETIME conversion = %d, want 123", got)
	}
}

func TestMSLSASessionKeyNull(t *testing.T) {
	for _, test := range []struct {
		name     string
		enctype  int32
		key      []byte
		expected bool
	}{
		{"null enctype", 0, []byte{1}, true},
		{"empty key", 18, nil, true},
		{"zero key", 18, []byte{0, 0}, true},
		{"real key", 18, []byte{0, 1}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mslsaSessionKeyNull(test.enctype, test.key); got != test.expected {
				t.Fatalf("null = %v, want %v", got, test.expected)
			}
		})
	}
}

func TestMSLSATicketConversion(t *testing.T) {
	client := mslsaName{Components: []string{"alice"}}
	service := mslsaName{Components: []string{"host", "server"}}
	ticket := mslsaTicketData{
		ClientName: client, ClientRealm: "EXAMPLE.COM",
		ServiceName: service, ServiceRealm: "EXAMPLE.COM",
		SessionKeyType: 18, SessionKey: []byte{1, 2, 3},
		TicketFlags:   0x50000000,
		StartTime:     int64(11644473600+100) * 10000000,
		EndTime:       int64(11644473600+200) * 10000000,
		RenewTime:     int64(11644473600+300) * 10000000,
		EncodedTicket: []byte{4, 5, 6},
	}
	credential, err := mslsaTicketCredential(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Client.String() != "alice@EXAMPLE.COM" ||
		credential.Server.String() != "host/server@EXAMPLE.COM" {
		t.Fatalf("principals = %s -> %s", credential.Client, credential.Server)
	}
	if credential.Enctype != 18 || credential.TicketFlags != ticket.TicketFlags {
		t.Fatalf("enctype/flags = %d/%#x", credential.Enctype, credential.TicketFlags)
	}
	if credential.StartTime != 100 || credential.EndTime != 200 || credential.RenewTill != 300 {
		t.Fatalf("times = %d/%d/%d", credential.StartTime, credential.EndTime, credential.RenewTill)
	}
	if string(credential.Key) != string(ticket.SessionKey) || string(credential.Ticket) != string(ticket.EncodedTicket) {
		t.Fatal("ticket or key was not copied")
	}
}

func TestMSLSACacheInfoConversion(t *testing.T) {
	info := mslsaCacheInfo{
		ClientName: "alice", ClientRealm: "EXAMPLE.COM",
		ServerName: "krbtgt/EXAMPLE.COM", ServerRealm: "EXAMPLE.COM",
		SessionKeyType: 18, TicketFlags: 0x40000000,
	}
	credential, err := mslsaCacheInfoCredential(info)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Client.String() != "alice@EXAMPLE.COM" ||
		credential.Server.String() != "krbtgt/EXAMPLE.COM@EXAMPLE.COM" ||
		credential.TicketFlags != info.TicketFlags {
		t.Fatalf("converted cache info = %#v", credential)
	}
}

func TestMSLSAMutationIsReadOnly(t *testing.T) {
	handle := &Handle{typ: TypeMSLSA, mslsa: &mslsaHandle{}}
	client, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	operations := []struct {
		name string
		call func() error
	}{
		{"initialize", func() error { return handle.Initialize(*client) }},
		{"write", func() error { return handle.Write(&Cache{}) }},
		{"store", func() error { return handle.Store(Credential{}) }},
		{"remove", func() error { return handle.Remove(Credential{}, 0) }},
		{"destroy", handle.Destroy},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.call()
			if !errors.Is(err, ErrMSLSAReadOnly) {
				t.Fatalf("error = %v, want %v", err, ErrMSLSAReadOnly)
			}
		})
	}
}

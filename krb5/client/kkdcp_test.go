package client

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestConfiguredHTTPSKDCUsesKKDCP(t *testing.T) {
	server := httptest.NewTLSServer(&kkdcp.Handler{
		Backend: func(_ context.Context, message []byte) ([]byte, error) {
			return message, nil
		},
	})
	defer server.Close()
	cfg := &config.Config{Realms: map[string][]string{"TEST.REALM": {server.URL}}}
	httpClient := server.Client()
	c := &Client{
		Config: cfg,
		KKDCP:  &kkdcp.Client{HTTPClient: httpClient},
	}
	got, err := c.roundTrip(context.Background(), "TEST.REALM", protocol.ASReq{PVNO: 5, MsgType: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("KKDCP returned empty message")
	}
}

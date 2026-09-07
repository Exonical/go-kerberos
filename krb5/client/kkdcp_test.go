package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestKKDCPOutcomeTracing(t *testing.T) {
	t.Run("exchange raw success", func(t *testing.T) {
		server := httptest.NewTLSServer(&kkdcp.Handler{
			Backend: func(_ context.Context, message []byte) ([]byte, error) {
				return message, nil
			},
		})
		defer server.Close()
		var messages []string
		c := &Client{
			Config: &config.Config{Realms: map[string][]string{"TEST.REALM": {server.URL}}},
			KKDCP:  &kkdcp.Client{HTTPClient: server.Client()},
			Trace: func(message string) {
				messages = append(messages, message)
			},
		}
		if _, err := c.ExchangeRaw(context.Background(), "TEST.REALM", []byte{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		assertKKDCPTrace(t, messages, "Sending HTTPS request to "+server.URL)
		assertKKDCPTrace(t, messages, "Received answer (3 bytes) from "+server.URL)
	})

	t.Run("round trip error", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusBadGateway)
		}))
		defer server.Close()
		var messages []string
		c := &Client{
			Config: &config.Config{Realms: map[string][]string{"TEST.REALM": {server.URL}}},
			KKDCP:  &kkdcp.Client{HTTPClient: server.Client()},
			Trace: func(message string) {
				messages = append(messages, message)
			},
		}
		if _, err := c.roundTrip(context.Background(), "TEST.REALM",
			protocol.ASReq{PVNO: 5, MsgType: 10}); err == nil {
			t.Fatal("roundTrip unexpectedly succeeded")
		}
		assertKKDCPTrace(t, messages, "Sending HTTPS request to "+server.URL)
		assertKKDCPTraceContains(t, messages, "KDC exchange error: ")
	})
}

func assertKKDCPTrace(t *testing.T, messages []string, want string) {
	t.Helper()
	for _, message := range messages {
		if message == want {
			return
		}
	}
	t.Fatalf("trace messages %v do not contain %q", messages, want)
}

func assertKKDCPTraceContains(t *testing.T, messages []string, want string) {
	t.Helper()
	for _, message := range messages {
		if strings.Contains(message, want) {
			return
		}
	}
	t.Fatalf("trace messages %v do not contain %q", messages, want)
}

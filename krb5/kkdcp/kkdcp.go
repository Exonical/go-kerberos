// Package kkdcp implements the Microsoft KDC Proxy Protocol.
package kkdcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/transport"
)

const (
	// ContentType is the media type used by MS-KKDCP.
	ContentType = "application/kerberos"
	// DefaultMaxMessageSize bounds both proxied Kerberos messages and HTTP
	// bodies. It is deliberately aligned with the existing TCP transport cap.
	DefaultMaxMessageSize = transport.DefaultMaxFrameSize
)

// Message is the DER KDC-PROXY-MESSAGE wrapper defined by MS-KKDCP.
type Message struct {
	KerbMessage   []byte  `krb5:"tag:0"`
	TargetDomain  *string `krb5:"tag:1,optional"`
	DCLocatorHint *int32  `krb5:"tag:2,optional"`
}

// Encode wraps a Kerberos message in a KDC-PROXY-MESSAGE. The wire payload
// includes the four-byte TCP-style length prefix required by MS-KKDCP.
func Encode(message []byte, targetDomain string) ([]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("KKDCP: empty Kerberos message")
	}
	if uint64(len(message)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("KKDCP: message is too large")
	}
	kerb := make([]byte, 4+len(message))
	binary.BigEndian.PutUint32(kerb, uint32(len(message)))
	copy(kerb[4:], message)
	value := Message{KerbMessage: kerb}
	if targetDomain != "" {
		value.TargetDomain = &targetDomain
	}
	return EncodeMessage(value)
}

// EncodeMessage DER-encodes a KDC-PROXY-MESSAGE. The KerbMessage field must
// contain its four-byte length prefix.
func EncodeMessage(value Message) ([]byte, error) {
	if len(value.KerbMessage) < 4 {
		return nil, fmt.Errorf("KKDCP: truncated Kerberos message")
	}
	length := binary.BigEndian.Uint32(value.KerbMessage[:4])
	if length == 0 || uint64(length) != uint64(len(value.KerbMessage)-4) {
		return nil, fmt.Errorf("KKDCP: invalid Kerberos message length")
	}
	return asn1.Marshal(value)
}

// Decode unwraps a KDC-PROXY-MESSAGE and returns the embedded Kerberos
// message and target domain.
func Decode(data []byte, max int) ([]byte, string, error) {
	if len(data) == 0 {
		return nil, "", fmt.Errorf("KKDCP: empty wrapper")
	}
	if max <= 0 {
		max = int(DefaultMaxMessageSize)
	}
	value, err := DecodeMessage(data)
	if err != nil {
		return nil, "", fmt.Errorf("KKDCP: decode wrapper: %w", err)
	}
	if len(value.KerbMessage) < 4 {
		return nil, "", fmt.Errorf("KKDCP: truncated Kerberos message")
	}
	length := binary.BigEndian.Uint32(value.KerbMessage[:4])
	if length == 0 || uint64(length) > uint64(max) ||
		int(length) != len(value.KerbMessage)-4 {
		return nil, "", fmt.Errorf("KKDCP: invalid Kerberos message length")
	}
	return append([]byte(nil), value.KerbMessage[4:]...), dereference(value.TargetDomain), nil
}

// DecodeMessage DER-decodes a KDC-PROXY-MESSAGE and validates its embedded
// four-byte length prefix.
func DecodeMessage(data []byte) (Message, error) {
	var value Message
	if err := asn1.Unmarshal(data, &value); err != nil {
		return Message{}, err
	}
	if len(value.KerbMessage) < 4 {
		return Message{}, fmt.Errorf("truncated Kerberos message")
	}
	length := binary.BigEndian.Uint32(value.KerbMessage[:4])
	if length == 0 || uint64(length) != uint64(len(value.KerbMessage)-4) {
		return Message{}, fmt.Errorf("invalid Kerberos message length")
	}
	return value, nil
}

// Handler forwards proxied Kerberos messages to Backend.
type Handler struct {
	Backend          func(context.Context, []byte) ([]byte, error)
	MaxMessageSize   int
	RequireTargetURL string
}

// ServeHTTP implements http.Handler for MS-KKDCP POST requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "KKDCP requires POST", http.StatusMethodNotAllowed)
		return
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != ContentType {
		http.Error(w, "KKDCP requires application/kerberos", http.StatusUnsupportedMediaType)
		return
	}
	if h == nil || h.Backend == nil {
		http.Error(w, "KKDCP backend unavailable", http.StatusServiceUnavailable)
		return
	}
	if h.RequireTargetURL != "" && r.URL.Path != h.RequireTargetURL {
		http.NotFound(w, r)
		return
	}
	max := h.MaxMessageSize
	if max <= 0 {
		max = int(DefaultMaxMessageSize)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+4096))
	if err != nil {
		http.Error(w, "KKDCP request read failed", http.StatusBadRequest)
		return
	}
	wrapper, err := DecodeMessage(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	message := append([]byte(nil), wrapper.KerbMessage[4:]...)
	response, err := h.Backend(r.Context(), message)
	if err != nil {
		http.Error(w, "KKDCP backend failed", http.StatusBadGateway)
		return
	}
	if len(response) == 0 || len(response) > max {
		http.Error(w, "KKDCP backend response is invalid", http.StatusBadGateway)
		return
	}
	responseKerb := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(responseKerb, uint32(len(response)))
	copy(responseKerb[4:], response)
	wrapper.KerbMessage = responseKerb
	responseDER, err := EncodeMessage(wrapper)
	if err != nil {
		http.Error(w, "KKDCP response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseDER)
}

// Client sends Kerberos requests to an HTTPS KDC proxy.
type Client struct {
	HTTPClient     *http.Client
	RootCAs        *x509.CertPool
	Dialer         transport.Dialer
	MaxMessageSize int
	Timeout        time.Duration
}

// Exchange sends message to endpoint, which must use the https scheme.
func (c *Client) Exchange(ctx context.Context, endpoint, realm string, message []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("KKDCP exchange: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("KKDCP exchange: %w", err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("KKDCP exchange: invalid HTTPS endpoint")
	}
	if message == nil || len(message) == 0 {
		return nil, fmt.Errorf("KKDCP exchange: empty Kerberos message")
	}
	max := c.maxMessageSize()
	if len(message) > max {
		return nil, fmt.Errorf("KKDCP exchange: message exceeds maximum")
	}
	body, err := Encode(message, realm)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("KKDCP exchange request: %w", err)
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)
	client := c.httpClient()
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("KKDCP exchange HTTP: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KKDCP exchange HTTP status %s", response.Status)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, int64(max)+4096))
	if err != nil {
		return nil, fmt.Errorf("KKDCP exchange response: %w", err)
	}
	result, _, err := Decode(responseBody, max)
	if err != nil {
		return nil, fmt.Errorf("KKDCP exchange response wrapper: %w", err)
	}
	return result, nil
}

func (c *Client) maxMessageSize() int {
	if c != nil && c.MaxMessageSize > 0 {
		return c.MaxMessageSize
	}
	return int(DefaultMaxMessageSize)
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c != nil && c.RootCAs != nil {
		tlsConfig.RootCAs = c.RootCAs
	}
	if c != nil && c.Dialer != nil {
		return &http.Client{Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext:     c.Dialer.DialContext,
		}, Timeout: c.Timeout}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   c.timeout(),
	}
}

func (c *Client) timeout() time.Duration {
	if c != nil {
		return c.Timeout
	}
	return 0
}

func dereference(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

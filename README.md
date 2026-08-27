# go-kerberos

`go-kerberos` is a pure Go implementation of the Kerberos V5 protocol
(RFC 4120) targeting wire, cryptographic, file-format, and behavioral
interoperability with MIT krb5. It uses no cgo, no `libkrb5`, and no external
Kerberos libraries — MIT binaries are used only as a differential oracle in
disposable integration test environments.

## Features

### Client
- **AS exchange** with PA-ENC-TIMESTAMP preauthentication (password-based
  `kinit` equivalent), including RFC 6113 **FAST** armored exchanges.
- **TGS exchange** for service tickets, with RFC 6806 **referral chasing**
  and canonicalization (loop detection, hop cap).
- **RFC 3244 password changes** against MIT `kadmind`, using AP-REQ and
  KRB-PRIV framing on the kpasswd service port.
- **AP exchange**: AP-REQ/AP-REP initiator and acceptor with mutual
  authentication, subkeys, sequence numbers, and a replay cache.
- **GSS-API Kerberos mechanism** (RFC 2743/4121): context establishment,
  mutual auth, Wrap (sealed and integrity-only), MIC, RRC rotation, strict
  sequence enforcement.

### KDC (server)
- In-memory KDC serving **AS and TGS** over UDP and TCP, verified live
  against real MIT `kinit`, `klist`, and `kvno` clients.
- RFC-correct key-usage handling (authenticator subkey → usage 9 replies,
  mandatory checksum-type enforcement, raw request-body checksum
  verification).

### Cryptography (RFC 3961/3962/8009)
- `aes128-cts-hmac-sha1-96` (17), `aes256-cts-hmac-sha1-96` (18),
  `aes128-cts-hmac-sha256-128` (19), `aes256-cts-hmac-sha384-192` (20).
- Verified against the published RFC test vectors. Deprecated enctypes
  (DES, 3DES, RC4; RFC 8429) are intentionally not implemented.

### Formats and configuration
- MIT **FILE keytab** (v2) reader/writer, byte-compatible with `ktutil`.
- MIT **FILE ccache** (v4) reader/writer, byte-compatible with `klist`.
- **krb5.conf** parsing, DNS SRV **KDC discovery**, UDP/TCP transport with
  response-too-big failover.

### CLIs
- `gokinit`, `goklist`, and `gokvno` — drop-in style equivalents of the MIT
  tools, interoperable with MIT ccaches and keytabs.

## Usage

```go
import (
    "context"
    "os"

    "github.com/Exonical/go-kerberos/krb5/client"
    "github.com/Exonical/go-kerberos/krb5/config"
    "github.com/Exonical/go-kerberos/krb5/principal"
)

data, err := os.ReadFile("/etc/krb5.conf")
if err != nil { /* ... */ }
cfg, err := config.Parse(data)
if err != nil { /* ... */ }

c := &client.Client{Config: cfg}
user, _ := principal.Parse("alice@EXAMPLE.COM")

tgt, err := c.ASExchange(context.Background(), *user, "password")
if err != nil { /* ... */ }

svc, _ := principal.Parse("host/service.example.com@EXAMPLE.COM")
creds, err := c.TGSExchange(context.Background(), tgt, *svc)
```

## Testing

Every feature is developed tests-first and gated on differential testing
against MIT krb5 (pinned at `krb5-1.22.2-final`):

```sh
go build ./... && go vet ./... && go test ./...

# Live MIT interoperability suite (requires MIT krb5 tools installed):
go test -tags integration ./integration/mit/ -count=1
```

The integration suite spins up hermetic disposable realms and verifies both
directions: Go artifacts consumed by MIT tools, MIT artifacts consumed by Go,
Go client against the MIT KDC, and MIT clients against the Go KDC.

See `docs/` for the architecture, standards coverage, MIT compatibility
notes, and the full test matrix.

## Roadmap

S4U (constrained delegation), PKINIT, KDC replay cache and renewals,
kdb persistence, server-side FAST, and RFC 3244 password changes are
implemented. The larger MIT kadm5 administrative RPC (ONC-RPC/GSS-RPC) is
not implemented; this project does not claim general kadmin RPC support.

Cross-realm TGS support currently covers direct single-hop trust. Configure
matching `krbtgt/TARGET@SOURCE` keys in both KDC stores; capaths and
transited-policy checking are intentionally out of scope.

## License

MIT — see [LICENSE](LICENSE). The project is completely open source; if you
use or redistribute the code, keep the Exonical copyright and license notice
intact as the license requires.

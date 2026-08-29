# go-kerberos

`go-kerberos` is a pure Go implementation of the Kerberos V5 protocol
(RFC 4120) targeting wire, cryptographic, file-format, and behavioral
interoperability with MIT krb5. It uses no cgo, no `libkrb5`, and no external
Kerberos libraries — MIT binaries are used only as a differential oracle in
disposable integration test environments.

## Features

### Client
- **AS exchange** with PA-ENC-TIMESTAMP preauthentication (password-based
  `kinit` equivalent), MIT-compatible PA-SPAKE (Edwards25519, P-256, P-384,
  and P-521), and
  RFC 6113 **FAST** armored exchanges.
- **TGS exchange** for service tickets, with RFC 6806 **referral chasing**
  and canonicalization (loop detection, hop cap).
- **RFC 3244 password changes** against MIT `kadmind`, using AP-REQ and
  KRB-PRIV framing on the kpasswd service port, including setting another
  principal's password with administrator credentials.
- **MIT kadm5 administrative RPC** over ONC-RPC/RFC 5531 record-marked TCP
  with RPCSEC_GSS privacy, covering API negotiation and principal
  create/get/modify/rename/delete/password-change/random-key operations,
  policy management, principal and policy listing, and privilege queries.
  The `kadm5.Server` counterpart accepts a `kadmin/admin` keytab, authenticates
  callers with the Go GSS acceptor, and applies a configurable ACL. Without an
  ACL, only the configured admin principal is authorized; an unset admin
  principal denies all operations. The Go client ↔ Go server round-trip covers
  the supported operation subset, and the live MIT gate covers `getprinc`,
  `addprinc`, `cpw`, `listprincs`, and `delprinc`. MIT `kadm5.acl` files can be
  parsed with `kadm5.LoadACL` and installed with `server.ACL = acl.Func()`;
  entries use MIT's ordered permissions, component wildcards, and target
  back-references. Restriction clauses are rejected because the server cannot
  apply field-level ACL restrictions.
- **MIT password policy and account lockout**: kadm5 cleartext password
  changes enforce minimum length, character classes, minimum lifetime,
  password history, and maximum lifetime. The KDC tracks preauthentication
  failures, failure intervals, temporary/permanent lockouts, and expired
  passwords. `kdb.Store` remains backward compatible; atomic lockout
  persistence is used when a store implements `kdb.LockoutRecorder`, with
  `kdb.LockoutUpdater` retained as a compatibility fallback.
- **RFC 3244 kpasswd server**: `kpasswd.Server` serves password changes and
  set-password requests over UDP and TCP, verifies `kadmin/changepw`
  AP-REQs, and applies the same policy and ACL controls as kadm5. Its UDP
  response lookaside cache replays identical retransmissions without applying
  a password change twice. Real MIT `kpasswd` interoperability is covered by
  the integration suite.
  AP-REQs, and applies the same policy and ACL controls as kadm5. Real MIT
  `kpasswd` interoperability is covered by the integration suite.
- **MIT incremental propagation**: `iprop.Server` serves authenticated
  `kiprop/<host>` RPCSEC_GSS update polling, and `iprop.Replica` applies
  committed principal snapshots to a Go KDB. The in-memory update log has
  configurable retention and MIT cursor/full-resync status semantics. The
  integration suite exercises a Go replica pulling `GET_UPDATES` from a real
  MIT `kadmind`, bootstrapping its cursor from an MIT ipropx dump header. The
  reverse `kpropd` gate runs against a real MIT 1.19 `kpropd -S` when the
  CI/runtime package is installed. The MIT kprop full-resync dump protocol is
  implemented in `krb5/kprop`, including chained AES KRB-PRIV transfer and
  load-before-ack handling.
- **PA-SPAKE**: the password AS path and Go KDC support padata type 151,
  Edwards25519 group 1 plus NIST P-256 (group 2), P-384 (group 3), and P-521
  (group 4), with MIT transcript/key derivation, SF-NONE, and
  stateless authenticated challenge cookies. The KDC can advertise the
  mechanism in its initial preauthentication hints, and the client handles
  MIT's `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` challenge round. Edwards25519
  remains the default for both client and KDC; groups can be configured for
  FIPS deployments. Live MIT client-to-Go KDC and Go client-to-MIT KDC gates
  cover both Edwards25519 and P-256; P-384/P-521 are covered by MIT vector
  goldens.
- **AP exchange**: AP-REQ/AP-REP initiator and acceptor with mutual
  authentication, subkeys, sequence numbers, and a replay cache.
- **GSS-API Kerberos mechanism** (RFC 2743/4121): context establishment,
  mutual auth, Wrap (sealed and integrity-only), MIC, RRC rotation, strict
  sequence enforcement.

### KDC (server)
- In-memory KDC serving **AS and TGS** over UDP and TCP, verified live
  against real MIT `kinit`, `klist`, and `kvno` clients.
- Optional principal aliases through `kdb.AliasResolver`. AS aliases require
  client canonicalization and return the canonical client name; TGS aliases
  echo the requested service name unless canonicalization is requested.
- KDC-side **S4U2Self**, **S4U2Proxy**, and forwarded-TGT handling, with an
  MIT-shaped `CheckAllowedToDelegate` hook for protocol transition and
  constrained delegation;
  MIT `kvno -U` and `kvno -P` interoperability is covered.
- Optional `Authorize` hook mirroring MIT's `kdcpolicy` plugin semantics for
  authenticated AS exchanges and validated TGS requests, including TGT gating
  and per-service policy checks; protocol-range KRB-ERROR codes are preserved,
  plain denials use `KDC_ERR_POLICY`, and FAST error wrapping is retained.
- MIT-style KDC operational hardening: complete-request lookaside replay
  caching for non-empty AS/TGS replies, including encoded KRB-ERROR replies,
  over UDP and TCP, concurrent UDP processing, configurable UDP reply-size
  fallback to `KRB_ERR_RESPONSE_TOO_BIG`, bounded UDP workers, one-minute TCP
  idle deadlines, and a default 45-connection TCP cap that evicts the oldest
  existing connection when exceeded.
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
- MIT **DIR** ccache collections (primary switching and subsidiary caches) and
  process-local **MEMORY** ccaches with collection resolution.
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

Principal aliases with MIT-compatible AS/TGS canonicalization, and S4U
(constrained delegation), including KDC-side protocol transition and
forwarded TGTs, PKINIT, KDC replay cache and renewals,
kdb persistence (including encrypted MIT version-7 dump export), server-side
FAST, RFC 3244 password changes and server-side kpasswd, and a focused
MIT kadm5 administrative RPC client and server subset are implemented. The
kadm5 client also
supports per-principal string attributes, principal-key extraction, and
API-v4 explicit key setting. General kadmin RPC coverage beyond the documented
operations remains out of scope.

PKINIT supports both certificate-backed RFC 4556 exchanges and anonymous
PKINIT (RFC 6112/8062). Anonymous exchanges use unsigned DH-only PKINIT; the
Go KDC requires the anonymous request option, issues an addressless ticket
with the anonymous flag, and interoperates with MIT `kinit -n` in both
directions. Ordinary PKINIT continues to require configured client trust
anchors.

MIT dump persistence supports Go-to-MIT export with `mitdump.Dump` or
`mitdump.Write`. Exports use the MIT `kdb5_util load_dump version 7` format,
include the encrypted `K/M@REALM` record, and encrypt principal key data with
AES master enctypes 17, 18, 19, or 20. The dump writer is covered by
decrypting round-trip tests and a live `kdb5_util load`/`kinit` integration
gate; the existing MIT-to-Go loader path remains supported as well. MIT dumps
can be loaded without a password using `mitdump.LoadWithStash`, which reads
modern FILE keytab-format `.k5.REALM` stashes and the legacy binary stash
format (with supported AES master enctypes). `mitdump.WriteStash` and
`mitdump.WriteStashFile` write keytab-format K/M stashes for those enctypes;
the stash reader and writer are covered by unit tests and a live MIT stash
loading gate.

PA-FOR-USER verification accepts the keyed checksum types supported by the
TGT session enctype, plus the RFC 4757 HMAC-MD5 checksum used by legacy
Windows clients; RC4 remains intentionally unavailable as a production
encryption type.

Cross-realm TGS support currently covers direct single-hop trust. Configure
matching `krbtgt/TARGET@SOURCE` keys in both KDC stores; capaths and
transited-policy checking are intentionally out of scope.

Password history is retained as derived key sets in the in-memory
`PrincipalRecord` and is never stored as cleartext. When `kadmin/history` is
present, MIT version-7 dumps encode that history in `KRB5_TL_KADM_DATA` with
historical keys encrypted under the history principal's key. Without that
principal, native history enforcement remains available but history cannot be
exported to MIT dumps. The RFC 3244 server accepts
MIT's request KRB-PRIV form even when its encrypted replay fields are absent;
AP-REQ replay and clock-skew checks remain enforced, while timestamp-bearing
KRB-PRIV requests are freshness-checked.

## License

MIT — see [LICENSE](LICENSE). The project is completely open source; if you
use or redistribute the code, keep the Exonical copyright and license notice
intact as the license requires.

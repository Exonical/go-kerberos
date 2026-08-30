# go-kerberos

`go-kerberos` is a pure Go implementation of the Kerberos V5 protocol
(RFC 4120) targeting wire, cryptographic, file-format, and behavioral
interoperability with MIT krb5. It uses no cgo, no `libkrb5`, and no external
Kerberos libraries — MIT binaries are used only as a differential oracle in
disposable integration test environments.

The crypto registry includes Camellia-128 and Camellia-256 CTS-CMAC enctypes
(25 and 26), grounded in RFC 3713 and RFC 6803. Their pure-Go block cipher,
CMAC, feedback-CMAC derivation, string-to-key, and Kerberos CTS implementations
are covered by RFC and MIT vectors.
When Go runs in FIPS 140 mode (`GODEBUG=fips140=on`), Camellia enctypes are
disabled as non-FIPS-approved algorithms regardless of configuration; AES
enctypes remain available. This is a RHEL-style policy for Go FIPS
deployments; upstream MIT krb5 does not apply this gate.

## Features

### Client
- **AS exchange** with PA-ENC-TIMESTAMP preauthentication (password-based
  `kinit` equivalent), MIT-compatible PA-SPAKE (Edwards25519, P-256, P-384,
  and P-521), and
  RFC 6113 **FAST** armored exchanges, including the RFC 6113
  PA-ENCRYPTED-CHALLENGE password factor. `Client.VerifyInitCreds` can verify
  newly acquired credentials against a service keytab by obtaining a service
  ticket and decrypting it with the keytab key, matching MIT's
  `krb5_verify_init_creds` behavior. Explicit service principals or the
  keytab's distinct principals are supported; missing keytabs are
  non-fatal by default and can be required with `NoFail`.
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
  authentication, subkeys, sequence numbers, and replay detection. The
  default acceptor cache is process-local; `ap.VerifyAPReqWithOptions` can
  select a persistent MIT-compatible `file2:` cache (or `none:`/`dfl:`).
  File2 stores use exclusive advisory locking and survive separate verifier
  processes; the MIT integration harness also verifies that Go detects an AP
  token recorded by an MIT `python3-gssapi` acceptor.
- **GSS-API Kerberos mechanism** (RFC 2743/4121): context establishment,
  mutual auth, Wrap (sealed and integrity-only), MIC, RRC rotation, strict
  sequence enforcement, typed IOV wrapping/unwrapping (HEADER, DATA, PADDING,
  TRAILER, SIGN_ONLY, and STREAM), RFC 4402 pseudo-random output, and credential delegation with RFC 4120 KRB-CRED
  forwarded-TGT credentials. Both encrypted (key usage 14) and legacy
  unencrypted KRB-CRED forms are accepted. Password-backed initiator,
  explicit/default keytab acceptor, and S4U impersonated credentials are
  supported; established contexts can be exported/imported with sequence
  state preserved, and version-1 lucid CFX state can be inspected.
- **IAKERB GSS mechanism** (MIT-compatible): proxy-token realm discovery,
  password/TGT/service-ticket initiation, KDC proxying, and IAKERB-FINISHED
  conversation integrity before the normal Kerberos GSS context. Delegation
  is rejected until IAKERB credential forwarding is implemented.
- **SPNEGO** (RFC 4178): Kerberos mechanism negotiation with the modern and
  Microsoft legacy Kerberos OIDs, mechListMIC exchange, and transparent
  Kerberos GSS Wrap/MIC access after establishment. Live MIT-backed gates cover
  Go and MIT initiators and acceptors.
- **MS-KKDCP**: HTTPS KDC Proxy Protocol client and `http.Handler` server,
  including strict DER wrapper and embedded TCP-length validation. Configure
  an HTTPS `kdc` entry and provide `client.Client.HTTPAnchors` (or a
  `kkdcp.Client` with a custom `x509.CertPool`) for private proxy CAs.

### KDC (server)
- In-memory KDC serving **AS and TGS** over UDP and TCP, verified live
  against real MIT `kinit`, `klist`, and `kvno` clients.
- RFC 4120 user-to-user authentication (`ENC-TKT-IN-SKEY`), including
  second-ticket validation, session-key-encrypted service tickets, and AP
  `USE-SESSION-KEY` acceptance.
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
- Heimdal/MIT-compatible **KCM** ccaches over Linux Unix-domain sockets,
  including cache replacement, retrieval, collection enumeration, KDC
  offsets, and the MIT `GET_CRED_LIST`/`REPLACE` extensions. The default
  socket is `/var/run/.heim_org.h5l.kcm-socket`; use `ResolveKCM` for an
  explicit socket, or pass `-` as the socket to disable KCM. `KCMServer`
  defaults to the unauthenticated shared namespace used by the MIT test
  daemon; set `IsolatePeers` to enable Linux `SO_PEERCRED` per-UID cache
  isolation. Isolated servers refuse connections when peer credentials are
  unavailable.
- **Local authorization and identity selection**: MIT-shaped
  `auth_to_local`/`auth_to_local_names` translation, `.k5login` authorization
  with `k5login_directory` and `k5login_authoritative`, and `.k5identity`
  service/host/realm matching for selecting a client principal from a ccache
  collection. The `Kuserok` convenience API accepts the parsed
  `*config.Config`; `.k5login` ownership must be verifiable as the target
  user or root before its entries are trusted.
- **krb5.conf** parsing, MIT-style `[domain_realm]` host mapping, injectable
  DNS TXT realm and URI/SRV **KDC discovery**, UDP/TCP transport with
  response-too-big failover, and HTTPS KDC Proxy routing for `kdc =
  https://host:port/path` entries.

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

PKINIT also implements RFC 8636 algorithm agility. Clients advertise the MIT
preference order SHA-256, SHA-1, and SHA-512 using KDF identifiers
`1.3.6.1.5.2.3.6.2`, `.1`, and `.3`; the KDC selects the first algorithm in
its preference order that the client supports. The RFC 8636 SP800-56A KDF
uses the encoded AS-REQ, PA-PK-AS-REP, and PKINIT principal context. If
`supportedKDFs` or `kdfID` is absent, both sides retain the RFC 4556
octet-string-to-key fallback for interoperability with legacy peers.

RFC 8070 PKINIT freshness tokens are supported by the Go client and KDC.
PKINIT clients advertise `PA-AS-FRESHNESS` (padata type 150), echo the
opaque token returned in `PREAUTH_REQUIRED` inside the signed
`PKAuthenticator.freshnessToken` field, and preserve anonymous DH-only
PKINIT behavior. Set `Server.PKINITRequireFreshness` to require a valid token;
the KDC uses a ten-minute, `krbtgt`-keyed token lifetime and returns
`KDC_ERR_PREAUTH_EXPIRED` for stale or invalid tokens.

RFC 6113 PA-ENCRYPTED-CHALLENGE (padata type 138) is supported as a
MIT-compatible FAST-only password factor. The Go client prefers it over
PA-ENC-TIMESTAMP when the KDC advertises it, derives the challenge key with
the FAST armor key, and verifies the KDC's usage-55 response challenge. The
KDC tries the client's available long-term keys with the
`clientchallengearmor` CF2 derivation, validates the timestamp, and returns
the advisory `kdcchallengearmor` response. KDC authentication indicators are
selected per request with `Server.EncryptedChallengeIndicator`,
`Server.SPAKEPreauthIndicators`, `Server.PKINITIndicators`, and
`Server.OTPIndicators`; ordinary encrypted-timestamp preauthentication does
not assert an indicator.

RFC 6560 OTP preauthentication is available through
`Client.ASExchangeFASTOTP`. The client accepts an OTP provider callback,
requires an RFC 6113 FAST armor TGT, and follows MIT's usage-45 encryption
of the challenge nonce with the FAST armor key. KDCs enable OTP by setting
`Server.OTPValidator` (and may provide challenge token metadata through
`Server.OTPTokenInfo`); OTP requests without FAST are rejected. The
integration suite covers both Go-client-to-MIT-KDC and MIT-client-to-Go-KDC
exchanges when MIT's `krb5-otp` plugin is installed.

MS-PAC container support is available in `krb5/pac`. PAC headers and aligned
`PAC_INFO_BUFFER` tables are parsed with strict bounds and overlap checks;
unknown buffers are preserved as opaque bytes. The package also provides
MS-DTYP SID parsing and binary encoding, UPN_DNS_INFO (type 12) generation
and parsing, and structured KERB_VALIDATION_INFO (type 1) NDR32
encoding/decoding. The package encodes client-info (type 10), server and KDC
checksums (types 6 and 7), and MIT's full PAC checksum (type 19), using
Kerberos application-data checksum usage 17. Ticket checksum type 16 can be
added after an encoded `EncTicketPart` is available. PAC authorization data
uses the nested AD-IF-RELEVANT/AD-WIN2K-PAC containers. KDC PAC issuance and
TGS re-signing are opt-in through `Server.EnablePAC` and the
`Server.GeneratePAC` opaque logon-info hook or the structured
`Server.GeneratePACIdentity` hook. S4U delegation-info (type 11) follows
MIT's NDR constructed-type layout and is updated during constrained
S4U2Proxy issuance; other TGS paths preserve it. Credentials-info (type 2)
follows MS-PAC 2.6.1: inner PAC_CREDENTIAL_DATA remains opaque, while the
optional `Server.GeneratePACCredentials` hook encrypts it with a replaced AS
reply key using key usage 16. The hook is not called for ordinary
password-key AS or TGS issuance. Acceptors can use
`pac.FromTicket` to extract and verify PAC signatures. Service tickets also
receive MIT's type-16 ticket checksum using the dummy-PAC encoding flow. Full
cross-implementation NDR validation and S4U-specific client-info policy are
intentionally outside this slice. The NDR codec follows the NDR32 common and
private headers, deferred pointers, RPC Unicode strings, group arrays, and
conditional SID arrays specified by MS-PAC sections 2.5, 2.6.1, 2.9, and
2.10.

GSS credential delegation uses the RFC 4121 `0x8003` checksum delegation
option and obtains a forwarded TGT with an addressless `KDCForwarded` TGS
request. Go-to-Go tests cover KRB-CRED marshal/read and delegated credential
exposure; the MIT integration suite covers a live `python3-gssapi`
delegation exchange against the Go acceptor and verifies the delegated TGT can
obtain another service ticket.

GSS channel bindings use the RFC 1964 little-endian encoding and MD5 digest in
the RFC 4121 `0x8003` authenticator checksum. Set
`gssapi.InitiatorOptions.ChannelBindings` or
`gssapi.AcceptorOptions.ChannelBindings` to bind a context to initiator and
acceptor addresses and application data. Matching non-zero bindings set
`GSS_C_CHANNEL_BOUND_FLAG`; absent or zero bindings retain MIT's tolerant
acceptor behavior. When the initiator requests the channel-bound flag, the
implementation also emits the MS-KILE `KERB_AP_OPTIONS_CBT` assertion in
authenticator authorization data; acceptors enforce matching bindings when
that assertion is present. SPNEGO and IAKERB propagate the option to their
Kerberos mechanism. The local test suite covers encoding, token placement,
matching, mismatch, and MIT-compatible absent/zero-binding cases, while the
MIT integration suite exercises both initiator and acceptor directions using
Python GSSAPI channel bindings.

GSS IOV operations are exposed by `Context.WrapIOV`, `Context.UnwrapIOV`, and
`Context.WrapIOVLength`.  Confidentiality and integrity-only CFX tokens use
the same RFC 4121 framing as the flat `Wrap` API; DATA buffers are distributed
across caller-supplied fragments, SIGN_ONLY buffers are authenticated without
being encrypted, and STREAM unwrap accepts a complete token in one buffer.
Nonzero RRC rotation and explicit DCE-style framing are supported; callers
must configure DCE mode on both sides when using that framing.  Length queries
only report required sizes and do not allocate or resize caller buffers.
RFC 4402 PRF output is available through
`Context.PseudoRandom` with `GSS_C_PRF_KEY_FULL` and
`GSS_C_PRF_KEY_PARTIAL`.  AES-SHA1, AES-SHA2, and enabled Camellia enctypes
use the existing RFC 3961/RFC 8009 crypto implementations.  `/usr/bin/python3`
with `python3-gssapi` exposes the raw IOV entry points
(`gssapi.raw.wrap_iov` and `gssapi.raw.unwrap_iov`); the Go integration harness
uses them when available.  The binding does not expose a raw PRF entry point,
so deterministic MIT PRF vectors provide the PRF gate.

RFC 7751 CAMMAC authorization data is available through the `krb5/cammac`
package. It encodes KDC and service verifiers with checksum key usage 64,
wraps protected elements in AD-IF-RELEVANT, and verifies service-protected
elements for AP acceptance. Successful preauthentication indicators are
carried in CAMMACs and propagated into derived TGS tickets. A principal's
`require_auth` string attribute is a space-separated any-match policy;
requests without a matching indicator fail with `KDC_ERR_POLICY` and the text
`Required auth indicators not present in ticket: <str>`. Malformed or tampered
CAMMACs are rejected rather than exposed as trusted authorization data.

MIT dump persistence supports Go-to-MIT export with `mitdump.Dump` or
`mitdump.Write`. Exports use the MIT `kdb5_util load_dump version 7` format,
include the encrypted `K/M@REALM` record, and encrypt principal key data with
AES or Camellia master enctypes. The dump writer is covered by
decrypting round-trip tests and a live `kdb5_util load`/`kinit` integration
gate; the existing MIT-to-Go loader path remains supported as well. MIT dumps
can be loaded without a password using `mitdump.LoadWithStash`, which reads
modern FILE keytab-format `.k5.REALM` stashes and the legacy binary stash
format (with supported AES and Camellia master enctypes). `mitdump.WriteStash` and
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

Realm discovery follows MIT's profile hostrealm order: exact host, then
progressively shorter suffixes with and without a leading dot. The optional
`_kerberos.<hostname>` TXT fallback is exposed through an injectable resolver
and is gated by `dns_lookup_realm`. URI KDC discovery parses MIT
`krb5srv:flags:udp|tcp|kkdcp:residual` records, honors priority, and runs
before SRV when URI lookup is enabled (the MIT default). The separate
`RealmForHostWithFallback` helper exposes MIT's upper-cased parent-domain
heuristic after profile lookup.

The `krb5/hostrealm` package mirrors MIT hostname expansion for host-based
service principals. `qualify_shortname` qualifies single-component names,
`dns_canonicalize_hostname` supports `true`, `false`, and `fallback`, and
`rdns` controls the optional reverse lookup after forward canonicalization.
Forward, reverse, TXT, and search-domain inputs are injectable for hermetic
tests; the default hostrealm module order is profile, DNS TXT, then the
upper-cased parent-domain/default-realm fallback.
In `fallback` mode, service-ticket operations first use the qualified,
non-DNS-canonicalized hostname and retry with forward canonicalization only
after `KDC_ERR_S_PRINCIPAL_UNKNOWN`. `realm_try_domains` controls injectable
KDC-realm probing (`-1` disables probing, while zero and positive values
bound the parent-label walk); an explicitly empty search-domain list disables
system resolver search domains.

`config.ParseKDCConf` parses profile-format `[kdcdefaults]` and `[realms]`
settings while retaining unsupported values for inspection, including the
authentication-indicator relations `encrypted_challenge_indicator`,
`spake_preauth_indicator`, `pkinit_indicator`, and `otp_indicator`.
`kdc.Server.ApplyKDCConf` applies supported lifetime and listener-port
settings plus these authentication-indicator settings without guessing at
other KDC policy.

KDC account expiration and disabled-principal state are enforced with MIT
error mappings (`KDC_ERR_NAME_EXP`, `KDC_ERR_KEY_EXP`,
`KDC_ERR_SERVICE_EXP`, and `KDC_ERR_CLIENT_REVOKED`). Per-principal
`MaxLife` and `MaxRenew` limits are applied together with the client,
service, and realm-wide ticket lifetime limits. RFC 6560 decimal OTP
format is represented by `otp.FormatDecimal`.

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

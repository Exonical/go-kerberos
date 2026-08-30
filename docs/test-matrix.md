# Client test matrix

All listed cells have RED test coverage. MIT-generated keytab and FILE ccache
fixtures are now checked in; parser assertions remain RED until their
implementations land. Packet captures are still deferred and skip explicitly
when absent.

Go FIPS 140 mode (`GODEBUG=fips140=on`) rejects Camellia enctypes 25 and 26
as non-FIPS-approved algorithms regardless of configuration, while retaining
AES support. This is a RHEL-style policy; upstream MIT krb5 has no equivalent
registry gate.

| Feature | Go client -> MIT KDC | MIT-generated fixture -> Go | Go-generated artifact -> MIT |
| --- | --- | --- | --- |
| Principal parsing | RED | RED | RED |
| ASN.1 | RED | RED | RED |
| AES128 SHA1 | RED | RED | RED |
| AES256 SHA1 | RED | RED | RED |
| AES128 SHA256 | RED | RED | RED |
| AES256 SHA384 | RED | RED | RED |
| Camellia128 CTS-CMAC (RFC 6803) | RFC 3713/RFC 6803 vectors; disabled in Go FIPS 140 mode | MIT client → Go KDC live gate; no MIT KDC reverse-direction gate is configured for this enctype | RFC 6803 string-to-key, derivation, CMAC, CTS, and round-trip vectors; FIPS registry rejection |
| Camellia256 CTS-CMAC (RFC 6803) | RFC 3713/RFC 6803 vectors; disabled in Go FIPS 140 mode | MIT client → Go KDC live gate passes; Go client → MIT KDC passes with a dedicated MIT fixture configured for `camellia256-cts` (MIT's alias for `camellia256-cts-cmac`) and a Camellia principal key | RFC 6803 string-to-key, derivation, CMAC, CTS, and round-trip vectors; FIPS registry rejection |
| keytab | RED | RED | RED |
| FILE ccache | Go reader/writer | MIT-generated cache parsed by Go | Go-generated cache read by MIT |
| DIR, MEMORY, and KCM ccache types | Go resolver, DIR primary/collection, MEMORY concurrency, and KCM v2 framing/server tests | MIT KCM test-server round trips and Go KCM server against MIT CLI where available | MIT KCM protocol operations, UUID fallback, default-cache ordering, and `GET_CRED_LIST`/`REPLACE` |
| Local authorization and identity selection | Go auth_to_local, .k5login, and .k5identity tests | No live MIT CLI gate exposes an2ln/kuserok; MIT source cases are ported locally | RULE/DEFAULT translation (including case-sensitive principal mappings), authoritative k5login fallback with verifiable user/root ownership, and service/host/realm identity matching |
| User-to-user authentication | Go client/KDC `ENC-TKT-IN-SKEY` issuance and AP `USE-SESSION-KEY` acceptance | `TestMITClientU2UAgainstGoKDC` uses MIT `kinit`, `kvno --u2u`, and `klist` against the Go KDC; MIT 1.22.2 behavior is the implementation oracle | Second-ticket validation, session-key ticket encryption, KVNO zero, and malformed-ticket rejection |
| AS exchange | RED | RED | RED |
| PA-SPAKE (Edwards25519, P-256, P-384, P-521) | Go client + Go KDC unit coverage; MIT vector goldens for all four groups | `TestMITClientSPAKEAgainstGoKDC`, `TestMITClientP256SPAKEAgainstGoKDC` (real MIT `kinit`, trace asserts SPAKE response) | `TestGoClientSPAKEAgainstMITKDC`, `TestGoClientP256SPAKEAgainstMITKDC` with MIT `spake_preauth_groups` configured |
| TGS exchange | RED | RED | RED |
| FAST-armored TGS exchange (RFC 6113) | Go unit + Go KDC | MIT `kvno` ordinary TGS path | Go unit |
| PA-ENCRYPTED-CHALLENGE (RFC 6113) | Go FAST AS client/KDC round trip, wrong-password and outside-FAST rejection | MIT `kinit -T` gate with KRB5_TRACE showing the type-138 challenge exchange (the factor is built into MIT libkrb5 rather than a separate plugin); existing Go FAST-to-MIT coverage exercises fallback when MIT does not advertise type 138 | Usage-54/55 CF2 crypto and response verification |
| KDC policy and ticket lifecycle | unit + MIT integration | unit coverage | MIT pass |
| Cross-realm TGS | unit + multi-hop coverage | unit coverage | unit coverage |
| KDB persistence (MIT dump and stash) | unit + golden | MIT pass (master enctypes 17/18/19/20); Go loads an MIT dump with the real `.k5.REALM` stash | Go dump -> MIT `kdb5_util load` + `kinit`; keytab-format stash round trip |
| AP exchange and persistent replay cache | Go AP-REQ/AP-REP tests; default in-memory replay detection; MIT-compatible file2 layout, SipHash seed, expiry, collision growth, and concurrent locking tests | `TestMITFile2ReplayCacheAgainstGo` uses MIT `python3-gssapi` as a Kerberos acceptor to populate a `file2:` cache, then verifies Go rejects the same AP token as a replay | Exact file2 record-layout golden, replay/expiry/wraparound, truncation, and same-tag race coverage |
| GSS credential delegation (RFC 4121 / KRB-CRED) | Go initiator and acceptor round trips, including encrypted usage-14 and plaintext compatibility | `TestMITGSSDelegationAgainstGo` uses live `python3-gssapi` delegation and verifies the forwarded TGT can obtain a service ticket | KRB-CRED golden DER, forwarded-TGT request construction, and delegated-context flag coverage |
| CAMMAC authorization data (RFC 7751) | Go KDC issuance and AP service-verifier acceptance | No live gate; the fixture does not configure MIT authentication indicators | CAMMAC golden DER, usage-64 KDC/service verification, protected-element extraction, and tamper rejection |
| SPNEGO (RFC 4178) over Kerberos GSS | Go unit coverage, including DER, legacy OID, and mechListMIC negotiation | `TestGoSPNEGOInitiatorAgainstMIT` (Python GSSAPI linked to MIT) | `TestMITSPNEGOInitiatorAgainstGo` (Python GSSAPI linked to MIT) |
| PKINIT (RFC 4556), RFC 8636 agility, and anonymous PKINIT (RFC 6112/8062) | client and Go KDC implemented; SHA-256, SHA-1, and SHA-512 KDF identifiers are advertised in MIT preference order | KDF vectors, wire goldens, Go↔Go, Go client ↔ MIT KDC, and MIT client ↔ Go KDC coverage; MIT trace asserts SHA-256 negotiation | MIT pass |
| PA-OTP (RFC 6560) | Go client + Go KDC FAST unit coverage | Go client ↔ MIT KDC with MIT OTP module and RADIUS stub; MIT `kinit` ↔ Go KDC | Both live directions pass when `krb5-otp` is installed |
| RFC 3244 kpasswd change/set-password | Go client + live MIT kadmind | MIT `kadmind` | Go client ↔ Go kpasswd server; MIT `kpasswd` ↔ Go kpasswd server |
| MIT kadm5 administrative RPC subset and `kadm5.acl` | Go client ↔ Go kadmind + live MIT `kadmind` | MIT `kadmind` and Go `kadm5.Server` | Go client ↔ Go server; MIT `kadmin` ↔ Go server, including ordered ACL grants/denials |
| MIT password policy and KDC account lockout | Go unit + live MIT `kadmin`/`kinit` | MIT policy semantics | Go kadmind policy checks; Go KDC lockout, expiration, and optional persistence |
| KDC aliases and canonicalization | Go client ↔ Go KDC + unit | MIT `kinit -C` client alias gate | Go client |
| KDC S4U2Self / S4U2Proxy / forwarded TGT | Go client ↔ Go KDC + unit | MIT `kvno` where supported | Go client |
| MIT iprop GET_UPDATES | Go replica → real MIT `kadmind` live gate; MIT 1.19 `kpropd -S` → Go master live gate; Go master ↔ Go replica unit coverage | MIT master gate bootstraps from a real `ipropx` dump header and verifies `addprinc` + `cpw`; reverse gate loads a Go-written ipropx dump into a disposable MIT replica, then verifies incremental Go-master add and password-change updates with `kadmin.local` | Full-resync dump transfer is implemented in `krb5/kprop`; live full-resync daemon gates require disposable MIT daemon orchestration and are tracked separately |
| MIT kprop full-resync dump transfer | Go `kprop.Send` ↔ Go `kprop.Server` unit/integration coverage; real MIT `kprop` → Go server; Go client → real MIT `kpropd` | MIT `kprop` sendauth/AP/Safe/Priv framing and chained AES transfer | Both live transfer gates pass with MIT 1.19 tooling; iprop full-resync callers use `Server.PushFullResync` and `Replica.KpropServer` |
| KDC lookaside and transport hardening | unit cache/transport tests; Go client UDP-too-big retry over TCP | MIT KDC interoperability suite | MIT client integration remains covered |
| MS-KKDCP HTTPS transport | Go client -> Go TLS proxy -> real MIT KDC (full AS + TGS) | DER wrapper and handler unit tests | MIT `kinit` -> Go TLS proxy -> real MIT KDC (skips when `k5tls` is unavailable) |

PA-ENCRYPTED-CHALLENGE support is FAST-only. Authentication indicators are
selected per successful preauthentication mechanism through the KDC's
`EncryptedChallengeIndicator`, `SPAKEPreauthIndicators`, `PKINITIndicators`,
and `OTPIndicators` fields; ordinary encrypted timestamp does not assert one.
The MIT encrypted-challenge implementation is built into libkrb5 rather than
provided as a separate preauthentication plugin. The live gate therefore runs
unconditionally and checks the type-138 challenge exchange in KRB5_TRACE.

The Go-to-MIT and MIT-to-Go KKDCP gates pass using a disposable TLS proxy and
a real MIT KDC. The reverse gate skips when the installed MIT runtime lacks
the `k5tls` plugin; Ubuntu provides it through the optional `krb5-k5tls`
package. MIT 1.22.2's source contains the HTTPS transport and TLS plugin path
used as the behavioral reference.

KCM uses Heimdal protocol version 2.0 over a Unix-domain stream. Requests and
replies use four-byte big-endian framing; names are NUL terminated, while
principals and credentials retain the v4 FILE ccache encoding. The client
enforces the 10 MiB reply limit, maps the Heimdal matching flags, retries
cached retrieval for older daemons, and falls back from the MIT
`GET_CRED_LIST` extension to UUID iteration. Linux does not implement the
optional Mach transport. The Go server is intentionally an in-memory daemon
for tests and local development; it does not provide persistent storage.
`KCMServer` defaults to the unauthenticated shared namespace matching
`kcmserver.py`. On Linux, setting `IsolatePeers` enables server-side
per-UID cache, UUID, default-cache, and offset isolation through
`SO_PEERCRED`; isolated servers reject connections without available Unix
peer credentials.

The KDC supports optional server-wide preauthentication disablement, default
ticket and renewable lifetimes for requests with omitted maximum `till` or
`rtime`, and optional forwardable/renewable/proxiable flag policy. A nil
policy preserves permissive issuance, including proxiable tickets when
requested; a non-nil policy clears disallowed flags, matching MIT's
`get_ticket_flags` behavior. MIT normally configures preauthentication and
flag restrictions per principal, while this implementation exposes
server-level knobs. Renewable, postdated, and validation behavior is covered
by unit and MIT integration tests. The optional `kdc.Server.Authorize` hook
mirrors MIT's `kdcpolicy` plugin interface semantics for authenticated AS
exchanges and validated TGS requests, preserving protocol-range KRB-ERROR
codes and returning FAST-armored policy errors when denied.

KDC UDP and TCP dispatches key the complete request packet in a bounded,
two-minute lookaside cache. Successful AS-REP and TGS-REP responses are
replayed verbatim, as are encoded protocol-error responses; an in-progress
duplicate is discarded. UDP replies above the configured
`MaxDatagramReplySize` are replaced with `KRB_ERR_RESPONSE_TOO_BIG`, allowing
the client transport to retry over TCP. UDP request handlers are bounded by
`MaxUDPWorkers` (default 1024) to provide backpressure. TCP connections use a
one-minute idle deadline and a default 45-connection cap. The pinned MIT sources verify
`MAX_DGRAM_SIZE` as 65536 bytes and `max_stream_data_connections` as 45;
the inspected `net-server.c` does not expose an explicit idle-timeout
constant, so the one-minute Go default follows the approved hardening design.
MIT evicts an existing least-recently-started stream when its cap is exceeded;
the Go listener follows the same newest-connection-preserving behavior.

MIT dump persistence decrypts database key data with AES and Camellia master-key
enctypes. Go version-7/r1.11 exports include
an encrypted `K/M@REALM` record and use the K/M salt from MIT's
`krb5_principal2salt` rule (`REALMKM`). Dump/parse round trips cover keys,
KVNOs, salts, flags, expirations, and lifetimes; `LoadWithStash` reads MIT's
modern keytab-format stash and its legacy binary fallback (legacy entries are
treated as KVNO 1). The integration gate loads a Go-generated dump with real
MIT `kdb5_util` and authenticates with `kinit`, and separately loads a real MIT
dump using the stash created by `kdb5_util create -s`. Go can write a
keytab-format K/M stash for the supported AES and Camellia master enctypes; interoperability
with MIT's stash writer is covered at the keytab byte-semantics level, while
the live gate covers MIT stash consumption by Go.

`DefaultRenewableLife` is an opt-in Go server default for renewable requests
without an explicit `rtime` (including the epoch maximum sentinel), followed
by the `MaxRenewableLife` cap. MIT's `kdc_get_ticket_renewtime` treats an
omitted `rtime` as infinity and applies `max_renewable_life`; the Go knob
provides a shorter default while retaining the same maximum cap. The default
also applies to `RENEWABLE-OK` requests whose `till` is omitted.

Cross-realm clients follow ordered `[capaths]` paths (up to ten hops), with
direct trust as the fallback. KDC tickets use RFC 4120
DOMAIN-X500-COMPRESS transited contents. KDC transited-policy checks follow
MIT's `krb5_check_transited_list`: a configured server capath replaces the
hierarchical path, and `.` permits only a direct path. Without a configured
capath, domain-style realms use the common-suffix hierarchy; X.500-style
`/` realms are accepted only through an explicit capath, matching MIT's
policy walker. Server-side capaths are supplied through `kdc.Server.Capaths`;
a full MIT policy-module configuration interface is not implemented.

FAST-armored TGS exchanges use the implicit RFC 6113 armor derived from the
PA-TGS-REQ authenticator subkey and TGT session key. The Go client and Go KDC
cover request unwrapping, strengthened replies, finished checksums, and
negative cases end to end. The MIT integration harness also confirms live
MIT `kvno` FAST-TGS interoperability: its trace contains
`Encoding request body and padata into FAST` and the resulting service ticket
is accepted by the Go KDC. MIT FAST AS interoperability remains covered by
`kinit -T`.

The PKINIT implementation supports the RFC 4556 Diffie-Hellman profile and
RFC 8636 algorithm agility on both the client and Go KDC. Clients advertise
KDF identifiers SHA-256 (`1.3.6.1.5.2.3.6.2`), SHA-1
(`1.3.6.1.5.2.3.6.1`), and SHA-512 (`1.3.6.1.5.2.3.6.3`) in that order.
The KDC selects the first identifier in its own preference order that appears
in the client list and includes it in `DHRepInfo`. The SP800-56A KDF binds
the DH secret to the algorithm identifier, client and KDC principals,
enctype, encoded AS-REQ, and encoded PA-PK-AS-REP. If either peer omits
`supportedKDFs` or `kdfID`, the RFC 4556 octet-string-to-key fallback remains
in use.

The KDC validates the client certificate chain,
the id-pkinit-KPClientAuth EKU, and the Kerberos principal SAN before signing
the DH reply and encrypting the AS-REP with the DH-derived reply key. Coverage
includes Go client ↔ Go KDC, Go client ↔ MIT KDC, and a live MIT
client ↔ Go KDC exchange when the system MIT client PKINIT plugin is
available; the latter's `KRB5_TRACE` records the SHA-256 KDF identifier.
The implementation currently uses the RFC 3526 MODP group 14 profile and
does not implement group 2 negotiation. The SHA-512 KDF is implemented, but
the MIT DES3 vector is not exercised because this repository does not expose
the MIT DES3 enctype profile.

Anonymous PKINIT follows RFC 6112/8062: the client sends unsigned DH-only
PKINIT, and the KDC accepts that form only with the anonymous request option.
Anonymous replies include the PKINIT KX padata required by MIT clients,
issue the canonical anonymous principal and anonymous ticket flag, and omit
client addresses. The integration suite covers MIT `kinit -n` against the Go
KDC and the Go anonymous client against a PKINIT-enabled MIT KDC.

RFC 8070 freshness coverage includes AuthPack field encoding and parsing,
Go client ↔ Go KDC success with `PKINITRequireFreshness`, missing-token
rejection with replacement method data, and stale/invalid-token rejection.
The token is the MIT-compatible opaque timestamp/KVNO/checksum format using
key usage 514 and a ten-minute lifetime. The live `TestMITClientPKINITAgainstGoKDC`
gate enables `PKINITRequireFreshness` on the Go KDC and exercises a real MIT
PKINIT client, including its freshness-token retry.

The client and server implement RFC 3244 password changes and set-password requests
against MIT `kadmind` on the kpasswd service port (464 by default; the isolated
integration harness uses a high, configured port because it runs without root
privileges). It sends an AP-REQ and KRB-PRIV request, verifies the AP-REP, and
decrypts the result code. Set-password requests encode RFC 3244
`ChangePasswdData` with the target principal and accept either version 1 or
0xff80 in the reply.
`kpasswd.Server` accepts both request versions over UDP and TCP, authenticates
the `kadmin/changepw` service, decrypts KRB-PRIV with the authenticator
subkey, enforces named password policies, and uses the same ACL callback as
the kadm5 server for administrative target changes. Real MIT `kpasswd`
integration covers successful self-service changes and visible policy
rejections; the Go client covers version-0xff80 set-password requests.
Because MIT `kadmind` enables sequence protection but does not request timestamp
protection on its reply KRB-PRIV, a reply must contain either a fresh timestamp
or a sequence number; replies containing neither are rejected.
The live integration gates cover both changing Alice's password directly and
an authorized admin setting Alice's password, followed by Go AS exchanges with
the resulting passwords. Password policy and authorization errors are returned
without exposing password material.

Kadmind and the RFC 3244 server enforce MIT-style minimum length and byte-oriented character classes,
minimum password lifetime for self-service changes, password history, and
maximum password lifetime. Administrator changes with modify privilege bypass
minimum lifetime. Password history is encoded in MIT `KRB5_TL_KADM_DATA` when
the database contains `kadmin/history`, with historical key data encrypted
using that principal's key. The live persistence suite covers MIT-to-Go and
Go-to-MIT history round trips. Without a history principal, the KDB retains
native history enforcement but cannot emit encrypted MIT history entries.
The RFC 3244 `kpasswd.Server` serves password changes and set-password requests
over UDP and TCP; the live integration suite covers the Go server with the MIT
`kpasswd` client. UDP requests are keyed by their complete packet bytes in a
bounded, two-minute lookaside cache, so retransmissions receive the original
response without repeating the password change; requests still in progress are
dropped silently.

The KDC applies named-policy lockout controls to PA-ENC-TIMESTAMP failures.
Failure counters reset after `FailureCountInterval`, accounts are permanently
or temporarily rejected with `KDC_ERR_CLIENT_REVOKED`, successful
preauthentication resets the counter and records `LastSuccess`, and expired
passwords return `KDC_ERR_KEY_EXP`. Lockout state uses atomic updates when the
configured store implements the optional `kdb.LockoutRecorder`, with the
legacy `kdb.LockoutUpdater` path retained for compatible stores; lookup-only
stores continue to operate without durable counters.

The Go client and `kadm5.Server` implement a focused MIT `kadm5`
administrative RPC subset over RFC 5531 record-marked TCP with RPCSEC_GSS
privacy and strict hand-written XDR. The server uses a `kadmin/admin` keytab
and the Go GSS acceptor for context establishment. Configure `Server.ACL` to
authorize callers by authenticated principal, operation, and target; MIT
`kadm5.acl` files are supported by `kadm5.ParseACL` and `kadm5.LoadACL`, with
first-match-wins evaluation, ordered lowercase grants and uppercase denies,
per-component `*` wildcards, and `*1` through `*9` target back-references.
Restriction clauses are rejected because this server does not expose
field-level mutation restrictions. When `Server.ACL` is nil, only
`Server.AdminPrincipal` is allowed, and an unset admin principal denies all
requests. Unknown procedures are rejected with RPC
`PROC_UNAVAIL`; malformed or truncated XDR is rejected.
API versions 4, 3, and 2 are negotiated against MIT `kadmind`; the live gate
covers principal create/get/modify/rename/delete/password-change,
`CHRAND_PRINCIPAL`, policy create/get/modify/delete, `GET_PRINCS`,
`GET_POLS`, and `GET_PRIVS`. It also covers `GET_STRINGS` (procedure 23),
`SET_STRING` (procedure 24), `SETKEY_PRINCIPAL4` (procedure 25), and
`EXTRACT_KEYS`/`GET_PRINCIPAL_KEYS` (procedure 26). These procedure numbers
are from MIT krb5 1.22.2's `kadm_rpc.h`; they supersede older or provisional
numbering. Explicit key setting uses API version 4, while string attributes
and key extraction use the negotiated API version. The Go client ↔ Go server
round-trip covers the supported server operations. The live MIT gate against
the Go server covers `getprinc`, `addprinc`, `cpw`, `listprincs`, and
`delprinc`. Key-data management beyond random-key and explicit API-v4 keys,
aliases, and other procedures remain out of scope. MIT's legacy
AUTH-GSSAPI flavor is retained only as a source-compatibility constant; the
modern MIT 1.22 daemon uses RPCSEC_GSS flavor 6.

## MS-PAC

`krb5/pac` covers strict MS-PAC header and `PAC_INFO_BUFFER` parsing,
eight-byte alignment, bounds and overlap rejection, unknown-buffer
preservation, client-info FILETIME/UTF-16LE encoding, and MIT application-data
checksum usage 17 for server, KDC, and full PAC signatures. The nested
AD-IF-RELEVANT/AD-WIN2K-PAC authorization-data form is covered by round-trip
tests. `Server.EnablePAC` enables Go KDC issuance and TGS re-signing, with
`Server.GeneratePAC` supplying opaque logon-info bytes or
`Server.GeneratePACIdentity` supplying structured KERB_VALIDATION_INFO and
UPN_DNS_INFO identity data. `krb5/pac` includes MS-DTYP SID parsing and
binary encoding, UPN_DNS_INFO (MS-PAC 2.10), and NDR32
KERB_VALIDATION_INFO (MS-PAC 2.5) marshal/unmarshal coverage. `pac.FromTicket`
extracts and verifies PACs for acceptors, including checksum-type matching
against the supplied keys. KDC service-ticket issuance also emits and
verifies the MIT type-16 ticket checksum using the dummy-PAC ticket encoding
flow. S4U_DELEGATION_INFO (type 11) uses MIT's NDR constructed-type layout;
the three AD-2019 captured MIT goldens are decoded and re-encoded
byte-for-byte. Constrained S4U2Proxy updates the delegation chain, while
ordinary TGS paths preserve the buffer. PAC_CREDENTIAL_INFO (type 2) has the
MS-PAC 2.6.1 version/enctype envelope and usage-16 AES encryption helpers;
the inner credential data remains opaque. `GeneratePACCredentials` is gated
on a replaced AS reply key and type 2 is preserved through TGS re-signing.

The MIT `t_pac.c` container layout is represented by parser and alignment
goldens; the installed Go crypto registry currently has AES enctypes but not
RC4-HMAC, so MIT's legacy RC4 signature vectors are parsed but cannot be
verified by the production checksum implementation. Cross-validation against
Samba/Windows NDR output and S4U-specific client-info substitution are not
implemented. Samba bindings, `samba-tool`, and `ndrdump` were unavailable in
the verification environment, so no independent NDR golden or Samba
cross-check was possible. The delegation goldens are MIT-source captures
rather than an additional Samba cross-check. The binary container,
SID/UPN_DNS_INFO offsets, NDR headers, delegation goldens, credentials
envelope, and KDC PAC issuance are covered in package and KDC tests.

The KDB `Store` interface remains compatible with Lookup-only stores.
Stores may additionally implement `kdb.AliasResolver` to resolve an alias
principal to its canonical record. The in-memory database exposes this through
`AddAlias`. For AS requests, an alias is accepted only when the
`KDCCanonicalize` option is set; the AS-REP and issued ticket then contain the
canonical client principal. Without that option the KDC returns
`KDC_ERR_C_PRINCIPAL_UNKNOWN`. For TGS requests, an alias service lookup is
allowed without canonicalization and the issued ticket echoes the requested
alias. With canonicalization, the ticket and encrypted reply carry the
canonical service principal. The Go client accepts the canonical TGS name when
canonicalization is enabled while retaining strict exact-name checks otherwise.
The installed MIT `kvno` in the integration environment does not expose a
`--canonicalize` option, so MIT coverage is limited to `kinit -C`; TGS alias
echo and canonicalization are covered by Go client/KDC tests.

The installed MIT `kvno` supports `-U` and `-P`; both FAST-armored S4U2Self
and S4U2Proxy requests pass against the Go KDC in
`TestMITClientS4U2SelfAgainstGoKDC`. The Go KDC accepts both
PA-S4U-X509-USER and legacy PA-FOR-USER protocol-transition requests.
PA-FOR-USER validates keyed AES checksums matching the TGT session enctype
and the RFC 4757 HMAC-MD5 compatibility checksum; this is defensive
verification only and does not add RC4. S4U2Self tickets are forwardable
only when `Server.CheckAllowedToDelegate` approves the requesting service.
The hook receives the impersonated user and target for S4U2Proxy, and nil
values for the S4U2Self general delegation query. S4U2Proxy requires a
single forwardable evidence ticket encrypted to that service and an allowed
target from the same hook. A nil hook permits non-forwardable S4U2Self but
denies S4U2Proxy with `KDC_ERR_BADOPTION`. Forwarded TGT requests require
a forwardable header TGT and set the FORWARDED ticket flag while honoring
requested addresses.

## RFC 6560 OTP preauthentication

The Go client and KDC implement MIT-compatible PA-OTP-CHALLENGE (141) and
PA-OTP-REQUEST (142) inside FAST. `Client.ASExchangeFASTOTP` obtains the
token value through a callback; `Server.OTPValidator` validates it and
`Server.OTPTokenInfo` can supply token metadata. The challenge nonce is
encrypted directly with the FAST armor key using key usage 45, matching
MIT krb5 1.22.2; no additional CF2/KDF is used for this request path.

The in-process Go KDC/client OTP exchange is covered by
`TestServerOTPFASTASExchange`. Live interoperability is covered in both
directions: `TestGoClientOTPAgainstMITKDC` uses the MIT OTP module with an
in-process UDP RADIUS acceptor, while `TestMITClientOTPAgainstGoKDC` uses
MIT `kinit` with a FAST armor ccache and the Go KDC hooks. These tests
require the Ubuntu `krb5-otp` package (the test remains conditional when
the plugin is unavailable). The Go KDC includes a FAST cookie in the
initial OTP challenge, as required by MIT's retry processing.

## Realm discovery and KDC configuration

Unit coverage exercises MIT profile `[domain_realm]` matching (exact host,
case-insensitive parent walking, leading-dot suffixes, and numeric-address
exclusion), the opt-in upper-cased parent-domain fallback,
`_kerberos.<host>` TXT fallback, and
`krb5srv:flags:transport:residual` URI parsing and priority ordering. DNS
tests use an injectable fake resolver rather than live DNS, so they are
deterministic in CI. URI lookup is attempted before SRV lookup by default;
callers can disable it to model `dns_uri_lookup = false`.

Host-based service principal expansion is covered by `krb5/hostrealm` unit
tests for `qualify_shortname`, DNS canonicalization modes, optional reverse
lookup, domain-realm parent walking, DNS TXT lookup ordering, fallback
realms, `realm_try_domains`, explicit RDNS defaults, and empty search-domain
overrides. DNS behavior uses injected resolvers and has no live-network
unit-test dependency. Client AS/TGS/U2U/FAST paths perform the MIT
fallback-mode retry after `KDC_ERR_S_PRINCIPAL_UNKNOWN`. The installed MIT
runtime does not expose a stable standalone `krb5_sname_to_principal` oracle,
so this slice has no live MIT gate.

`config.ParseKDCConf` is covered against generated MIT profile syntax,
including `[kdcdefaults]` inheritance into `[realms]`, port lists, ticket
lifetime values, master-key enctype, supported enctypes, authentication
indicator relations, and preservation of unknown realm settings.
`kdc.Server.ApplyKDCConf` is covered for listener ports, lifetime settings,
and authentication indicators that have direct Go server equivalents. The
integration harness uses the same profile-format KDC configuration with a
disposable MIT KDC; DNS itself is intentionally not a live integration
dependency.

## Testing layers

Each major subsystem will use several complementary layers:

1. **RFC vector tests** — official external vectors for PBKDF2,
   string-to-key, DK/DR, AES CTS, HMAC, key usage derivation, RFC 3962, and
   RFC 8009. Expected values never come from the implementation under test.
2. **Golden encoding tests** — deterministic Go structure ↔ exact DER bytes
   for canonical Kerberos encodings, including malformed ASN.1.
3. **Round-trip tests** — verify `decode(encode(x)) == x`, while recognizing
   that round trips alone cannot expose a shared encoder/decoder bug.
4. **Negative tests** — truncated and malformed input, invalid tags and
   lengths, missing or duplicate fields, invalid times and principals,
   unsupported enctypes, bad checksums, corrupt ciphertext, invalid lifetimes,
   clock skew, nonce mismatch, wrong identities, and malformed errors or
   padata.
5. **Fuzz tests** — native Go fuzz targets for principal, ASN.1, config,
   keytab, ccache, KRB-ERROR, AS-REP, TGS-REP, AP-REQ, and crypto decrypt
   operations. Fuzzing must not panic, hang, or allocate without bounds.
6. **MIT differential/interoperability tests** — disposable
   `TEST.GOKRB5.LOCAL` realms with dynamically generated config, KDC
   database, keytabs, and FILE ccaches. Tests must not depend on the
   developer's machine configuration.

The planned corpus will include valid MIT packets, valid RFC vectors,
truncated messages, and malformed historical regression cases. Each
regression receives a reproducer before its fix and remains permanently in
the suite.

## RFC 7751 CAMMAC authorization data

CAMMAC protocol golden tests cover the RFC 7751 elements and verifier-mac
structure. Go unit tests cover KDC/service checksum generation, protected
element extraction, KDC and service verification, and tamper rejection.
Successful preauthentication emits authentication indicators inside
AD-IF-RELEVANT/AD-CAMMAC with key usage 64. TGS issuance verifies and
propagates protected indicators from the header ticket, and AP acceptance
verifies the service verifier before exposing them. The per-principal
`require_auth` string attribute uses space-separated any-match semantics;
failure returns `KDC_ERR_POLICY` with
`Required auth indicators not present in ticket: <str>`. Anonymous PKINIT
does not assert PKINIT indicators. No live MIT indicator gate is enabled yet:
the fixture does not configure SPAKE indicators and `require_auth` together,
so a live test would not exercise this parity slice.

## IAKERB GSS mechanism

IAKERB proxy framing uses the MIT mechanism OID (`1.3.6.1.5.2.5`), proxy
token ID `0x0501`, strict DER IAKERB-HEADER encoding, opaque cookie echo, and
stepwise realm-discovery, AS, and TGS exchanges. The final AP-REQ is a normal
Kerberos GSS token and carries the MIT IAKERB-FINISHED extension, whose
conversation checksum uses key usage 41 and the authenticator subkey.

Unit coverage includes header and finished DER goldens, malformed framing,
conversation checksum tamper detection, cookie-preserving proxy tokens, and
existing-ticket AP handoff. The proxy uses the configured Go KDC transport.
IAKERB credential delegation is explicitly rejected because delegation is not
implemented yet. The acceptor is single-conversation and can restrict proxy
realms with an explicit allowlist; without one it proxies only realms in its
KDC client configuration.
The live MIT initiator gate uses `python3-gssapi` raw credentials acquired
with a password and selects mechanism OID `1.3.6.1.5.2.5`; it proxies AS/TGS
traffic through the Go acceptor and verifies a Go `Wrap`/MIT `Unwrap`
round-trip. Older MIT runtimes whose IAKERB implementation predates the
current protocol return `KRB5_BAD_MSIZE` and are skipped by the gate; the
CI image installs the MIT GSS Python binding. Reverse MIT acceptor/proxy
interoperability is not enabled.
SPNEGO remains unchanged: callers select IAKERB directly by mechanism OID.

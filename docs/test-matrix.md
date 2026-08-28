# Client test matrix

All listed cells have RED test coverage. MIT-generated keytab and FILE ccache
fixtures are now checked in; parser assertions remain RED until their
implementations land. Packet captures are still deferred and skip explicitly
when absent.

| Feature | Go client -> MIT KDC | MIT-generated fixture -> Go | Go-generated artifact -> MIT |
| --- | --- | --- | --- |
| Principal parsing | RED | RED | RED |
| ASN.1 | RED | RED | RED |
| AES128 SHA1 | RED | RED | RED |
| AES256 SHA1 | RED | RED | RED |
| AES128 SHA256 | RED | RED | RED |
| AES256 SHA384 | RED | RED | RED |
| keytab | RED | RED | RED |
| FILE ccache | RED | RED | RED |
| AS exchange | RED | RED | RED |
| TGS exchange | RED | RED | RED |
| FAST-armored TGS exchange (RFC 6113) | Go unit + Go KDC | MIT `kvno` ordinary TGS path | Go unit |
| KDC policy and ticket lifecycle | unit + MIT integration | unit coverage | MIT pass |
| Cross-realm TGS | unit + multi-hop coverage | unit coverage | unit coverage |
| KDB persistence (MIT dump) | unit + golden | MIT pass (master enctypes 17/18/19/20) | Go dump -> MIT `kdb5_util load` + `kinit` |
| AP exchange | RED | RED | RED |
| PKINIT (RFC 4556) | client and Go KDC implemented | unit + Go↔Go + MIT client coverage | MIT pass |
| RFC 3244 kpasswd change/set-password | Go client + live MIT kadmind | MIT `kadmind` | Go client |
| MIT kadm5 administrative RPC subset | Go client ↔ Go kadmind + live MIT `kadmind` | MIT `kadmind` and Go `kadm5.Server` | Go client ↔ Go server; MIT `kadmin` ↔ Go server |
| KDC aliases and canonicalization | Go client ↔ Go KDC + unit | MIT `kinit -C` client alias gate | Go client |
| KDC S4U2Self / S4U2Proxy / forwarded TGT | Go client ↔ Go KDC + unit | MIT `kvno` where supported | Go client |

The KDC supports optional server-wide preauthentication disablement, default
ticket and renewable lifetimes for requests with omitted maximum `till` or
`rtime`, and optional forwardable/renewable/proxiable flag policy. A nil
policy preserves permissive issuance, including proxiable tickets when
requested; a non-nil policy clears disallowed flags, matching MIT's
`get_ticket_flags` behavior. MIT normally configures preauthentication and
flag restrictions per principal, while this implementation exposes
server-level knobs. Renewable, postdated, and validation behavior is covered
by unit and MIT integration tests.

MIT dump persistence decrypts database key data with AES master-key enctypes
17, 18, 19, and 20 (AES-SHA1 and AES-SHA2). Go version-7/r1.11 exports include
an encrypted `K/M@REALM` record and use the K/M salt from MIT's
`krb5_principal2salt` rule (`REALMKM`). Dump/parse round trips cover keys,
KVNOs, salts, flags, expirations, and lifetimes; the integration gate loads a
Go-generated dump with real MIT `kdb5_util` and authenticates with `kinit`.

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

The PKINIT implementation supports the RFC 4556 Diffie-Hellman profile on
both the client and Go KDC. The KDC validates the client certificate chain,
the id-pkinit-KPClientAuth EKU, and the Kerberos principal SAN before signing
the DH reply and encrypting the AS-REP with the DH-derived reply key. Coverage
includes Go client ↔ Go KDC, Go client ↔ MIT KDC, and a live MIT
client ↔ Go KDC exchange when the system MIT client PKINIT plugin is
available. The implementation currently uses the RFC 3526 MODP group 14
profile and does not implement group 2 negotiation or newer algorithm-agility
KDF profiles.

The client implements RFC 3244 password changes and set-password requests
against MIT `kadmind` on the kpasswd service port (464 by default; the isolated
integration harness uses a high, configured port because it runs without root
privileges). It sends an AP-REQ and KRB-PRIV request, verifies the AP-REP, and
decrypts the result code. Set-password requests encode RFC 3244
`ChangePasswdData` with the target principal and accept either version 1 or
0xff80 in the reply.
Because MIT `kadmind` enables sequence protection but does not request timestamp
protection on its reply KRB-PRIV, a reply must contain either a fresh timestamp
or a sequence number; replies containing neither are rejected.
The live integration gates cover both changing Alice's password directly and
an authorized admin setting Alice's password, followed by Go AS exchanges with
the resulting passwords. Password policy and authorization errors are returned
without exposing password material.

The Go client and `kadm5.Server` implement a focused MIT `kadm5`
administrative RPC subset over RFC 5531 record-marked TCP with RPCSEC_GSS
privacy and strict hand-written XDR. The server uses a `kadmin/admin` keytab
and the Go GSS acceptor for context establishment. Configure `Server.ACL` to
authorize callers by authenticated principal, operation, and target; when it
is nil, only `Server.AdminPrincipal` is allowed, and an unset admin principal
denies all requests. Unknown procedures are rejected with RPC
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
only when `Server.DelegationPolicy` approves the requesting service.
S4U2Proxy requires a single forwardable evidence ticket encrypted to that
service and an allowed target from the same hook. A nil hook permits
non-forwardable S4U2Self but denies S4U2Proxy. Forwarded TGT requests require
a forwardable header TGT and set the FORWARDED ticket flag while honoring
requested addresses.

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

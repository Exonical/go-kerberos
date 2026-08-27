# Architecture

## Scope

The project is a pure Go Kerberos V5 implementation. Production packages do
not use cgo, link to `libkrb5`, shell out to MIT tools, or depend on MIT
Kerberos at runtime. MIT binaries are reserved for hermetic integration and
differential tests.

Phase 0 establishes the client-side package boundaries and test architecture.
It intentionally contains no protocol exchange, ASN.1 implementation,
cryptographic implementation, file-format parser, or KDC implementation.

## Package responsibilities

| Package | Responsibility |
| --- | --- |
| `krb5/types` | Foundational protocol values such as times, flags, addresses, and keys. |
| `krb5/principal` | Structured principal names, realms, components, and escaping. |
| `krb5/asn1` | Kerberos-specific DER/application-tag encoding and decoding. |
| `krb5/protocol` | RFC 4120 message structures and protocol field semantics. |
| `krb5/crypto/aescts` | Raw AES ciphertext stealing primitive. |
| `krb5/crypto/rfc3961` | Kerberos key derivation, key usages, checksums, and framework interfaces. |
| `krb5/crypto/rfc3962` | AES CTS HMAC SHA1 profiles (enctypes 17 and 18). |
| `krb5/crypto/rfc8009` | AES CTS HMAC SHA2 profiles (enctypes 19 and 20). |
| `krb5/config` | Intentionally scoped MIT-compatible `krb5.conf` parsing. |
| `krb5/discovery` | Configured KDC and injectable DNS SRV discovery. |
| `krb5/transport` | Bounded UDP/TCP KDC framing and exchange. |
| `krb5/keytab` | MIT FILE keytab v2 reading, writing, and lookup. |
| `krb5/ccache` | MIT FILE credential cache v4 reading, writing, and lookup. |
| `krb5/preauth` | Preauthentication data and mechanisms, including encrypted timestamp. |
| `krb5/client` | High-level password, keytab, and service-ticket client flows. |
| `krb5/ap` | AP-REQ/AP-REP application exchange. |
| `krb5/errors` | Sentinel and typed Kerberos errors with safe metadata. |
| `internal/testenv` | Disposable, hermetic test realm and dependency helpers. |
| `integration/mit` | MIT krb5 process and interoperability harness helpers. |
| `integration/fixtures` | Reproducible synthetic fixture generation and metadata. |

The `cmd` packages are deliberately thin debugging and interoperability
tools; the library is the primary product.

## Dependency direction

Dependencies point from low-level representations toward higher-level
behavior:

```text
types / principal
        ↓
      asn1
        ↓
    protocol
        ↓
 crypto, config, keytab, ccache, discovery, transport, preauth
        ↓
   client / ap
```

Low-level types must remain independent of the client. The client must not be
imported by protocol, ASN.1, principal, crypto, or file-format packages.
Integration and test helpers may depend on production packages, but production
packages must never depend on integration packages. No package may introduce a
circular dependency to share convenience helpers; shared abstractions belong
in the lowest appropriate package.

## Public API philosophy

The public API is idiomatic Go rather than a libkrb5 ABI. The eventual shape
is expected to include `Client`, `Config`, `Credentials`, and option-based
construction, for example:

```go
func NewClient(cfg Config, opts ...Option) (*Client, error)
func (c *Client) AuthenticatePassword(
    ctx context.Context, principal Principal, password []byte,
) (*Credentials, error)
func (c *Client) AuthenticateKeytab(
    ctx context.Context, principal Principal, kt *keytab.Keytab,
) (*Credentials, error)
func (c *Client) ServiceTicket(
    ctx context.Context, creds *Credentials, service Principal,
) (*Credential, error)
```

Network operations accept `context.Context`. Configuration is explicit and
there is no mutable global configuration. Key material is immutable or
carefully controlled. Protocol failures use typed errors and support
`errors.Is`/`errors.As`.

## Deterministic testing hooks

Protocol code receives dependencies instead of scattering process-global
calls. The design reserves injection points for:

* a `Clock` (`Now() time.Time`) with the production implementation backed by
  the system clock and tests backed by a fake clock;
* cryptographic randomness, defaulting to `crypto/rand.Reader`;
* nonce and sequence-number generation;
* DNS resolution and deterministic KDC ordering;
* UDP/TCP transport and timeout behavior.

These hooks allow exact RFC vectors, reproducible packet fixtures, controlled
clock-skew tests, cancellation tests, and failure-injection tests without
changing production behavior.

## Resource limits and parser policy

Every network and file parser has explicit bounds. ASN.1 lengths, TCP record
lengths, ccache and keytab records, padata, addresses, authorization-data
elements, and principal component counts are attacker-controlled and must not
drive unbounded allocation. Malformed, truncated, oversized, duplicate, or
unexpected fields return errors and never panic.

## Security baseline

The initial supported enctypes are:

* `aes128-cts-hmac-sha1-96` (17);
* `aes256-cts-hmac-sha1-96` (18);
* `aes128-cts-hmac-sha256-128` (19);
* `aes256-cts-hmac-sha384-192` (20).

DES, 3DES, and RC4-HMAC are not part of the initial implementation and are
never selected by default. Any future RC4 support must be isolated behind an
explicit legacy compatibility option or package. Cryptographic code validates
key and ciphertext lengths, rejects malformed input, uses constant-time
comparisons where required, uses `crypto/rand` for security-sensitive
randomness, avoids key material in errors/logs, and clears temporary buffers
where reasonably practical.

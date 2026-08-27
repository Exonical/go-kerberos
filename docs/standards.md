# Standards and implementation map

RFCs are normative. MIT behavior is used for published file formats and for
documented compatibility details, not as a substitute for protocol
requirements.

## RFC mapping

| Component | RFC | Sections | Tests | Implementation |
| --- | --- | --- | --- | --- |
| PrincipalName | RFC 4120 | 4.1.1, 4.2.1 | RED | not started |
| KerberosTime | RFC 4120 | 5.2.3 | RED | not started |
| KDCOptions | RFC 4120 | 5.4.1 | RED | not started |
| TicketFlags | RFC 4120 | 5.3.1 | RED | not started |
| APOptions | RFC 4120 | 5.5.1 | RED | not started |
| HostAddress / HostAddresses | RFC 4120 | 5.2.5 | RED | not started |
| AuthorizationData | RFC 4120 | 5.2.6 | RED | not started |
| PA-DATA | RFC 4120 | 5.2.7, 5.9 | RED | not started |
| EncryptedData | RFC 4120 | 5.2.9 | RED | not started |
| EncryptionKey | RFC 4120 | 5.2.9 | RED | not started |
| Checksum | RFC 4120 | 5.2.9 | RED | not started |
| Ticket | RFC 4120 | 5.3 | RED | not started |
| EncTicketPart | RFC 4120 | 5.3.1 | RED | not started |
| Authenticator | RFC 4120 | 5.5.1 | RED | not started |
| KDC-REQ / KDC-REQ-BODY | RFC 4120 | 5.4.1 | RED | not started |
| AS-REQ | RFC 4120 | 5.4.1 | RED | not started |
| TGS-REQ | RFC 4120 | 5.4.1 | RED | not started |
| KDC-REP | RFC 4120 | 5.4.2 | RED | not started |
| AS-REP | RFC 4120 | 5.4.2 | RED | not started |
| TGS-REP | RFC 4120 | 5.4.2 | RED | not started |
| EncASRepPart / EncTGSRepPart | RFC 4120 | 5.4.2 | RED | not started |
| AP-REQ / AP-REP | RFC 4120 | 5.5.1 | RED | not started |
| EncAPRepPart | RFC 4120 | 5.5.2 | RED | not started |
| KRB-ERROR | RFC 4120 | 5.9.1 | RED | not started |
| METHOD-DATA | RFC 4120 | 5.9.1 | RED | not started |
| ETYPE-INFO / ETYPE-INFO2 | RFC 4120 | 5.2.7, 5.9.1 | RED | not started |
| LastReq | RFC 4120 | 5.2.8 | RED | not started |
| TransitedEncoding | RFC 4120 | 5.3.1 | implemented | DOMAIN-X500-COMPRESS codec; MIT-compatible hierarchical and replacing-capath policy checks |
| AES CTS primitive | RFC 3962 | 5 | RED | not started |
| Kerberos crypto framework | RFC 3961 | 4–6 | RED | not started |
| AES128/AES256 CTS HMAC SHA1 | RFC 3962 | 4–5 | RED | not started |
| AES CTS HMAC SHA2 | RFC 8009 | 3–6 | RED | not started |
| AES enctype assignments and deprecations | RFC 8429 | 2–3 | RED | not started |
| String-to-key | RFC 3961, RFC 3962, RFC 8009 | 5, 4 | RED | not started |
| Key derivation and key usage | RFC 3961 | 5.1–5.2 | RED | not started |
| Checksums | RFC 3961, RFC 3962, RFC 8009 | 4, 5 | RED | not started |
| FILE keytab format | MIT krb5 format | v2 record layout | RED | not started |
| FILE ccache format | MIT krb5 format | v4 header and credential layout | RED | not started |
| `krb5.conf` | MIT krb5 format | `libdefaults`, `realms`, `domain_realm`, `capaths` | implemented | ordered client capaths |
| Generalized preauthentication / FAST | RFC 6113 | later client phase | not started | not started |
| Principal canonicalization and referrals | RFC 6806 | later client phase | not started | not started |
| Kerberos GSS-API mechanism | RFC 4121 | later client phase | not started | not started |
| GSS channel bindings | RFC 6542 | later client phase | not started | not started |
| PKINIT | RFC 4556 | client and Go KDC Diffie-Hellman profile (group 14) | implemented | unit + MIT interoperability |

## Core RFC set

The initial core set is RFC 4120, RFC 3961, RFC 3962, RFC 8009, and RFC 8429.
Later client phases include RFC 6113, RFC 6806, RFC 4121, RFC 6542, and RFC
4556. Additional RFCs will be added as functionality requires them.

## MIT compatibility oracle

The pinned source oracle is MIT krb5 tag **`krb5-1.22.2-final`**, commit
**`8570e77819563e036027e1da789d08ec9333ed4d`**.

The local runtime interop environment is Ubuntu package version
**`1.19.2-2ubuntu0.8`** (`krb5-kdc`, `krb5-user`, and related packages). This
runtime version is intentionally recorded separately from the pinned source
oracle and may differ from it.

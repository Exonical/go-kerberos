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
| AP exchange | RED | RED | RED |

The matrix will be extended for later client features such as renewal,
canonicalization, referrals, FAST, GSS-API, S4U, and PKINIT.

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

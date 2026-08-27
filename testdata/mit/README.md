# MIT fixtures

Fixtures in this directory must record the MIT krb5 version, source,
command used, principal, realm, enctype, and expected interpretation.
All fixture data must be synthetic and reproducible.

The checked-in HTML files are provenance copies of the documented MIT formats:

- `https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html`
- `https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html`

They were fetched with `curl -fsSL` while preparing the MIT krb5
`1.19.2-2ubuntu0.8` interoperability fixtures.

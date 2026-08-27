# MIT dump fixture

`test-gokrb5.dump` was generated with MIT Kerberos `kdb5_util dump -r18`
from a disposable `TEST.GOKRB5.LOCAL` database created by the integration
harness tooling. It contains only the synthetic `alice`,
`host/service.test`, and `krbtgt/TEST.GOKRB5.LOCAL` principals. The dump
uses MIT's default AES256-SHA1 database master key.

The `alice` principal used the disposable password `alice-password`; the
database master password was `synthetic-master-password`. MIT encrypts
principal key data with that master key in a normal `kdb5_util dump`; the
fixture is committed solely as a parser/interoperability test vector and
contains no production credentials. Use `mitdump.ParseWithMasterPassword`
to decrypt the key data for KDC use.

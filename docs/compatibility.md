# MIT compatibility policy

## Authority layers

Compatibility decisions use the following order of authority:

1. RFC requirements;
2. published MIT krb5 file formats and documented behavior;
3. observed MIT krb5 interoperability behavior.

The project does not mechanically translate MIT C implementation details into
Go. Core protocol behavior remains standards-driven and compatibility quirks
are isolated at the boundary where they are required.

## Discrepancy handling

When observed MIT behavior appears to contradict an RFC:

1. do not guess or silently normalize the behavior;
2. document the discrepancy and the versions involved;
3. add a focused compatibility test;
4. explain the standards-compliance and interoperability tradeoff;
5. prefer standards compliance unless interoperability requires otherwise;
6. isolate the quirk from the core protocol implementation.

Binary fixtures must be reproducible and document their source, MIT krb5
version, command used, principal, realm, enctype, and expected interpretation.
All fixture credentials are synthetic; externally used secrets must never be
committed.

## Oracle versions

The pinned MIT source oracle is **`krb5-1.22.2-final`** at commit
**`8570e77819563e036027e1da789d08ec9333ed4d`**.

The local runtime interop version is Ubuntu's MIT krb5 packages,
**`1.19.2-2ubuntu0.8`**. The source oracle is used to anchor future source
inspection and compatibility decisions; the installed runtime is used to run
the local integration harness.

The installed runtime tools are:

| Tool | Path |
| --- | --- |
| `krb5kdc` | `/usr/sbin/krb5kdc` |
| `kadmin.local` | `/usr/sbin/kadmin.local` |
| `kinit` | `/usr/bin/kinit` |
| `klist` | `/usr/bin/klist` |
| `kvno` | `/usr/bin/kvno` |
| `ktutil` | `/usr/bin/ktutil` |

## Verified interoperability results

No client interoperability results have been recorded yet. This section will
be populated at the client completion gate after the mandatory tests and MIT
integration suite pass:

* Go password client → MIT KDC;
* Go keytab client → MIT KDC;
* Go TGS client → MIT KDC;
* Go AP-REQ → MIT-compatible acceptor;
* MIT keytab → Go parser;
* Go keytab → MIT parser;
* MIT FILE ccache → Go parser;
* Go FILE ccache → MIT parser.

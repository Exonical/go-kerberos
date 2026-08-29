// Package pac implements the Microsoft Privilege Attribute Certificate
// (MS-PAC) carried in Kerberos authorization data.
//
// PAC logon-info buffers are intentionally opaque.  The package implements
// the PAC container, standard client-info and signature buffers, and the
// Kerberos keyed checksums used by MIT krb5.
package pac

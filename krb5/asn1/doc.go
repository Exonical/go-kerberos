// Package asn1 contains the DER codec used by Kerberos protocol messages.
//
// Struct fields use the krb5 tag language:
//
//   - tag:N assigns context-specific tag number N.
//   - optional allows the field to be absent.
//   - choice marks a field as one alternative in a CHOICE.
//   - implicit replaces the field's universal tag instead of wrapping it.
//   - signed encodes an unsigned Go integer using signed INTEGER semantics.
//   - bare suppresses context-specific wrapping for the field.
//
// Types implementing ApplicationTag() are encoded with the returned
// application tag. RawDER preserves an already-encoded value, ObjectIdentifier
// uses the OBJECT IDENTIFIER tag, UTF8String uses UTF8String, and KerberosTime
// and time.Time use GeneralizedTime. Flag types use the Kerberos BIT STRING
// representation. Boolean fields map to BOOLEAN, integer fields to INTEGER,
// strings to GeneralString, byte slices to OCTET STRING, other slices to
// SEQUENCE OF, and structs to SEQUENCE.
package asn1

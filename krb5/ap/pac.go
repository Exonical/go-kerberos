package ap

import (
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

// ExtractPAC extracts and verifies the MS-PAC from a decrypted service
// ticket. The service checksum is mandatory; the optional KDC key enables
// verification of the privileged-server checksum as well.
func ExtractPAC(ticket protocol.EncTicketPart, serviceKey pac.Key, kdcKey *pac.Key) (*pac.PAC, error) {
	return pac.FromTicket(ticket, serviceKey, kdcKey)
}

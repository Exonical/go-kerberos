package pac

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

func FuzzParsePAC(f *testing.F) {
	addMITFuzzSeeds(f, "FuzzParsePAC")
	if data, err := os.ReadFile("testdata/mit-saved-pac.bin"); err == nil {
		f.Add(data)
	}
	f.Add([]byte{2, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Parse(input)
	})
}

func FuzzParseLogonInfo(f *testing.F) {
	if data, err := os.ReadFile("testdata/mit-saved-logon-info.bin"); err == nil {
		f.Add(data)
	}
	f.Add([]byte{1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseLogonInfo(input)
	})
}

func FuzzParseUPNDNSInfo(f *testing.F) {
	basic, err := (UPNDNSInfoData{
		UPN: "alice@example.com", DNSDomainName: "example.com",
		Flags: UPNDNSInfoNoUPNSet,
	}).MarshalBinary()
	if err == nil {
		f.Add(basic)
	}
	sid, err := ParseSID("S-1-5-21-1-2-3")
	if err == nil {
		extended, marshalErr := (UPNDNSInfoData{
			UPN: "alice@example.com", DNSDomainName: "example.com",
			SAMName: "alice", SID: &sid, Flags: UPNDNSInfoHasSAMNameAndSID,
		}).MarshalBinary()
		if marshalErr == nil {
			f.Add(extended)
		}
	}
	f.Add([]byte{0, 0, 12, 0, 0, 0, 12, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseUPNDNSInfo(input)
	})
}

func FuzzParseDelegationInfo(f *testing.F) {
	addMITFuzzSeeds(f, "FuzzParseDelegationInfo")
	for _, value := range []string{
		"01100800cccccccca000000000000000000002002a002c0004000200010000000800020016000000000000001500000073007600630032002f00610064007300650072007600650072002e00610064002e0074006500730074000000010000003a003c000c0002001e000000000000001d00000073007600630031002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e0054004500530054000000",
		"01100800cccccccca80000000000000000000200300032000400020001000000080002001900000000000000180000006c006f006e0067007300760063002f00610064007300650072007600650072002e00610064002e007400650073007400010000003a003c000c0002001e000000000000001d00000073007600630031002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e005400450053005400000000000000",
		"01100800ccccccccf80000000000000000000200300032000400020002000000080002001900000000000000180000006c006f006e0067007300760063002f00610064007300650072007600650072002e00610064002e007400650073007400020000003a003c000c0002003a003c00100002001e000000000000001d00000073007600630031002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e00540045005300540000001e000000000000001d00000073007600630032002f00610064007300650072007600650072002e00610064002e0074006500730074004000410044002e005400450053005400000000000000",
	} {
		if data, err := hex.DecodeString(value); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseDelegationInfo(input)
	})
}

func addMITFuzzSeeds(f *testing.F, target string) {
	dir := filepath.Join("..", "..", "testdata", "mit", "fuzz", target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatalf("read MIT fuzz seeds: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			f.Fatalf("read MIT fuzz seed %s: %v", entry.Name(), err)
		}
		f.Add(data)
	}
}

func FuzzParseCredentialInfo(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 18, 0, 0, 0, 1, 2, 3, 4})
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		f.Fatal(err)
	}
	info, err := EncryptCredentialInfo(etype, bytes.Repeat([]byte{0x41}, etype.KeySize()), []byte("opaque"))
	if err == nil {
		if data, marshalErr := info.MarshalBinary(); marshalErr == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseCredentialInfo(input)
	})
}

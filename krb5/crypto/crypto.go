package crypto

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/Exonical/go-kerberos/krb5/crypto/aescts"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	EnctypeAES128SHA1   int32 = 17
	EnctypeAES256SHA1   int32 = 18
	EnctypeAES128SHA256 int32 = 19
	EnctypeAES256SHA384 int32 = 20

	ChecksumHMACSHA196AES128    int32 = 15
	ChecksumHMACSHA196AES256    int32 = 16
	ChecksumHMACSHA256128AES128 int32 = 19
	ChecksumHMACSHA384192AES256 int32 = 20
)

// EType is the common Kerberos encryption-type and checksum contract.
type EType interface {
	ID() int32
	KeySize() int
	StringToKey(password, salt, params []byte) ([]byte, error)
	Encrypt(key []byte, usage uint32, plaintext []byte) ([]byte, error)
	Decrypt(key []byte, usage uint32, ciphertext []byte) ([]byte, error)
	Checksum(key []byte, usage uint32, data []byte) ([]byte, error)
	ChecksumSize() int
	VerifyChecksum(key []byte, usage uint32, data, checksum []byte) error
}

// RandomSource supplies confounders for encryption. Tests may replace it with
// a deterministic reader; production code leaves it as rand.Reader.
var RandomSource types.RandomSource = cryptorand.Reader

// SetRandomSource replaces the confounder source and returns a restore hook.
func SetRandomSource(source types.RandomSource) func() {
	previous := RandomSource
	if source != nil {
		RandomSource = source
	}
	return func() { RandomSource = previous }
}

type aesEType struct {
	id            int32
	keySize       int
	checksumSize  int
	sha2          bool
	hash          func() hash.Hash
	etypeName     string
	defaultRounds uint32
}

func (e aesEType) ID() int32    { return e.id }
func (e aesEType) KeySize() int { return e.keySize }

func (e aesEType) StringToKey(password, salt, params []byte) ([]byte, error) {
	iterations, err := parseIterations(params, e.defaultRounds)
	if err != nil {
		return nil, fmt.Errorf("etype %d string-to-key: %w", e.id, err)
	}
	saltInput := salt
	if e.sha2 {
		saltInput = make([]byte, 0, len(e.etypeName)+1+len(salt))
		saltInput = append(saltInput, e.etypeName...)
		saltInput = append(saltInput, 0)
		saltInput = append(saltInput, salt...)
	}
	tkey, err := pbkdf2Key(e.hash, password, saltInput, iterations, e.keySize)
	if err != nil {
		return nil, fmt.Errorf("etype %d string-to-key: %w", e.id, err)
	}
	if e.sha2 {
		return kdfSHA2(e.hash, tkey, []byte("kerberos"), nil, e.keySize*8)
	}
	return dkAES(tkey, []byte("kerberos"), e.keySize)
}

func (e aesEType) Encrypt(key []byte, usage uint32, plaintext []byte) ([]byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	confounder := make([]byte, 16)
	if _, err := io.ReadFull(RandomSource, confounder); err != nil {
		return nil, fmt.Errorf("etype %d encrypt confounder: %w", e.id, err)
	}
	plain := append(append([]byte(nil), confounder...), plaintext...)
	ke, ki, err := e.deriveEncryptionKeys(key, usage)
	if err != nil {
		return nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	encrypted, err := aescts.Encrypt(ke, make([]byte, 16), plain)
	if err != nil {
		return nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	var macInput []byte
	if e.sha2 {
		macInput = append(make([]byte, 0, 16+len(encrypted)), make([]byte, 16)...)
		macInput = append(macInput, encrypted...)
	} else {
		macInput = plain
	}
	mac := hmacDigest(e.hash, ki, macInput)[:e.checksumSize]
	return append(encrypted, mac...), nil
}

func (e aesEType) Decrypt(key []byte, usage uint32, ciphertext []byte) ([]byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, fmt.Errorf("etype %d decrypt: %w", e.id, err)
	}
	if len(ciphertext) < 16+e.checksumSize {
		return nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	encrypted := ciphertext[:len(ciphertext)-e.checksumSize]
	suppliedMAC := ciphertext[len(ciphertext)-e.checksumSize:]
	ke, ki, err := e.deriveEncryptionKeys(key, usage)
	if err != nil {
		return nil, fmt.Errorf("etype %d decrypt: %w", e.id, err)
	}
	var macInput []byte
	var plain []byte
	if e.sha2 {
		macInput = append(make([]byte, 0, 16+len(encrypted)), make([]byte, 16)...)
		macInput = append(macInput, encrypted...)
	} else {
		plain, err = aescts.Decrypt(ke, make([]byte, 16), encrypted)
		if err != nil {
			return nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
		}
		macInput = plain
	}
	expectedMAC := hmacDigest(e.hash, ki, macInput)[:e.checksumSize]
	if !hmac.Equal(expectedMAC, suppliedMAC) {
		return nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	if plain == nil {
		plain, err = aescts.Decrypt(ke, make([]byte, 16), encrypted)
	}
	if err != nil || len(plain) < 16 {
		return nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	return plain[16:], nil
}

func (e aesEType) Checksum(key []byte, usage uint32, data []byte) ([]byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, fmt.Errorf("etype %d checksum: %w", e.id, err)
	}
	kc, _, err := e.deriveChecksumKey(key, usage)
	if err != nil {
		return nil, fmt.Errorf("etype %d checksum: %w", e.id, err)
	}
	return hmacDigest(e.hash, kc, data)[:e.checksumSize], nil
}

func (e aesEType) ChecksumSize() int { return e.checksumSize }

func (e aesEType) VerifyChecksum(key []byte, usage uint32, data, checksum []byte) error {
	expected, err := e.Checksum(key, usage, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, checksum) {
		return fmt.Errorf("etype %d verify checksum: %w", e.id, krberrors.ErrIntegrity)
	}
	return nil
}

// PRF computes the enctype-specific Kerberos pseudorandom function.
func PRF(etype EType, key, input []byte) ([]byte, error) {
	if etype == nil {
		return nil, fmt.Errorf("PRF: nil enctype")
	}
	aes, ok := etype.(aesEType)
	if !ok {
		return nil, krberrors.ErrUnsupportedEType
	}
	if err := validateKey(key, aes.keySize); err != nil {
		return nil, err
	}
	if aes.sha2 {
		return kdfSHA2(aes.hash, key, []byte("prf"), input, aes.hash().Size()*8)
	}
	dkey, err := dkAES(key, []byte("prf"), aes.keySize)
	if err != nil {
		return nil, err
	}
	digest := sha1.Sum(input)
	block := digest[:16]
	return aescts.Encrypt(dkey, make([]byte, 16), block)
}

// CF2 combines two keys using the RFC 6113 KRB-FX-CF2 construction.
func CF2(etype EType, key1, key2, pepper1, pepper2 []byte) ([]byte, error) {
	if etype == nil {
		return nil, fmt.Errorf("CF2: nil enctype")
	}
	if len(key1) != etype.KeySize() || len(key2) != etype.KeySize() {
		return nil, fmt.Errorf("CF2: invalid key length")
	}
	first, err := prfPlus(etype, key1, pepper1, etype.KeySize())
	if err != nil {
		return nil, err
	}
	second, err := prfPlus(etype, key2, pepper2, etype.KeySize())
	if err != nil {
		return nil, err
	}
	if len(first) != len(second) || len(first) != etype.KeySize() {
		return nil, fmt.Errorf("CF2: invalid PRF output length")
	}
	out := make([]byte, len(first))
	for i := range out {
		out[i] = first[i] ^ second[i]
	}
	return out, nil
}

func prfPlus(etype EType, key, sharedInfo []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for counter := byte(1); len(out) < size; counter++ {
		input := make([]byte, 1, 1+len(sharedInfo))
		input[0] = counter
		input = append(input, sharedInfo...)
		part, err := PRF(etype, key, input)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
		if counter == 0 {
			return nil, fmt.Errorf("CF2: shared info too long")
		}
	}
	return out[:size], nil
}

func (e aesEType) deriveEncryptionKeys(key []byte, usage uint32) ([]byte, []byte, error) {
	_, ke, ki, err := e.deriveKeys(key, usage)
	return ke, ki, err
}

func (e aesEType) deriveChecksumKey(key []byte, usage uint32) ([]byte, []byte, error) {
	kc, ke, _, err := e.deriveKeys(key, usage)
	return kc, ke, err
}

func (e aesEType) deriveKeys(key []byte, usage uint32) ([]byte, []byte, []byte, error) {
	var suffixes = [...]byte{0x99, 0xaa, 0x55}
	labels := make([][]byte, len(suffixes))
	for i, suffix := range suffixes {
		label := make([]byte, 5)
		binary.BigEndian.PutUint32(label, usage)
		label[4] = suffix
		labels[i] = label
	}
	if e.sha2 {
		kc, err := kdfSHA2(e.hash, key, labels[0], nil, e.checksumSize*8)
		if err != nil {
			return nil, nil, nil, err
		}
		ke, err := kdfSHA2(e.hash, key, labels[1], nil, e.keySize*8)
		if err != nil {
			return nil, nil, nil, err
		}
		ki, err := kdfSHA2(e.hash, key, labels[2], nil, e.checksumSize*8)
		return kc, ke, ki, err
	}
	kc, err := dkAES(key, labels[0], e.keySize)
	if err != nil {
		return nil, nil, nil, err
	}
	ke, err := dkAES(key, labels[1], e.keySize)
	if err != nil {
		return nil, nil, nil, err
	}
	ki, err := dkAES(key, labels[2], e.keySize)
	return kc, ke, ki, err
}

// Registry selects one of the supported AES enctypes.
type Registry struct{}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Get(id int32) (EType, error) {
	_ = r
	switch id {
	case EnctypeAES128SHA1:
		return aesEType{id: id, keySize: 16, checksumSize: 12, hash: sha1.New, defaultRounds: 4096}, nil
	case EnctypeAES256SHA1:
		return aesEType{id: id, keySize: 32, checksumSize: 12, hash: sha1.New, defaultRounds: 4096}, nil
	case EnctypeAES128SHA256:
		return aesEType{id: id, keySize: 16, checksumSize: 16, sha2: true, hash: sha256.New, etypeName: "aes128-cts-hmac-sha256-128", defaultRounds: 32768}, nil
	case EnctypeAES256SHA384:
		return aesEType{id: id, keySize: 32, checksumSize: 24, sha2: true, hash: sha512.New384, etypeName: "aes256-cts-hmac-sha384-192", defaultRounds: 32768}, nil
	default:
		return nil, krberrors.ErrUnsupportedEType
	}
}

func validateKey(key []byte, size int) error {
	if len(key) != size {
		return fmt.Errorf("invalid AES key length %d, want %d", len(key), size)
	}
	return nil
}

func parseIterations(params []byte, defaultValue uint32) (int, error) {
	if len(params) == 0 {
		return int(defaultValue), nil
	}
	if len(params) != 4 {
		return 0, fmt.Errorf("invalid string-to-key parameters length %d", len(params))
	}
	n := binary.BigEndian.Uint32(params)
	if n == 0 {
		return 0, fmt.Errorf("string-to-key iteration count is zero")
	}
	return int(n), nil
}

func pbkdf2Key(newHash func() hash.Hash, password, salt []byte, iterations, length int) ([]byte, error) {
	if iterations <= 0 || length < 0 {
		return nil, fmt.Errorf("invalid PBKDF2 parameters")
	}
	h := newHash()
	blocks := (length + h.Size() - 1) / h.Size()
	if uint64(blocks) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("PBKDF2 output too long")
	}
	out := make([]byte, 0, length)
	var counter [4]byte
	for i := 1; i <= blocks; i++ {
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		mac := hmac.New(newHash, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for round := 1; round < iterations; round++ {
			mac = hmac.New(newHash, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:length], nil
}

func dkAES(key, constant []byte, size int) ([]byte, error) {
	folded := nFold(constant, 128)
	out := make([]byte, 0, size)
	input := folded
	for len(out) < size {
		block, err := aescts.Encrypt(key, make([]byte, 16), input)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
		input = block
	}
	return out[:size], nil
}

func kdfSHA2(newHash func() hash.Hash, key, label, context []byte, bits int) ([]byte, error) {
	if bits <= 0 || bits%8 != 0 {
		return nil, fmt.Errorf("invalid KDF output size")
	}
	input := make([]byte, 4, 4+len(label)+1+len(context)+4)
	binary.BigEndian.PutUint32(input, 1)
	input = append(input, label...)
	input = append(input, 0)
	input = append(input, context...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(bits))
	input = append(input, length[:]...)
	return hmacDigest(newHash, key, input)[:bits/8], nil
}

func hmacDigest(newHash func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// nFold implements RFC 3961's one-complement n-fold operation.
func nFold(input []byte, outputBits int) []byte {
	if len(input) == 0 || outputBits <= 0 {
		return nil
	}
	inputBits := len(input) * 8
	lcmBits := lcm(inputBits, outputBits)
	result := make([]byte, (outputBits+7)/8)
	for chunk := 0; chunk < lcmBits/outputBits; chunk++ {
		term := make([]byte, len(result))
		for bit := 0; bit < outputBits; bit++ {
			position := chunk*outputBits + bit
			repetition := position / inputBits
			offset := position % inputBits
			source := (offset - 13*repetition) % inputBits
			if source < 0 {
				source += inputBits
			}
			if input[source/8]&(1<<uint(7-source%8)) != 0 {
				term[bit/8] |= 1 << uint(7-bit%8)
			}
		}
		addOneComplement(result, term)
	}
	return result
}

func addOneComplement(dst, src []byte) {
	var carry byte
	for i := len(dst) - 1; i >= 0; i-- {
		sum := uint16(dst[i]) + uint16(src[i]) + uint16(carry)
		dst[i] = byte(sum)
		carry = byte(sum >> 8)
	}
	for carry != 0 {
		var next byte
		for i := len(dst) - 1; i >= 0; i-- {
			sum := uint16(dst[i]) + uint16(carry)
			dst[i] = byte(sum)
			next = byte(sum >> 8)
			carry = next
		}
	}
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func lcm(a, b int) int { return a / gcd(a, b) * b }

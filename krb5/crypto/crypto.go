package crypto

import (
	"crypto/cipher"
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
	"github.com/Exonical/go-kerberos/krb5/crypto/camellia"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/types"
)

const (
	EnctypeAES128SHA1   int32 = 17
	EnctypeAES256SHA1   int32 = 18
	EnctypeAES128SHA256 int32 = 19
	EnctypeAES256SHA384 int32 = 20
	EnctypeCamellia128  int32 = 25
	EnctypeCamellia256  int32 = 26

	ChecksumHMACSHA196AES128    int32 = 15
	ChecksumHMACSHA196AES256    int32 = 16
	ChecksumHMACSHA256128AES128 int32 = 19
	ChecksumHMACSHA384192AES256 int32 = 20
	ChecksumCMACCamellia128     int32 = 17
	ChecksumCMACCamellia256     int32 = 18
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

// StatefulEType is implemented by block enctypes which support the MIT
// auth-context cipher state used by KRB-PRIV streams.
type StatefulEType interface {
	EType
	EncryptWithIV(key []byte, usage uint32, plaintext, iv []byte) (ciphertext, nextIV []byte, err error)
	DecryptWithIV(key []byte, usage uint32, ciphertext, iv []byte) (plaintext, nextIV []byte, err error)
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

type camelliaEType struct {
	id      int32
	keySize int
}

func (e camelliaEType) ID() int32    { return e.id }
func (e camelliaEType) KeySize() int { return e.keySize }

func (e camelliaEType) StringToKey(password, salt, params []byte) ([]byte, error) {
	iterations, err := parseIterations(params, 32768)
	if err != nil {
		return nil, fmt.Errorf("etype %d string-to-key: %w", e.id, err)
	}
	saltInput := make([]byte, 0, len(e.name())+1+len(salt))
	saltInput = append(saltInput, e.name()...)
	saltInput = append(saltInput, 0)
	saltInput = append(saltInput, salt...)
	tkey, err := pbkdf2Key(sha1.New, password, saltInput, iterations, e.keySize)
	if err != nil {
		return nil, fmt.Errorf("etype %d string-to-key: %w", e.id, err)
	}
	return camelliaDerive(tkey, []byte("kerberos"), e.keySize)
}

func (e camelliaEType) name() string {
	if e.id == EnctypeCamellia128 {
		return "camellia128-cts-cmac"
	}
	return "camellia256-cts-cmac"
}

func (e camelliaEType) Encrypt(key []byte, usage uint32, plaintext []byte) ([]byte, error) {
	out, _, err := e.EncryptWithIV(key, usage, plaintext, make([]byte, camellia.BlockSize))
	return out, err
}

func (e camelliaEType) EncryptWithIV(key []byte, usage uint32, plaintext, iv []byte) ([]byte, []byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	if len(iv) != camellia.BlockSize {
		return nil, nil, fmt.Errorf("etype %d encrypt: invalid IV length %d", e.id, len(iv))
	}
	confounder := make([]byte, camellia.BlockSize)
	if _, err := io.ReadFull(RandomSource, confounder); err != nil {
		return nil, nil, fmt.Errorf("etype %d encrypt confounder: %w", e.id, err)
	}
	plain := append(append([]byte(nil), confounder...), plaintext...)
	ke, err := camelliaDerivedUsage(key, usage, 0xaa)
	if err != nil {
		return nil, nil, err
	}
	ki, err := camelliaDerivedUsage(key, usage, 0x55)
	if err != nil {
		return nil, nil, err
	}
	encrypted, nextIV, err := camelliaCTS(ke, iv, plain, false)
	if err != nil {
		return nil, nil, err
	}
	mac, err := camelliaCMACKey(ki, plain)
	if err != nil {
		return nil, nil, err
	}
	return append(encrypted, mac...), nextIV, nil
}

func (e camelliaEType) Decrypt(key []byte, usage uint32, ciphertext []byte) ([]byte, error) {
	out, _, err := e.DecryptWithIV(key, usage, ciphertext, make([]byte, camellia.BlockSize))
	return out, err
}

func (e camelliaEType) DecryptWithIV(key []byte, usage uint32, ciphertext, iv []byte) ([]byte, []byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, err)
	}
	if len(iv) != camellia.BlockSize || len(ciphertext) < camellia.BlockSize+camellia.BlockSize {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	encrypted := ciphertext[:len(ciphertext)-camellia.BlockSize]
	supplied := ciphertext[len(ciphertext)-camellia.BlockSize:]
	ke, err := camelliaDerivedUsage(key, usage, 0xaa)
	if err != nil {
		return nil, nil, err
	}
	ki, err := camelliaDerivedUsage(key, usage, 0x55)
	if err != nil {
		return nil, nil, err
	}
	plain, nextIV, err := camelliaCTS(ke, iv, encrypted, true)
	if err != nil || len(plain) < camellia.BlockSize {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	expected, err := camelliaCMACKey(ki, plain)
	if err != nil || !hmac.Equal(expected, supplied) {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	return plain[camellia.BlockSize:], nextIV, nil
}

func (e camelliaEType) Checksum(key []byte, usage uint32, data []byte) ([]byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, fmt.Errorf("etype %d checksum: %w", e.id, err)
	}
	kc, err := camelliaDerivedUsage(key, usage, 0x99)
	if err != nil {
		return nil, err
	}
	return camelliaCMACKey(kc, data)
}

func (e camelliaEType) ChecksumSize() int { return camellia.BlockSize }

func (e camelliaEType) VerifyChecksum(key []byte, usage uint32, data, checksum []byte) error {
	expected, err := e.Checksum(key, usage, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, checksum) {
		return fmt.Errorf("etype %d verify checksum: %w", e.id, krberrors.ErrIntegrity)
	}
	return nil
}

func camelliaCMACKey(key, data []byte) ([]byte, error) {
	block, err := camellia.New(key)
	if err != nil {
		return nil, err
	}
	zero := make([]byte, camellia.BlockSize)
	l := make([]byte, camellia.BlockSize)
	block.Encrypt(l, zero)
	k1 := cmacDouble(l)
	k2 := cmacDouble(k1)
	n := (len(data) + camellia.BlockSize - 1) / camellia.BlockSize
	complete := len(data) > 0 && len(data)%camellia.BlockSize == 0
	if n == 0 {
		n = 1
	}
	last := make([]byte, camellia.BlockSize)
	if complete {
		copy(last, data[(n-1)*camellia.BlockSize:])
		xorBytes(last, last, k1)
	} else {
		if len(data) > 0 {
			copy(last, data[(n-1)*camellia.BlockSize:])
		}
		last[len(data)%camellia.BlockSize] = 0x80
		xorBytes(last, last, k2)
	}
	state := make([]byte, camellia.BlockSize)
	for i := 0; i < n-1; i++ {
		input := make([]byte, camellia.BlockSize)
		copy(input, data[i*camellia.BlockSize:])
		xorBytes(input, input, state)
		block.Encrypt(state, input)
	}
	xorBytes(last, last, state)
	block.Encrypt(state, last)
	return state, nil
}

func cmacDouble(in []byte) []byte {
	out := make([]byte, len(in))
	carry := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		next := in[i] >> 7
		out[i] = in[i]<<1 | carry
		carry = next
	}
	if carry != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func camelliaDerivedUsage(key []byte, usage uint32, suffix byte) ([]byte, error) {
	label := make([]byte, 5)
	binary.BigEndian.PutUint32(label, usage)
	label[4] = suffix
	return camelliaDerive(key, label, len(key))
}

func camelliaDerive(key, label []byte, size int) ([]byte, error) {
	block, err := camellia.New(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	previous := make([]byte, camellia.BlockSize)
	for counter := uint32(1); len(out) < size; counter++ {
		input := make([]byte, 0, camellia.BlockSize+4+len(label)+1+4)
		input = append(input, previous...)
		var counterBytes [4]byte
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		input = append(input, counterBytes[:]...)
		input = append(input, label...)
		input = append(input, 0)
		var lengthBytes [4]byte
		binary.BigEndian.PutUint32(lengthBytes[:], uint32(size*8))
		input = append(input, lengthBytes[:]...)
		previous, err = camelliaCMACBlock(block, input)
		if err != nil {
			return nil, err
		}
		out = append(out, previous...)
	}
	return out[:size], nil
}

func camelliaCMACBlock(block cipher.Block, data []byte) ([]byte, error) {
	zero := make([]byte, block.BlockSize())
	l := make([]byte, block.BlockSize())
	block.Encrypt(l, zero)
	k1 := cmacDouble(l)
	k2 := cmacDouble(k1)
	n := (len(data) + block.BlockSize() - 1) / block.BlockSize()
	complete := len(data) > 0 && len(data)%block.BlockSize() == 0
	if n == 0 {
		n = 1
	}
	last := make([]byte, block.BlockSize())
	if complete {
		copy(last, data[(n-1)*block.BlockSize():])
		xorBytes(last, last, k1)
	} else {
		copy(last, data[(n-1)*block.BlockSize():])
		last[len(data)%block.BlockSize()] = 0x80
		xorBytes(last, last, k2)
	}
	state := make([]byte, block.BlockSize())
	for i := 0; i < n-1; i++ {
		input := make([]byte, block.BlockSize())
		copy(input, data[i*block.BlockSize():])
		xorBytes(input, input, state)
		block.Encrypt(state, input)
	}
	xorBytes(last, last, state)
	block.Encrypt(state, last)
	return state, nil
}

func camelliaCTS(key, iv, input []byte, decrypt bool) ([]byte, []byte, error) {
	block, err := camellia.New(key)
	if err != nil {
		return nil, nil, err
	}
	bs := block.BlockSize()
	if len(iv) != bs || len(input) < bs {
		return nil, nil, fmt.Errorf("Camellia CTS: invalid input")
	}
	if !decrypt {
		if len(input) == bs {
			out := make([]byte, bs)
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, input)
			return out, append([]byte(nil), out...), nil
		}
		if len(input)%bs == 0 {
			out := make([]byte, len(input))
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, input)
			last := len(out) - bs
			previous := last - bs
			swapped := append([]byte(nil), out[previous:last]...)
			copy(out[previous:last], out[last:])
			copy(out[last:], swapped)
			return out, append([]byte(nil), out[len(out)-2*bs:len(out)-bs]...), nil
		}
		full := len(input) / bs
		rem := len(input) % bs
		out := make([]byte, 0, len(input))
		previous := iv
		for i := 0; i < full-1; i++ {
			encrypted := make([]byte, bs)
			xorBytes(encrypted, input[i*bs:(i+1)*bs], previous)
			block.Encrypt(encrypted, encrypted)
			out = append(out, encrypted...)
			previous = encrypted
		}
		penultimate := input[(full-1)*bs : full*bs]
		last := input[full*bs:]
		x := make([]byte, bs)
		xorBytes(x, penultimate, previous)
		block.Encrypt(x, x)
		padded := make([]byte, bs)
		copy(padded, last)
		xorBytes(padded, padded, x)
		y := make([]byte, bs)
		block.Encrypt(y, padded)
		out = append(out, y...)
		out = append(out, x[:rem]...)
		nextOffset := len(out) - rem - bs
		return out, append([]byte(nil), out[nextOffset:nextOffset+bs]...), nil
	}
	if len(input) == bs {
		out := make([]byte, bs)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, input)
		return out, append([]byte(nil), input...), nil
	}
	full := len(input) / bs
	rem := len(input) % bs
	out := make([]byte, 0, len(input))
	previous := iv
	previousBlocks := full - 2
	if rem != 0 {
		previousBlocks = full - 1
	}
	for i := 0; i < previousBlocks; i++ {
		plain := make([]byte, bs)
		cipher.NewCBCDecrypter(block, previous).CryptBlocks(plain, input[i*bs:(i+1)*bs])
		out = append(out, plain...)
		previous = input[i*bs : (i+1)*bs]
	}
	yBlock := full - 2
	if rem != 0 {
		yBlock = full - 1
	}
	y := input[yBlock*bs : yBlock*bs+bs]
	xPart := input[yBlock*bs+bs:]
	if rem == 0 {
		dy := make([]byte, bs)
		block.Decrypt(dy, y)
		plainLast := make([]byte, bs)
		xorBytes(plainLast, dy, xPart)
		dx := make([]byte, bs)
		block.Decrypt(dx, xPart)
		plainPenultimate := make([]byte, bs)
		xorBytes(plainPenultimate, dx, previous)
		out = append(out, plainPenultimate...)
		out = append(out, plainLast...)
		return out, append([]byte(nil), input[len(input)-2*bs:len(input)-bs]...), nil
	}
	dy := make([]byte, bs)
	block.Decrypt(dy, y)
	x := make([]byte, bs)
	copy(x, xPart)
	copy(x[rem:], dy[rem:])
	plainLast := make([]byte, rem)
	for i := range plainLast {
		plainLast[i] = dy[i] ^ x[i]
	}
	dx := make([]byte, bs)
	block.Decrypt(dx, x)
	plainPenultimate := make([]byte, bs)
	xorBytes(plainPenultimate, dx, previous)
	out = append(out, plainPenultimate...)
	out = append(out, plainLast...)
	nextOffset := len(input) - rem - bs
	return out, append([]byte(nil), input[nextOffset:nextOffset+bs]...), nil
}

func xorBytes(dst, left, right []byte) {
	for i := range dst {
		dst[i] = left[i] ^ right[i]
	}
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
	out, _, err := e.EncryptWithIV(key, usage, plaintext, make([]byte, 16))
	return out, err
}

func (e aesEType) EncryptWithIV(key []byte, usage uint32, plaintext, iv []byte) ([]byte, []byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	if len(iv) != 16 {
		return nil, nil, fmt.Errorf("etype %d encrypt: invalid IV length %d", e.id, len(iv))
	}
	confounder := make([]byte, 16)
	if _, err := io.ReadFull(RandomSource, confounder); err != nil {
		return nil, nil, fmt.Errorf("etype %d encrypt confounder: %w", e.id, err)
	}
	plain := append(append([]byte(nil), confounder...), plaintext...)
	ke, ki, err := e.deriveEncryptionKeys(key, usage)
	if err != nil {
		return nil, nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	encrypted, nextIV, err := aescts.EncryptWithState(ke, iv, plain)
	if err != nil {
		return nil, nil, fmt.Errorf("etype %d encrypt: %w", e.id, err)
	}
	var macInput []byte
	if e.sha2 {
		macInput = append(make([]byte, 0, 16+len(encrypted)), iv...)
		macInput = append(macInput, encrypted...)
	} else {
		macInput = plain
	}
	mac := hmacDigest(e.hash, ki, macInput)[:e.checksumSize]
	return append(encrypted, mac...), nextIV, nil
}

func (e aesEType) Decrypt(key []byte, usage uint32, ciphertext []byte) ([]byte, error) {
	out, _, err := e.DecryptWithIV(key, usage, ciphertext, make([]byte, 16))
	return out, err
}

func (e aesEType) DecryptWithIV(key []byte, usage uint32, ciphertext, iv []byte) ([]byte, []byte, error) {
	if err := validateKey(key, e.keySize); err != nil {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, err)
	}
	if len(iv) != 16 {
		return nil, nil, fmt.Errorf("etype %d decrypt: invalid IV length %d", e.id, len(iv))
	}
	if len(ciphertext) < 16+e.checksumSize {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	encrypted := ciphertext[:len(ciphertext)-e.checksumSize]
	suppliedMAC := ciphertext[len(ciphertext)-e.checksumSize:]
	ke, ki, err := e.deriveEncryptionKeys(key, usage)
	if err != nil {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, err)
	}
	var macInput []byte
	var plain []byte
	var nextIV []byte
	if e.sha2 {
		macInput = append(make([]byte, 0, 16+len(encrypted)), iv...)
		macInput = append(macInput, encrypted...)
	} else {
		plain, nextIV, err = aescts.DecryptWithState(ke, iv, encrypted)
		if err != nil {
			return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
		}
		macInput = plain
	}
	expectedMAC := hmacDigest(e.hash, ki, macInput)[:e.checksumSize]
	if !hmac.Equal(expectedMAC, suppliedMAC) {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	if plain == nil {
		plain, nextIV, err = aescts.DecryptWithState(ke, iv, encrypted)
	}
	if err != nil || len(plain) < 16 {
		return nil, nil, fmt.Errorf("etype %d decrypt: %w", e.id, krberrors.ErrIntegrity)
	}
	return plain[16:], nextIV, nil
}

// EncryptWithIV performs authenticated encryption with an explicit CBC-CTS
// IV and returns the next MIT auth-context state.
func EncryptWithIV(etype EType, key []byte, usage uint32, plaintext, iv []byte) ([]byte, []byte, error) {
	stateful, ok := etype.(StatefulEType)
	if !ok {
		return nil, nil, fmt.Errorf("etype %d does not support cipher state", etype.ID())
	}
	return stateful.EncryptWithIV(key, usage, plaintext, iv)
}

// DecryptWithIV performs authenticated decryption with an explicit CBC-CTS IV
// and returns the next MIT auth-context state.
func DecryptWithIV(etype EType, key []byte, usage uint32, ciphertext, iv []byte) ([]byte, []byte, error) {
	stateful, ok := etype.(StatefulEType)
	if !ok {
		return nil, nil, fmt.Errorf("etype %d does not support cipher state", etype.ID())
	}
	return stateful.DecryptWithIV(key, usage, ciphertext, iv)
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
		if cam, ok := etype.(camelliaEType); ok {
			if err := validateKey(key, cam.keySize); err != nil {
				return nil, err
			}
			dkey, err := camelliaDerive(key, []byte("prf"), cam.keySize)
			if err != nil {
				return nil, err
			}
			return camelliaCMACKey(dkey, input)
		}
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
	return CF2WithKeyEType(etype, key1, etype, key2, pepper1, pepper2)
}

// CF2WithKeyEType combines keys using RFC 6113 KRB-FX-CF2 when the
// contribution keys have different enctypes. The result has the enctype and
// key length of etype1, matching krb5_c_fx_cf2_simple.
func CF2WithKeyEType(etype1 EType, key1 []byte, etype2 EType, key2, pepper1, pepper2 []byte) ([]byte, error) {
	if etype1 == nil || etype2 == nil {
		return nil, fmt.Errorf("CF2: nil enctype")
	}
	if len(key1) != etype1.KeySize() || len(key2) != etype2.KeySize() {
		return nil, fmt.Errorf("CF2: invalid key length")
	}
	first, err := prfPlus(etype1, key1, pepper1, etype1.KeySize())
	if err != nil {
		return nil, err
	}
	second, err := prfPlus(etype2, key2, pepper2, etype1.KeySize())
	if err != nil {
		return nil, err
	}
	if len(first) != len(second) || len(first) != etype1.KeySize() {
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

// Registry selects one of the supported enctypes.
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
	case EnctypeCamellia128:
		return camelliaEType{id: id, keySize: 16}, nil
	case EnctypeCamellia256:
		return camelliaEType{id: id, keySize: 32}, nil
	default:
		return nil, krberrors.ErrUnsupportedEType
	}
}

func validateKey(key []byte, size int) error {
	if len(key) != size {
		return fmt.Errorf("invalid key length %d, want %d", len(key), size)
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

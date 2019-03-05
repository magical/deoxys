package deoxys

/*
Potential optimizations:

the output of m.encrypt is almost always immediately xored with something
*/

import (
	"crypto/subtle"
	"errors"
)

const (
	tagMessage        = 0 << 4
	tagNonce          = 1 << 4
	tagAdditionalData = 2 << 4
	tagPadding        = 4 << 4
)

const padByte byte = 0x80

const (
	blockSize = 16
	numRounds = 15
	NonceSize = 15
	TagSize   = 16
)

// Mode implements the Deoxys-II authenticated encryption mode
// with Deoxys-BC as the underlying tweakable block cipher
type mode struct {
	state   [16]uint8
	subkey  [numRounds][16]uint8
	counter [16]uint8
}

func New(key []byte) *mode {
	m := new(mode)
	m.Reset(key)
	return m
}

func (m *mode) Reset(key []byte) {
	expandKey(key, m.subkey[:])
}

func (m *mode) NonceSize() int {
	return NonceSize
}

func (m *mode) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates the plaintext
func (m *mode) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	tmp := make([]byte, 16)
	auth := make([]byte, TagSize)

	// hash the message and additional data
	// to get the auth tag
	m.hash(tagAdditionalData, additionalData, tmp, auth)
	m.hash(tagMessage, plaintext, tmp, auth)

	// encrypt the auth with the nonce as tweak to get the final tag
	m.counter[0] = tagNonce
	copy(m.counter[1:], nonce)
	m.encrypt(auth, auth)

	// encrypt the message
	// using the auth tag as an IV
	copy(m.counter[0:], auth)
	m.counter[0] |= 0x80
	p := plaintext
	var nonce0 = make([]byte, 16)
	copy(nonce0[1:], nonce)
	var i int64
	for i = 0; len(p) >= 16; i++ {
		m.counter[8] = auth[8] ^ uint8(i>>56)
		m.counter[9] = auth[9] ^ uint8(i>>48)
		m.counter[10] = auth[10] ^ uint8(i>>40)
		m.counter[11] = auth[11] ^ uint8(i>>32)
		m.counter[12] = auth[12] ^ uint8(i>>24)
		m.counter[13] = auth[13] ^ uint8(i>>16)
		m.counter[14] = auth[14] ^ uint8(i>>8)
		m.counter[15] = auth[15] ^ uint8(i)

		m.encrypt(nonce0, tmp)

		xor(tmp, p[:16])
		p = p[16:]
		dst = append(dst, tmp...)
	}
	if len(p) > 0 {
		m.counter[8] = auth[8] ^ uint8(i>>56)
		m.counter[9] = auth[9] ^ uint8(i>>48)
		m.counter[10] = auth[10] ^ uint8(i>>40)
		m.counter[11] = auth[11] ^ uint8(i>>32)
		m.counter[12] = auth[12] ^ uint8(i>>24)
		m.counter[13] = auth[13] ^ uint8(i>>16)
		m.counter[14] = auth[14] ^ uint8(i>>8)
		m.counter[15] = auth[15] ^ uint8(i)

		m.encrypt(nonce0, tmp)
		xor(tmp, p)
		dst = append(dst, tmp[:len(p)]...)
	}

	// append the tag
	dst = append(dst, auth...)

	return dst
}

// Open authenticates the ciphertext and additional data and returns the decrypted plaintext.
func (m *mode) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	tmp := make([]byte, 16)
	auth := make([]byte, TagSize)

	if len(ciphertext) < TagSize {
		return dst, errors.New("Open: ciphertext too short")
	}

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]

	origLen := len(dst)

	// decrypt
	// using the auth tag as an IV
	copy(m.counter[0:], tag)
	m.counter[0] |= 0x80
	p := ciphertext
	var nonce0 = make([]byte, 16)
	copy(nonce0[1:], nonce)
	var i uint64
	for i = 0; len(p) >= blockSize; i++ {
		m.counter[8] = tag[8] ^ uint8(i>>56)
		m.counter[9] = tag[9] ^ uint8(i>>48)
		m.counter[10] = tag[10] ^ uint8(i>>40)
		m.counter[11] = tag[11] ^ uint8(i>>32)
		m.counter[12] = tag[12] ^ uint8(i>>24)
		m.counter[13] = tag[13] ^ uint8(i>>16)
		m.counter[14] = tag[14] ^ uint8(i>>8)
		m.counter[15] = tag[15] ^ uint8(i)

		m.encrypt(nonce0, tmp)
		xor(tmp, p[:blockSize])
		p = p[blockSize:]
		dst = append(dst, tmp...)
	}
	if len(p) > 0 {
		m.counter[8] = tag[8] ^ uint8(i>>56)
		m.counter[9] = tag[9] ^ uint8(i>>48)
		m.counter[10] = tag[10] ^ uint8(i>>40)
		m.counter[11] = tag[11] ^ uint8(i>>32)
		m.counter[12] = tag[12] ^ uint8(i>>24)
		m.counter[13] = tag[13] ^ uint8(i>>16)
		m.counter[14] = tag[14] ^ uint8(i>>8)
		m.counter[15] = tag[15] ^ uint8(i)

		m.encrypt(nonce0, tmp)
		xor(tmp, p)
		dst = append(dst, tmp[:len(p)]...)
	}

	// hash the message and additional data
	// to get the auth tag
	m.hash(tagAdditionalData, additionalData, tmp, auth)
	m.hash(tagMessage, dst[origLen:], tmp, auth)

	// encrypt the auth with the nonce as tweak to get the final tag
	m.counter[0] = tagNonce
	copy(m.counter[1:], nonce)
	m.encrypt(auth, auth)

	if subtle.ConstantTimeCompare(auth, tag) == 0 {
		return dst, errors.New("Open: invalid tag")
	}

	return dst, nil
}

func (m *mode) encrypt(in, out []byte) {
	encryptBlock(m.subkey[:], m.counter[:], in, out)
}

func (m *mode) hash(tag uint8, data, tmp, auth []byte) {
	for i := range m.counter {
		m.counter[i] = 0
	}
	m.counter[0] = tag
	for len(data) >= 16 {
		m.encrypt(data[:16], tmp)
		data = data[16:]
		xor(auth, tmp)
		m.inc()
	}
	if len(data) > 0 {
		m.counter[0] |= tagPadding
		for i := range tmp {
			tmp[i] = 0
		}
		n := copy(tmp, data)
		tmp[n] = padByte
		m.encrypt(tmp, tmp)
		xor(auth, tmp)
	}
}

func (m *mode) inc() {
	for i := len(m.counter) - 1; i >= 0; i-- {
		m.counter[i]++
		if m.counter[i] != 0 {
			return
		}
	}
}

func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}

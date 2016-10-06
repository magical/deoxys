package deoxys

/*
Potential optimizations:

the third parameter of m.encrypt is always counter
the output of m.encrypt is almost always immediately xored with something
*/

import (
	"crypto/subtle"
	"errors"
)

const (
	tagNonce          = 1
	tagAdditionalData = 2
	tagPadding        = 4
	tagMessage        = 8
)

const padByte byte = 0x80

const (
	blockSize = 16
	numRounds = 15
	NonceSize = 16 // 15?
	TagSize   = 16
)

// Mode implements SCT (Synthetic Counter in Tweak) mode for Deoxys-BC
type mode struct {
	key     []byte
	state   [16]uint8
	subkey  [numRounds][16]uint8
	counter [16]uint8
}

func (m *mode) NonceSize() int {
	return NonceSize
}

func (m *mode) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates the plaintext
func (m *mode) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	expandKey(m.key, m.subkey[:])

	out := make([]byte, 16)
	auth := make([]byte, TagSize)
	pad := make([]byte, 16)

	// hash the additional data to get an auth tag
	m.setCounter(tagAdditionalData)
	for len(additionalData) >= 16 {
		m.encrypt(additionalData[:16], out)
		additionalData = additionalData[16:]
		xor(auth, out)
		m.inc()
	}
	if len(additionalData) > 0 {
		m.setPadding()
		n := copy(pad, additionalData)
		pad[n] = padByte
		m.encrypt(pad, out)
		xor(auth, out)
		m.inc()
	}

	// hash the message to get another auth tag
	m.setCounter(tagMessage)
	p := plaintext
	for len(p) >= 16 {
		m.encrypt(p[:16], out)
		p = p[16:]
		xor(auth, out)
		m.inc()
	}
	if len(p) > 0 {
		m.setPadding()
		for i := range pad {
			pad[i] = 0
		}
		n := copy(pad, p)
		pad[n] = padByte
		m.encrypt(pad, out)
		xor(auth, out)
	}

	// encrypt the auth with the nonce as tweak to get the final tag
	m.counter[0] = tagNonce
	copy(m.counter[1:], nonce)
	m.encrypt(auth, auth)

	// encrypt the message
	// using the auth tag as an IV
	copy(m.counter[0:], auth)
	m.counter[0] |= 0x80
	p = plaintext
	for len(p) >= 16 {
		m.encrypt(nonce, out)
		m.inc()
		xor(out, p[:16])
		p = p[16:]
		dst = append(dst, out...)
	}
	if len(p) > 0 {
		m.encrypt(nonce, out)
		xor(out, p)
		dst = append(dst, out[:len(p)]...)
	}

	// append the tag
	dst = append(dst, auth...)

	return dst
}

// Open authenticates the ciphertext and additional data and returns the decrypted plaintext.
func (m *mode) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	expandKey(m.key, m.subkey[:])

	out := make([]byte, 16)
	auth := make([]byte, TagSize)
	pad := make([]byte, 16)

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
	for len(p) >= blockSize {
		m.encrypt(nonce, out)
		m.inc()
		xor(out, p[:blockSize])
		p = p[blockSize:]
		dst = append(dst, out...)
	}
	if len(p) > 0 {
		m.encrypt(nonce, out)
		xor(out, p)
		dst = append(dst, out[:len(p)]...)
	}

	// hash the additional data to get an auth tag
	m.setCounter(tagAdditionalData)
	p = dst[origLen:]
	for len(additionalData) >= blockSize {
		m.encrypt(additionalData[:blockSize], out)
		additionalData = additionalData[blockSize:]
		xor(auth, out)
		m.inc()
	}
	if len(additionalData) > 0 {
		m.setPadding()
		for i := range pad {
			pad[i] = 0
		}
		n := copy(pad, additionalData)
		pad[n] = padByte
		m.encrypt(pad, out)
		xor(auth, out)
		m.inc()
	}

	// reset the counter
	// hash the message to get another auth tag
	m.setCounter(tagMessage)
	p = dst[origLen:]
	for len(p) >= blockSize {
		m.encrypt(p[:blockSize], out)
		p = p[blockSize:]
		xor(auth, out)
		m.inc()
	}
	if len(p) > 0 {
		m.setPadding()
		n := copy(pad, p)
		pad[n] = padByte
		m.encrypt(pad, out)
		xor(auth, out)
	}

	// encrypt the auth with the nonce as tweak to get the final tag
	m.counter[0] = tagNonce
	copy(m.counter[1:], nonce)
	m.encrypt(auth, auth)

	if subtle.ConstantTimeCompare(auth, tag) == 0 {
		return dst, errors.New("Open: invalid tag")
	}

	return dst, nil
}

func (m *mode) encrypt(msg, out []byte) {
	encrypt(m.subkey[:], m.counter[:], msg, out)
}

func (m *mode) setCounter(tag uint8) {
	for i := range m.counter {
		m.counter[i] = 0
	}
	m.counter[0] = tag
}

func (m *mode) setPadding() {
	m.counter[0] |= tagPadding
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

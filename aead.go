package deoxys

/*
Potential optimizations:

the third parameter of c.encrypt is always counter
the output of c.encrypt is almost always immediately xored with something
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
	NonceSize = 16 // 15?
	TagSize   = 16
)

// Mode implements SCT (Synthetic Counter in Tweak) mode for Deoxys-BC
type mode struct {
	key []byte
}

func (m *mode) NonceSize() int {
	return NonceSize
}

func (m *mode) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates the plaintext
func (m *mode) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	var c cipher

	c.expand(m.key)

	counter := make([]byte, 16)
	out := make([]byte, 16)
	auth := make([]byte, TagSize)
	pad := make([]byte, 16)

	// hash the additional data to get an auth tag
	counter[0] = tagAdditionalData
	for len(additionalData) >= 16 {
		c.encrypt(additionalData[:16], out, counter)
		additionalData = additionalData[16:]
		xor(auth, out)
		inc(counter)
	}
	if len(additionalData) > 0 {
		counter[0] |= tagPadding
		n := copy(pad, additionalData)
		pad[n] = padByte
		c.encrypt(pad, out, counter)
		xor(auth, out)
		inc(counter)
	}

	// reset the counter
	// hash the message to get another auth tag
	for i := range counter {
		counter[i] = 0
	}
	counter[0] = tagMessage

	p := plaintext
	for len(p) >= 16 {
		c.encrypt(p[:16], out, counter)
		p = p[16:]
		xor(auth, out)
		inc(counter)
	}
	if len(p) > 0 {
		counter[0] |= tagPadding
		for i := range pad {
			pad[i] = 0
		}
		n := copy(pad, p)
		pad[n] = padByte
		c.encrypt(pad, out, counter)
		xor(auth, out)
	}

	// encrypt the nonce to get the final tag
	tmp := []byte{tagNonce}
	tmp = append(tmp, nonce[:15]...)
	c.encrypt(tmp, auth, counter)

	// encrypt the message
	// using the auth tag as an IV
	copy(counter, auth)
	counter[0] |= 0x80
	p = plaintext
	for len(p) >= 16 {
		c.encrypt(nonce, out, counter)
		inc(counter)
		xor(out, p[:16])
		p = p[16:]
		dst = append(dst, out...)
	}
	if len(p) > 0 {
		c.encrypt(nonce, out, counter)
		xor(out, p)
		dst = append(dst, out[:len(p)]...)
	}

	// append the tag
	dst = append(dst, auth...)

	return dst
}

// Open authenticates the ciphertext and additional data and returns the decrypted plaintext.
func (m *mode) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var c cipher

	c.expand(m.key)

	counter := make([]byte, 16)
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
	copy(counter, tag)
	counter[0] |= 0x80
	p := ciphertext
	for len(p) >= blockSize {
		c.encrypt(nonce, out, counter)
		inc(counter)
		xor(out, p[:blockSize])
		p = p[blockSize:]
		dst = append(dst, out...)
	}
	if len(p) > 0 {
		c.encrypt(nonce, out, counter)
		xor(out, p)
		dst = append(dst, out[:len(p)]...)
	}

	// hash the additional data to get an auth tag
	for i := range counter {
		counter[i] = 0
	}
	counter[0] = tagAdditionalData
	p = dst[origLen:]
	for len(additionalData) >= blockSize {
		c.encrypt(additionalData[:blockSize], out, counter)
		additionalData = additionalData[blockSize:]
		xor(auth, out)
		inc(counter)
	}
	if len(additionalData) > 0 {
		counter[0] |= tagPadding
		for i := range pad {
			pad[i] = 0
		}
		n := copy(pad, additionalData)
		pad[n] = padByte
		c.encrypt(pad, out, counter)
		xor(auth, out)
		inc(counter)
	}

	// reset the counter
	// hash the message to get another auth tag
	for i := range counter {
		counter[i] = 0
	}
	counter[0] = tagMessage

	p = dst[origLen:]
	for len(p) >= blockSize {
		c.encrypt(p[:blockSize], out, counter)
		p = p[blockSize:]
		xor(auth, out)
		inc(counter)
	}
	if len(p) > 0 {
		counter[0] |= tagPadding
		n := copy(pad, p)
		pad[n] = padByte
		c.encrypt(pad, out, counter)
		xor(auth, out)
	}

	// encrypt the nonce to get the final tag
	// XXX don't allocate
	tmp := []byte{tagNonce}
	tmp = append(tmp, nonce[:15]...)
	c.encrypt(tmp, auth, counter)

	if subtle.ConstantTimeCompare(auth, tag) == 0 {
		return dst, errors.New("Open: invalid tag")
	}

	return dst, nil
}

func inc(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}

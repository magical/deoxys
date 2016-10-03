package deoxys

const (
	tagNonce          = 1 << 4
	tagAdditionalData = 2 << 4
	tagPadding        = 4 << 4
	tagMessage        = 8 << 4
)

const padByte byte = 0x80

const (
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
	counter[len(counter)-1] = tagAdditionalData
	for len(additionalData) > 0 {
		c.encrypt(additionalData[:16], out, counter)
		additionalData = additionalData[16:]
		xor(auth, out)
		inc(counter)
	}
	if len(additionalData) > 0 {
		counter[len(counter)-1] |= tagPadding
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
	counter[len(counter)-1] = tagMessage

	p := plaintext
	for len(p) >= 16 {
		c.encrypt(p[:16], out, counter)
		p = p[16:]
		xor(auth, out)
		inc(counter)
	}
	if len(p) > 0 {
		counter[len(counter)-1] |= tagPadding
		n := copy(pad, p)
		pad[n] = padByte
		c.encrypt(pad, out, counter)
		xor(auth, out)
	}

	// encrypt the nonce to get the final tag
	// XXX don't modify the nonce
	nonce[15] = tagNonce
	c.encrypt(nonce, out, counter)
	xor(auth, out)

	// encrypt the message
	// using the auth tag as an IV
	copy(counter, auth)
	counter[len(auth)-1] |= 0x80
	p = plaintext
	for len(p) >= 16 {
		c.encrypt(nonce, out, counter)
		inc(counter)
		xor(out, p[:16])
		p = p[16:]
		dst = append(dst, out...)
	}

	// append the tag
	dst = append(dst, auth...)

	return dst
}

// Open authenticates the ciphertext and additional data and returns the decrypted plaintext.
func (m *mode) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return dst, nil
}

func inc(b []byte) {
	for i := range b {
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

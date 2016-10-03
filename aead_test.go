package deoxys

import (
	"bytes"
	"testing"
)

func TestAEAD(t *testing.T) {
	var m mode
	m.key = []byte("16-byte password")
	msg := []byte("A witty saying means nothing.")
	nonce := make([]byte, 16)
	t.Errorf("%x", m.Seal(nil, nonce, msg, nil))
	t.Errorf("%x", m.Seal(nil, nonce, msg, nil))
	m.key[0]++
	t.Errorf("%x", m.Seal(nil, nonce, msg, nil))
	m.key[0]--
	t.Errorf("%x", m.Seal(nil, nonce, msg[:len(msg)-1], nil))
}

func TestRoundTrip(t *testing.T) {
	var m mode
	m.key = []byte("16-byte password")
	msg := []byte("A witty saying means nothing.")
	nonce := make([]byte, 16)
	ciphertext := m.Seal(nil, nonce, msg, nil)
	plaintext, err := m.Open(nil, nonce, ciphertext, nil)
	if !bytes.Equal(plaintext, msg) {
		t.Errorf("got %q, expected %q", plaintext, msg)
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

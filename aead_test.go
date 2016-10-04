package deoxys

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAEAD(t *testing.T) {
	var m mode
	m.key = []byte("16-byte password")
	msg := []byte("A witty saying means nothing.")
	nonce := make([]byte, 16)
	fmt.Printf("%x\n", m.Seal(nil, nonce, msg, nil))
	fmt.Printf("%x\n", m.Seal(nil, nonce, msg, nil))
	m.key[0]++
	fmt.Printf("%x\n", m.Seal(nil, nonce, msg, nil))
	m.key[0]--
	fmt.Printf("%x\n", m.Seal(nil, nonce, msg[:len(msg)-1], nil))
}

func TestRoundTrip(t *testing.T) {
	var m mode
	m.key = []byte("16-byte password")
	strings := []string{
		"A witty saying means nothing.",
		"Test",
		"16-byte message.",
	}
	for _, s := range strings {
		msg := []byte(s)
		nonce := make([]byte, 16)
		ciphertext := m.Seal(nil, nonce, msg, nil)
		plaintext, err := m.Open(nil, nonce, ciphertext, nil)
		if !bytes.Equal(plaintext, msg) {
			t.Errorf("got %q, expected %q", plaintext, msg)
		}
		if len(ciphertext) != len(msg)+m.Overhead() {
			t.Errorf("ciphertext is %d bytes long, expected %d", len(ciphertext), len(msg)+m.Overhead())
		}
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

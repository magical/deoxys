package deoxys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAEAD(t *testing.T) {
	key := []byte("16-byte password")
	m := New(key)
	msg := []byte("A witty saying means nothing.")
	nonce := make([]byte, 16)

	c0 := m.Seal(nil, nonce, msg, nil)
	expected := "3cf210b430d6e145caa59ea2b40e78a421e4e2afca47684e911e5caa430cd55152e1e168780c40bd547846622d"
	if hex.EncodeToString(c0) != expected {
		t.Errorf("Seal(%q) = %x, want %s", msg, c0, expected)
	}

	// Encrypting the same message twice should yield the same result
	c1 := m.Seal(nil, nonce, msg, nil)
	if !bytes.Equal(c0, c1) {
		t.Errorf("Seal(%q) != Seal(%q), got %x, want %x", msg, msg, c1, c0)
	}

	// A shorter message should result in a completely different ciphertext
	m.Reset(key)
	c2 := m.Seal(nil, nonce, msg[:len(msg)-1], nil)
	if bytes.Equal(c2[:4], c0[:4]) {
		fmt.Printf("Seal(%q) = %x which shares a prefix with %x, want them not to share a prefix\n",
			msg[:len(msg)-1], c2, c0)
	}

	// Changing the key should completely change the result
	key[0]++
	m.Reset(key)
	c3 := m.Seal(nil, nonce, msg, nil)
	if c3[0] == c0[0] {
		t.Errorf("encrypting with a different key: got %x, want first byte not to equal %x", c3, c0)
	}

	t.Logf("%x", c0)
	t.Logf("%x", c1)
	t.Logf("%x", c2)
	t.Logf("%x", c3)
}

func TestRoundTrip(t *testing.T) {
	m := New([]byte("16-byte password"))
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

func BenchmarkAEAD(b *testing.B) {
	m := New([]byte("16-byte password"))
	msg := []byte("A witty saying means nothing.")
	nonce := make([]byte, 16)
	dst := make([]byte, 0, len(msg)+TagSize)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Seal(dst, nonce, msg, nil)
	}
}

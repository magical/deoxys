package deoxys

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAEAD(t *testing.T) {
	var messages = []struct {
		msg      string
		expected string
	}{
		{
			msg:      "",
			expected: "cb65a26fa783f43e3a521222528f0784",
		},
		{
			msg:      "A witty saying means nothing.",
			expected: "1af49030fb15049f74de9e6128a0bc52c4ad781449d74e969c03143a07611b478d4601b26ac0136539520955d0",
		},
		{
			msg:      "A witty saying means nothing",
			expected: "f2dd5a749ef9693679e03f81466ecfb98b653fb37a46fdd5d1823664cf3e9afd41204283ea157580fa13adbe",
		},
	}

	key := []byte("16-byte password")
	m := New(key)
	for _, tt := range messages {
		msg := []byte(tt.msg)
		nonce := make([]byte, 16)

		c0 := m.Seal(nil, nonce, msg, nil)
		if hex.EncodeToString(c0) != tt.expected {
			t.Errorf("Seal(%q) = %x, want %s", msg, c0, tt.expected)
		}

		// Encrypting the same message twice should yield the same result
		c1 := m.Seal(nil, nonce, msg, nil)
		if !bytes.Equal(c0, c1) {
			t.Errorf("Seal(%q) != Seal(%q), got %x, want %x", msg, msg, c1, c0)
		}
	}

	m = New(ones(16))
	c2 := m.Seal(nil, ones(16), ones(16), ones(16))
	expected := "208a09bb8bbe926a4ab279558a73e9f5b7faa510395cc8616c8647834f07a7b0"
	if hex.EncodeToString(c2) != expected {
		t.Errorf("Seal(all ones) = %x, want %s", c2, expected)
	}

	m = New(seq(16))
	c3 := m.Seal(nil, seq(16), seq(16), seq(16))
	expected = "b69e98eca406bb3dd32243a8a7eed7591652f9313719cdc264e4949437e2ffd7"
	if hex.EncodeToString(c3) != expected {
		t.Errorf("Seal(seq) = %x, want %s", c3, expected)
	}

}

func ones(n int) []byte {
	return bytes.Repeat([]byte{0xff}, n)
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestAEADReset(t *testing.T) {
	msg := []byte("A witty saying means nothing.")
	key := []byte("16-byte password")
	nonce := make([]byte, 16)
	m := New(key)

	c0 := m.Seal(nil, nonce, msg, nil)
	expected := "1af49030fb15049f74de9e6128a0bc52c4ad781449d74e969c03143a07611b478d4601b26ac0136539520955d0"
	if hex.EncodeToString(c0) != expected {
		t.Errorf("Seal(%q) = %x, want %s", msg, c0, expected)
	}

	// Changing the key should completely change the result
	key[0]++
	m.Reset(key)
	c3 := m.Seal(nil, nonce, msg, nil)
	if c3[0] == c0[0] {
		t.Errorf("encrypting with a different key: got %x, want first byte not to equal %x", c3, c0)
	}
}

func TestRoundTrip(t *testing.T) {
	m := New([]byte("16-byte password"))
	strings := []string{
		"",
		"A witty saying means nothing.",
		"Test",
		"16-byte message.",
		"32-byte message.thirty-two bytes",
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

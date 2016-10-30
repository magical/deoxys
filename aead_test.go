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
		{"", "cb65a26fa783f43e3a521222528f0784"},
		{"A witty saying means nothing.", "1af49030fb15049f74de9e6128a0bc52c4ad781449d74e969c03143a07611b478d4601b26ac0136539520955d0"},
		{"A witty saying means nothing", "f2dd5a749ef9693679e03f81466ecfb98b653fb37a46fdd5d1823664cf3e9afd41204283ea157580fa13adbe"},
		{"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe;\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.", "cb6633b2e730db0d16a0a8e03387c9ea129474dfba9078841d91fdf0ef67b2dee95f12d3bd4885bd5ce020d49c04a81e4015f6e52c66601d3d61f1f8b41528ba8321432ecbfb8a8d57ec96e03ec0aaeef024265715bc998579de2c16cebf79c8959c01ce73f0ad1fd3541f51d1145d7c6ef274666f567c6d1d0b4b4c6046d583007d73d28e0c08ce0a8c0f64f2503e"},
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
		"this message is almost 32 bytes",
		"this message is exactly 32 bytes",
		"this message is exactly forty-five bytes long",
		"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe;\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.",
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

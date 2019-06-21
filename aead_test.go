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
		{"", "7c6267994f22088683fd3e3cee4181b2"},
		{"A witty saying means nothing.", "6ecc0e56ba5c4ab9d319cb6369c76a966ac539dc602bdab82f204f54329ac667ae01578d4ad38fee2f5c4e2f1e"},
		{"A witty saying means nothing", "dad0f5e05a13565af2e35d3b0970ccd08c1adcd4407a07f4f2eea30ac4a56e92fc2b50dee99812dc2daa556e"},
		{"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe;\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.", "135d06320d5eb9e28b14ab9b336c856d043e532f66dcbc3b0341b167e94059f65bf1eff775775f7313ad76c25c2710b7596c7165ba2841789b1142f29d42f639a8ceb6e19aa8fbd0297b49d44c173027e1324486fe221f69ad42944ff9a6b95993df1fdd2134c6768a407aa1e5024769d9b8af7b40f673f5aa1d984c40ac55e969aa5f0214666109f7510b26ad8ce5"},
	}

	key := []byte("16-byte password")
	m := New(key)
	for _, tt := range messages {
		msg := []byte(tt.msg)
		nonce := make([]byte, 15)

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
	c2 := m.Seal(nil, ones(15), ones(16), ones(16))
	expected := "0f38e4dcd31415f6aa3afeb6453a504ace67765a883b62e325f95999faadedde"
	if hex.EncodeToString(c2) != expected {
		t.Errorf("Seal(all ones) = %x, want %s", c2, expected)
	}

	m = New(seq(16))
	c3 := m.Seal(nil, seq(15), seq(16), seq(16))
	expected = "9f19f37a6f1257ef08ffcfb14f27c1f22c49b01bf5830c39d31c6c781ca25bfb"
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
	nonce := make([]byte, 15)
	m := New(key)

	c0 := m.Seal(nil, nonce, msg, nil)
	expected := "6ecc0e56ba5c4ab9d319cb6369c76a966ac539dc602bdab82f204f54329ac667ae01578d4ad38fee2f5c4e2f1e"
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
		nonce := make([]byte, 15)
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
	nonce := make([]byte, 15)
	dst := make([]byte, 0, len(msg)+TagSize)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Seal(dst, nonce, msg, nil)
	}
}

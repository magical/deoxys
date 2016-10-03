package deoxys

import "testing"

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

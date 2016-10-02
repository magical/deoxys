package deoxys

import "testing"

func TestDeoxys(t *testing.T) {
	var c cipher
	key := make([]byte, 16)
	tweak := make([]byte, 16)
	msg := make([]byte, 16)
	out := make([]byte, 16)
	c.expand(key)
	c.encrypt(msg, out, tweak)
	t.Errorf("% x", c)
	t.Errorf("% x", out)
}

func TestMul(t *testing.T) {
	tests := []struct {
		a, b, r uint
	}{
		{1, 1, 1},
		{2, 1, 2},
		{2, 2, 4},
		{2, 0x80, 0x1b},
	}
	for _, tt := range tests {
		got := mul(tt.a, tt.b)
		if got != tt.r {
			t.Errorf("mul(%d, %d) = %d, expected %d", tt.a, tt.b, got, tt.r)
		}
	}
}

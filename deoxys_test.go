package deoxys

import (
	"encoding/hex"
	"testing"
)

func TestDeoxys(t *testing.T) {
	key := make([]byte, 16)
	tweak := make([]byte, 16)
	msg := make([]byte, 16)
	out := make([]byte, 16)
	subkey := make([][16]byte, rounds+1)

	expandKey(key, subkey)
	encrypt(subkey, tweak, msg, out)

	actual := hex.EncodeToString(out)
	expected := "80b2311e3129c07c386da385e79a4886"
	if actual != expected {
		t.Errorf("got %s, expected %s", actual, expected)
	}
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

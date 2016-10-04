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
	subkey := make([][16]byte, numRounds)

	expandKey(key, subkey)
	encrypt(subkey, tweak, msg, out)

	actual := hex.EncodeToString(out)
	expected := "80b2311e3129c07c386da385e79a4886"
	if actual != expected {
		t.Errorf("got %s, expected %s", actual, expected)
	}

	msg[1] = 0xff
	encrypt(subkey, tweak, msg, out)

	actual = hex.EncodeToString(out)
	expected = "1bdfc9a6c16149ac337d959724c4142b"
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

func TestMul2(t *testing.T) {
	for x := 0; x < 256; x++ {
		got := uint(mul2(uint8(x)))
		want := mul(2, uint(x))
		if got != want {
			t.Errorf("mul2(%d) = %d, expected %d", x, got, want)
		}
	}
}

func TestMul3(t *testing.T) {
	for x := 0; x < 256; x++ {
		got := uint(mul3(uint8(x)))
		want := mul(3, uint(x))
		if got != want {
			t.Errorf("mul3(%d) = %d, expected %d", x, got, want)
		}
	}
}

func mul(a, b uint) uint {
	var r uint
	for a > 0 {
		if a&1 != 0 {
			r ^= b
		}
		a >>= 1
		b <<= 1
		if b >= 0x100 {
			b ^= poly
		}
	}
	return r
}

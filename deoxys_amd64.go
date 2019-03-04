package deoxys

import "golang.org/x/sys/cpu"

//go:noescape
func encryptBlockAsm(subkey [][16]uint8, tweak, in, out []byte)

func supported() bool {
	// for AESENC and PSHUFB
	return cpu.X86.HasAES && cpu.X86.HasSSSE3
}

func encryptBlock(subkey [][16]uint8, tweak, in, out []byte) {
	if supported() {
		encryptBlockAsm(subkey, tweak, in, out)
	} else {
		encryptBlockGo(subkey, tweak, in, out)
	}
}

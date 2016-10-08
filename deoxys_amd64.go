package deoxys

func hasAESNI() bool

//go:noescape
func encryptBlockAsm(subkey [][16]uint8, tweak, in, out []byte)

func encryptBlock(subkey [][16]uint8, tweak, in, out []byte) {
	if hasAESNI() {
		encryptBlockAsm(subkey, tweak, in, out)
	} else {
		encryptBlockGo(subkey, tweak, in, out)
	}
}

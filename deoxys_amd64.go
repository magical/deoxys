package deoxys

//go:noescape
func encryptBlockAsm(subkey [][16]uint8, tweak, in, out []byte)

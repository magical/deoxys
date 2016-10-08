// +build !amd64

package deoxys

func encryptBlock(subkey [][16]uint8, tweak, in, out []byte) {
	encryptBlockGo(subkey, tweak, in, out)
}

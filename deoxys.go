// Package deoxys implements the Deoxys-BC block cipher
// and Deoxys-II nonce-misuse-resistant authenticated encryption mode.
//
// Deoxys 1.4 Specification:
//
//     http://www1.spms.ntu.edu.sg/~syllab/m/images/8/87/Deoxys.v1.4.pdf
//
package deoxys

// AES Sbox
var sbox = [256]uint8{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var rc = [17]uint8{0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72}

var permutations = [8][16]int8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8},
	{6, 15, 4, 13, 10, 3, 8, 1, 14, 7, 12, 5, 2, 11, 0, 9},
	{15, 8, 5, 2, 3, 12, 9, 6, 7, 0, 13, 10, 11, 4, 1, 14},
	{8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7},
	{9, 14, 3, 4, 13, 2, 7, 8, 1, 6, 11, 12, 5, 10, 15, 0},
	{14, 7, 12, 5, 2, 11, 0, 9, 6, 15, 4, 13, 10, 3, 8, 1},
	{7, 0, 13, 10, 11, 4, 1, 14, 15, 8, 5, 2, 3, 12, 9, 6},
}

const poly = 0x11b

// ExpandKey expands a 16-byte key into a
// number of subkeys
func expandKey(key []byte, subkey [][16]uint8) {
	var tk1 [16]uint8
	if len(key) != 16 {
		panic("wrong size key")
	}
	copy(tk1[:], key[0:16])
	for i := range subkey {
		subkey[i] = tk1
		subkey[i][0] ^= 1
		subkey[i][4] ^= 2
		subkey[i][8] ^= 4
		subkey[i][12] ^= 8
		subkey[i][1] ^= rc[i]
		subkey[i][5] ^= rc[i]
		subkey[i][9] ^= rc[i]
		subkey[i][13] ^= rc[i]
		for j, v := range h(tk1) {
			tk1[j] = v<<1 | v>>7 | (v>>5)&1
		}
	}
}

func encrypt(subkey [][16]uint8, tweak, in, out []byte) {
	var s [16]uint8
	var tw [16]uint8
	copy(tw[:], tweak[0:16])
	for i := range s {
		s[i] = in[swap(i)]
	}
	copy(s[:], in) // FIXME
	for r := range subkey[:len(subkey)-1] {
		k := &subkey[r]

		// Add tweakey
		for i := range s {
			s[i] ^= k[i] ^ tw[i]
		}

		// subbytes
		for i, v := range s {
			s[i] = sbox[v]
		}

		// shiftrows
		s[4], s[5], s[6], s[7] = s[5], s[6], s[7], s[4]
		s[8], s[9], s[10], s[11] = s[10], s[11], s[8], s[9]
		s[12], s[13], s[14], s[15] = s[15], s[12], s[13], s[14]

		// mixcolumns
		for i := 0; i < 4; i++ {
			s0, s1, s2, s3 := s[i], s[i+4], s[i+8], s[i+12]
			s[i+0] = mul2(s0) ^ mul3(s1) ^ s2 ^ s3
			s[i+4] = mul2(s1) ^ mul3(s2) ^ s3 ^ s0
			s[i+8] = mul2(s2) ^ mul3(s3) ^ s0 ^ s1
			s[i+12] = mul2(s3) ^ mul3(s0) ^ s1 ^ s2
		}

		// update tweak
		tw = h(tw)
	}
	// Add tweakey
	for i := range s {
		s[i] ^= subkey[len(subkey)-1][i] ^ tw[i]
	}

	for i := range out {
		out[i] = s[swap(i)]
	}
}

func round(s *[16]byte, k, tw *[16]byte, rc uint8) {
}

func mul2(x uint8) uint8 {
	t := int32(x) << 1
	t ^= poly & (t << 23 >> 31)
	return uint8(t)
}

func mul3(x uint8) uint8 {
	t := int32(x)
	t ^= t << 1
	t ^= poly & (t << 23 >> 31)
	return uint8(t)
}

func h(p [16]uint8) [16]uint8 {
	return [16]uint8{
		p[1], p[6], p[11], p[12], p[5], p[10], p[15], p[0],
		p[9], p[14], p[3], p[4], p[13], p[2], p[7], p[8]}
}

func swap(v int) int {
	return v>>2&3 | v&3<<2
}

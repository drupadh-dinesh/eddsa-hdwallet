package hdwallet

import "encoding/binary"

func ripemd160(message []byte) [20]byte {
	h0 := uint32(0x67452301)
	h1 := uint32(0xefcdab89)
	h2 := uint32(0x98badcfe)
	h3 := uint32(0x10325476)
	h4 := uint32(0xc3d2e1f0)

	padded := make([]byte, len(message)+1)
	copy(padded, message)
	padded[len(message)] = 0x80
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.LittleEndian.AppendUint64(padded, uint64(len(message))*8)

	for i := 0; i < len(padded); i += 64 {
		var x [16]uint32
		for j := range x {
			x[j] = binary.LittleEndian.Uint32(padded[i+4*j:])
		}

		al, bl, cl, dl, el := h0, h1, h2, h3, h4
		ar, br, cr, dr, er := h0, h1, h2, h3, h4

		for j := range 80 {
			t := bitsRotateLeft32(al+f(j, bl, cl, dl)+x[rl[j]]+kl(j), sl[j]) + el
			al, el, dl, cl, bl = el, dl, bitsRotateLeft32(cl, 10), bl, t

			t = bitsRotateLeft32(ar+f(79-j, br, cr, dr)+x[rr[j]]+kr(j), sr[j]) + er
			ar, er, dr, cr, br = er, dr, bitsRotateLeft32(cr, 10), br, t
		}

		t := h1 + cl + dr
		h1 = h2 + dl + er
		h2 = h3 + el + ar
		h3 = h4 + al + br
		h4 = h0 + bl + cr
		h0 = t
	}

	var digest [20]byte
	binary.LittleEndian.PutUint32(digest[0:], h0)
	binary.LittleEndian.PutUint32(digest[4:], h1)
	binary.LittleEndian.PutUint32(digest[8:], h2)
	binary.LittleEndian.PutUint32(digest[12:], h3)
	binary.LittleEndian.PutUint32(digest[16:], h4)
	return digest
}

func f(j int, x, y, z uint32) uint32 {
	switch {
	case j < 16:
		return x ^ y ^ z
	case j < 32:
		return (x & y) | (^x & z)
	case j < 48:
		return (x | ^y) ^ z
	case j < 64:
		return (x & z) | (y & ^z)
	default:
		return x ^ (y | ^z)
	}
}

func kl(j int) uint32 {
	switch {
	case j < 16:
		return 0x00000000
	case j < 32:
		return 0x5a827999
	case j < 48:
		return 0x6ed9eba1
	case j < 64:
		return 0x8f1bbcdc
	default:
		return 0xa953fd4e
	}
}

func kr(j int) uint32 {
	switch {
	case j < 16:
		return 0x50a28be6
	case j < 32:
		return 0x5c4dd124
	case j < 48:
		return 0x6d703ef3
	case j < 64:
		return 0x7a6d76e9
	default:
		return 0x00000000
	}
}

func bitsRotateLeft32(x uint32, k int) uint32 {
	return x<<k | x>>(32-k)
}

var rl = [80]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var rr = [80]int{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var sl = [80]int{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

var sr = [80]int{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

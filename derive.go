package hdwallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"filippo.io/edwards25519"
)

// HardenedOffset is added to a child number to request hardened derivation.
const HardenedOffset uint32 = 0x80000000

// Hardened returns the hardened child index for i.
func Hardened(i uint32) uint32 {
	return i + HardenedOffset
}

// Derive derives a child extended key.
//
// Private extended keys can derive hardened and non-hardened children. Public
// extended keys can derive only non-hardened children.
func (k *ExtendedKey) Derive(index uint32) (*ExtendedKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if !k.isPrivate && index >= HardenedOffset {
		return nil, fmt.Errorf("%w: index %d", ErrHardenedPublicChild, index)
	}
	if k.depth == ^uint8(0) {
		return nil, ErrDepthOverflow
	}

	if k.isPrivate {
		return k.derivePrivate(index)
	}
	return k.derivePublic(index)
}

func (k *ExtendedKey) derivePrivate(index uint32) (*ExtendedKey, error) {
	parentKey := k.seed()
	if parentKey == nil {
		return nil, ErrInvalidKey
	}

	z, childChainCode, err := k.deriveMaterial(index, parentKey, k.PublicKey())
	if err != nil {
		return nil, err
	}
	defer zero(z)

	tweak, err := scalarTweakFromZ(z[:32])
	if err != nil {
		return nil, err
	}
	parentScalar := scalarFromBytes(parentKey[:scalarSize])
	childScalar := edwards25519.NewScalar().Add(parentScalar, tweak)

	childKey := make([]byte, privateKeySize)
	copy(childKey[:scalarSize], childScalar.Bytes())
	copy(childKey[scalarSize:], add256(parentKey[scalarSize:], z[32:]))

	return &ExtendedKey{
		key:       childKey,
		chainCode: childChainCode,
		depth:     k.depth + 1,
		childNum:  index,
		parentFP:  k.Fingerprint(),
		isPrivate: true,
	}, nil
}

func (k *ExtendedKey) derivePublic(index uint32) (*ExtendedKey, error) {
	if index >= HardenedOffset {
		return nil, fmt.Errorf("%w: index %d", ErrHardenedPublicChild, index)
	}
	parentPub := k.PublicKey()
	if len(parentPub) != publicKeySize {
		return nil, ErrInvalidKey
	}

	z, childChainCode, err := k.deriveMaterial(index, nil, parentPub)
	if err != nil {
		return nil, err
	}
	defer zero(z)

	tweak, err := scalarTweakFromZ(z[:32])
	if err != nil {
		return nil, err
	}
	tweakPoint := new(edwards25519.Point).ScalarBaseMult(tweak)
	parentPoint, err := new(edwards25519.Point).SetBytes(parentPub)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid public key point", ErrInvalidKey)
	}
	childPoint := new(edwards25519.Point).Add(parentPoint, tweakPoint)

	return &ExtendedKey{
		key:       cloneBytes(childPoint.Bytes()),
		chainCode: childChainCode,
		depth:     k.depth + 1,
		childNum:  index,
		parentFP:  k.Fingerprint(),
		isPrivate: false,
	}, nil
}

func (k *ExtendedKey) deriveMaterial(index uint32, privateKey, publicKey []byte) ([]byte, [32]byte, error) {
	var zPrefix, cPrefix byte
	var keyMaterial []byte
	if index >= HardenedOffset {
		if len(privateKey) != privateKeySize {
			return nil, [32]byte{}, ErrInvalidKey
		}
		zPrefix = 0x00
		cPrefix = 0x01
		keyMaterial = privateKey
	} else {
		if len(publicKey) != publicKeySize {
			return nil, [32]byte{}, ErrInvalidKey
		}
		zPrefix = 0x02
		cPrefix = 0x03
		keyMaterial = publicKey
	}

	data := make([]byte, 1+len(keyMaterial)+4)
	data[0] = zPrefix
	copy(data[1:], keyMaterial)
	binary.LittleEndian.PutUint32(data[1+len(keyMaterial):], index)
	defer zero(data)

	zmac := hmac.New(sha512.New, k.chainCode[:])
	_, _ = zmac.Write(data)
	z := zmac.Sum(nil)

	data[0] = cPrefix
	cmac := hmac.New(sha512.New, k.chainCode[:])
	_, _ = cmac.Write(data)
	cc := cmac.Sum(nil)
	defer zero(cc)

	var childChainCode [32]byte
	copy(childChainCode[:], cc[32:])
	return z, childChainCode, nil
}

func scalarTweakFromZ(z []byte) (*edwards25519.Scalar, error) {
	if len(z) < 28 {
		return nil, ErrInvalidKey
	}
	var shifted [32]byte
	var carry uint16
	for i := range 28 {
		v := uint16(z[i])<<3 | carry
		shifted[i] = byte(v)
		carry = v >> 8
	}
	shifted[28] = byte(carry)
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(shifted[:])
	if err != nil {
		return nil, err
	}
	return scalar, nil
}

func add256(a, b []byte) []byte {
	out := make([]byte, 32)
	var carry uint16
	for i := range 32 {
		sum := uint16(a[i]) + uint16(b[i]) + carry
		out[i] = byte(sum)
		carry = sum >> 8
	}
	return out
}

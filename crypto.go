package main

import (
	"errors"
	"golang.org/x/crypto/blake2b"
	"io"
)

const keyLen = 64

func RNGcryptEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	var err error
	var out []byte
	var expandedKey []byte

	var xof blake2b.XOF

	var rng0 BitPrng
	var rng1 BitPrng

	var r0 byte
	var r1 byte

	xof, err = blake2b.NewXOF(keyLen, nil)
	if err != nil {
		return nil, errors.Join(errors.New("error initializing hash"), err)
	}
	_, err = xof.Write(key) //can't error
	expandedKey, _ = io.ReadAll(xof)

	rng0 = &FortunaRand{}
	rng1 = &FortunaRand{}

	rng0.Init(expandedKey[:(keyLen/2)-1])
	rng1.Init(expandedKey[keyLen/2:])

	out = make([]byte, len(plaintext))

	var bytePos uint64
	var bitPos uint64

	for i := uint64(0); i < uint64(len(plaintext)*8); i++ {
	retry:
		r0 = rng0.NextBit()
		r1 = rng1.NextBit()
		if r0 == r1 {
			goto retry
		}

		bytePos = i / 8
		bitPos = 7 - (i % 8)

		if (plaintext[bytePos]>>bitPos)&1 == 0 {
			out[bytePos] |= r0 << bitPos
		} else {
			out[bytePos] |= r1 << bitPos
		}
	}

	return out, nil
}

func RNGcryptDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	var err error
	var out []byte
	var expandedKey []byte

	var xof blake2b.XOF

	var rng0 BitPrng
	var rng1 BitPrng

	var r0 byte
	var r1 byte

	xof, err = blake2b.NewXOF(keyLen, nil)
	if err != nil {
		return nil, errors.Join(errors.New("error initializing hash"), err)
	}
	_, err = xof.Write(key) //can't error
	expandedKey, _ = io.ReadAll(xof)

	rng0 = &FortunaRand{}
	rng1 = &FortunaRand{}

	rng0.Init(expandedKey[:(keyLen/2)-1])
	rng1.Init(expandedKey[keyLen/2:])

	out = make([]byte, len(ciphertext))

	for i := uint64(0); i < uint64(len(ciphertext)*8); i++ {
	retry:
		r0 = rng0.NextBit()
		r1 = rng1.NextBit()
		if r0 == r1 {
			goto retry
		}

		if (ciphertext[i/8]>>(7-(i%8)))&1 == r0 {
			out[i/8] |= 0 << (7 - (i % 8))
		} else {
			out[i/8] |= 1 << (7 - (i % 8))
		}
	}

	return out, nil
}

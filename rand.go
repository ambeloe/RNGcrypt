package main

import (
	"crypto/aes"
	"math"
	"math/rand"
)
import "github.com/seehuhn/fortuna"

type BitPrng interface {
	Init(seed []byte)

	NextBit() byte
}

type MathRand struct {
	s rand.Source

	r *rand.Rand
}

func (m *MathRand) Init(seed []byte) {
	m.s = rand.NewSource(int64(seed[0]) | int64(seed[1])<<8 | int64(seed[2])<<16 | int64(seed[3])<<24)
	m.r = rand.New(m.s)
}

func (m *MathRand) NextBit() byte {
	return byte(m.r.Uint32()) & 1
}

type FortunaRand struct {
	gen *fortuna.Generator

	buf    []byte
	offset int
}

func (f *FortunaRand) Init(seed []byte) {
	f.gen = fortuna.NewGenerator(aes.NewCipher)

	f.gen.Seed(int64(seed[0]) | int64(seed[1])<<8 | int64(seed[2])<<16 | int64(seed[3])<<24)

	f.offset = math.MaxInt
}

func (f *FortunaRand) NextBit() byte {
	var t byte
	if f.offset > 127*8 {
		f.buf = f.gen.PseudoRandomData(128)
		f.offset = 0
	}

	//get f.offset bit of buf slice
	t = (f.buf[f.offset/8] >> (7 - (f.offset % 8))) & 1
	f.offset++

	return t
}

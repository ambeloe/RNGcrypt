package main

import "testing"

const key = "passwrord123"

var cool []byte

func BenchmarkRNGcryptEncrypt(b *testing.B) {
	var e, o []byte
	e = make([]byte, 1000000)
	for i := 0; i < b.N; i++ {
		o, _ = RNGcryptEncrypt([]byte(key), e)
	}

	cool = o
}

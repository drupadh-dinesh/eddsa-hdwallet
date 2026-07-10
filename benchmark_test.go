package hdwallet

import "testing"

func BenchmarkNewMaster(b *testing.B) {
	seed := make([]byte, 32)
	for b.Loop() {
		_, err := NewMaster(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDerivePath(b *testing.B) {
	master, err := NewMaster(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_, err := master.DerivePath("m/44'/0'/0'")
		if err != nil {
			b.Fatal(err)
		}
	}
}

package lms

import (
	"runtime"
	"testing"

	"github.com/trailofbits/lms-go/lms/common"
)

var benchmarkSignature LmsSignature

// Run explicitly with -run '^$' -bench '^BenchmarkSignH20$' -benchtime=1000x.
// Each signature uses the next index of a fresh H20 key; setup is untimed.
func BenchmarkSignH20(b *testing.B) {
	key, err := NewPrivateKey(common.LMS_SHA256_M32_H20, common.LMOTS_SHA256_N32_W4)
	if err != nil {
		b.Fatal(err)
	}
	if b.N > 1<<20 {
		b.Fatal("benchmark exceeds H20 signature capacity; use -benchtime=1000x")
	}
	message := []byte("benchmark message")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := key.Sign(message, nil)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSignature = sig
	}
	b.StopTimer()
	benchmarkSignature = LmsSignature{}
}

// Measure live heap after the private key goes out of scope while one
// unserialized signature remains. Run with -benchtime=1x; tree construction is
// intentionally expensive. Other runtime allocations make this approximate.
func BenchmarkSignatureRetainedMemoryH20(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		sig := signatureFromTemporaryKey(b)
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained-B")
		runtime.KeepAlive(sig)
	}
}

func signatureFromTemporaryKey(b *testing.B) LmsSignature {
	b.Helper()
	key, err := NewPrivateKey(common.LMS_SHA256_M32_H20, common.LMOTS_SHA256_N32_W4)
	if err != nil {
		b.Fatal(err)
	}
	sig, err := key.Sign([]byte("retained message"), nil)
	if err != nil {
		b.Fatal(err)
	}
	return sig
}

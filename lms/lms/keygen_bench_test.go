package lms_test

import (
	"testing"

	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
)

func benchKeygen(b *testing.B, tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := lms.NewPrivateKey(tc, otstc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeygen_H15_W4(b *testing.B) {
	benchKeygen(b, common.LMS_SHA256_M32_H15, common.LMOTS_SHA256_N32_W4)
}

func BenchmarkKeygen_H15_W8(b *testing.B) {
	benchKeygen(b, common.LMS_SHA256_M32_H15, common.LMOTS_SHA256_N32_W8)
}

func BenchmarkKeygen_H20_W4(b *testing.B) {
	benchKeygen(b, common.LMS_SHA256_M32_H20, common.LMOTS_SHA256_N32_W4)
}

func BenchmarkKeygen_H20_W8(b *testing.B) {
	benchKeygen(b, common.LMS_SHA256_M32_H20, common.LMOTS_SHA256_N32_W8)
}

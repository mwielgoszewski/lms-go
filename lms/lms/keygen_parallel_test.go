package lms_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
	"github.com/trailofbits/lms-go/lms/ots"
)

// generatePKTreeSerial is the serial RFC 8554 Appendix A algorithm, used as
// a reference oracle.
func generatePKTreeSerial(t *testing.T, tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType, id common.ID, seed []byte) [][]byte {
	t.Helper()
	params, err := tc.LmsParams()
	if err != nil {
		t.Fatal(err)
	}
	ots_params, err := otstc.Params()
	if err != nil {
		t.Fatal(err)
	}

	tree_nodes := uint32(1)<<(params.H+1) - 1
	leaves := uint32(1) << params.H
	authtree := make([][]byte, tree_nodes)

	var r uint32
	var r_be [4]byte
	for i := uint32(0); i < leaves; i++ {
		r = i + leaves
		ots_priv, err := ots.NewPrivateKeyFromSeed(otstc, i, id, seed)
		if err != nil {
			t.Fatal(err)
		}
		ots_pub, err := ots_priv.Public()
		if err != nil {
			t.Fatal(err)
		}

		binary.BigEndian.PutUint32(r_be[:], r)

		hasher := ots_params.H.New()
		common.HashWrite(hasher, id[:])
		common.HashWrite(hasher, r_be[:])
		common.HashWrite(hasher, common.D_LEAF[:])
		common.HashWrite(hasher, ots_pub.Key())
		authtree[r-1] = common.HashSum(hasher, ots_params.N)

		j := i
		for j%2 == 1 {
			r = (r - 1) >> 1
			j = (j - 1) >> 1
			hasher := ots_params.H.New()
			binary.BigEndian.PutUint32(r_be[:], r)
			common.HashWrite(hasher, id[:])
			common.HashWrite(hasher, r_be[:])
			common.HashWrite(hasher, common.D_INTR[:])
			common.HashWrite(hasher, authtree[2*r-1])
			common.HashWrite(hasher, authtree[2*r])
			authtree[r-1] = common.HashSum(hasher, ots_params.N)
		}
	}
	return authtree
}

func TestGeneratePKTreeParallelMatchesSerial(t *testing.T) {
	cases := []struct {
		name  string
		tc    common.LmsAlgorithmType
		otstc common.LmsOtsAlgorithmType
	}{
		{"H10_W4", common.LMS_SHA256_M32_H10, common.LMOTS_SHA256_N32_W4},
		{"H10_W8", common.LMS_SHA256_M32_H10, common.LMOTS_SHA256_N32_W8},
		{"H5_W8", common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W8},
	}

	id := common.ID{0xd0, 0x8f, 0xab, 0xd4, 0xa2, 0x09, 0x1f, 0xf0, 0xa8, 0xcb, 0x4e, 0xd8, 0x34, 0xe7, 0x45, 0x34}
	seed := []byte{
		0x55, 0x8b, 0x89, 0x66, 0xc4, 0x8a, 0xe9, 0xcb,
		0x89, 0x8b, 0x42, 0x3c, 0x83, 0x44, 0x3a, 0xae,
		0x01, 0x4a, 0x72, 0xf1, 0xb1, 0xab, 0x5c, 0xc8,
		0x5c, 0xf1, 0xd8, 0x92, 0x90, 0x3b, 0x54, 0x39,
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			want := generatePKTreeSerial(t, tt.tc, tt.otstc, id, seed)
			got, err := lms.GeneratePKTree(tt.tc, tt.otstc, id, seed)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatalf("tree length mismatch: got %d, want %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("tree node %d differs:\n got  %x\n want %x", i, got[i], want[i])
				}
			}
		})
	}
}

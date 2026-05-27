package hss_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/hss"
)

// twoLevelTypes returns parameter slices for an L=2 HSS using the smallest
// available LMS/OTS parameters. Both levels use H=5 (32 leaves each).
func twoLevelTypes() ([]common.LmsAlgorithmType, []common.LmsOtsAlgorithmType) {
	return []common.LmsAlgorithmType{common.LMS_SHA256_M32_H5, common.LMS_SHA256_M32_H5},
		[]common.LmsOtsAlgorithmType{common.LMOTS_SHA256_N32_W8, common.LMOTS_SHA256_N32_W8}
}

func TestHssNewPrivateKeyAndPublic(t *testing.T) {
	lmsTypes, otsTypes := twoLevelTypes()
	priv, err := hss.NewPrivateKey(lmsTypes, otsTypes)
	assert.NoError(t, err)

	pub := priv.Public()
	assert.Equal(t, uint32(2), pub.Levels())

	// Public key should round-trip through bytes.
	encoded := pub.ToBytes()
	decoded, err := hss.HssPublicKeyFromBytes(encoded)
	assert.NoError(t, err)
	assert.Equal(t, encoded, decoded.ToBytes())
}

func TestHssNewPrivateKeyRejectsBadInputs(t *testing.T) {
	lmsTypes, otsTypes := twoLevelTypes()

	// Empty levels.
	_, err := hss.NewPrivateKey(nil, nil)
	assert.Error(t, err)

	// Too many levels.
	tooMany := make([]common.LmsAlgorithmType, 9)
	tooManyOts := make([]common.LmsOtsAlgorithmType, 9)
	for i := range tooMany {
		tooMany[i] = common.LMS_SHA256_M32_H5
		tooManyOts[i] = common.LMOTS_SHA256_N32_W8
	}
	_, err = hss.NewPrivateKey(tooMany, tooManyOts)
	assert.Error(t, err)

	// Length mismatch.
	_, err = hss.NewPrivateKey(lmsTypes, otsTypes[:1])
	assert.Error(t, err)
}

func TestHssNewPrivateKeyFromSeedDeterministicTopPub(t *testing.T) {
	lmsTypes, otsTypes := twoLevelTypes()

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	var id common.ID
	for i := range id {
		id[i] = byte(i)
	}

	priv1, err := hss.NewPrivateKeyFromSeed(lmsTypes, otsTypes, id, seed)
	assert.NoError(t, err)
	priv2, err := hss.NewPrivateKeyFromSeed(lmsTypes, otsTypes, id, seed)
	assert.NoError(t, err)

	// Top-level (== HSS) public key must be identical across runs.
	pub1 := priv1.Public()
	pub2 := priv2.Public()
	assert.Equal(t, pub1.ToBytes(), pub2.ToBytes())
}

func TestHssSignVerifyL1(t *testing.T) {
	priv, err := hss.NewPrivateKey(
		[]common.LmsAlgorithmType{common.LMS_SHA256_M32_H5},
		[]common.LmsOtsAlgorithmType{common.LMOTS_SHA256_N32_W8},
	)
	assert.NoError(t, err)
	pub := priv.Public()

	msg := []byte("hello hss L=1")
	sig, err := priv.Sign(msg, nil)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), sig.Levels())

	assert.True(t, pub.Verify(msg, sig))

	// Tampering with the message must cause verification to fail.
	assert.False(t, pub.Verify([]byte("different"), sig))
}

func TestHssSignVerifyL2(t *testing.T) {
	lmsTypes, otsTypes := twoLevelTypes()
	priv, err := hss.NewPrivateKey(lmsTypes, otsTypes)
	assert.NoError(t, err)
	pub := priv.Public()

	msg := []byte("hello hss L=2")
	sig, err := priv.Sign(msg, nil)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), sig.Levels())

	assert.True(t, pub.Verify(msg, sig))
	assert.False(t, pub.Verify([]byte("tampered"), sig))
}

func TestHssVerifyRejectsWrongLevels(t *testing.T) {
	// Sign with L=2.
	lmsTypes, otsTypes := twoLevelTypes()
	priv, err := hss.NewPrivateKey(lmsTypes, otsTypes)
	assert.NoError(t, err)
	pub := priv.Public()

	msg := []byte("level mismatch")
	sig, err := priv.Sign(msg, nil)
	assert.NoError(t, err)

	// Re-package the signature claiming L=3 should fail to verify.
	mismatchedPub, err := hss.NewPublicKey(3, pub.LmsPublic())
	assert.NoError(t, err)
	assert.False(t, mismatchedPub.Verify(msg, sig))
}

func TestHssPrivateKeyRoundTrip(t *testing.T) {
	lmsTypes, otsTypes := twoLevelTypes()
	priv, err := hss.NewPrivateKey(lmsTypes, otsTypes)
	assert.NoError(t, err)

	// Sign once so we exercise non-zero q.
	_, err = priv.Sign([]byte("first"), nil)
	assert.NoError(t, err)

	encoded := priv.ToBytes()
	decoded, err := hss.HssPrivateKeyFromBytes(encoded)
	assert.NoError(t, err)

	// Public keys must match (top-level pub depends on top-level seed/id).
	origPub := priv.Public()
	decodedPub := decoded.Public()
	assert.Equal(t, origPub.ToBytes(), decodedPub.ToBytes())

	// Sign with the decoded key — verifies under the same public key, which
	// proves the entire chain (intermediate keys + signatures) was preserved.
	msg := []byte("second after reload")
	sig, err := decoded.Sign(msg, nil)
	assert.NoError(t, err)
	pubAfter := decoded.Public()
	assert.True(t, pubAfter.Verify(msg, sig))

	// Re-encoding a fresh decode (not the one we just Sign'd with) should
	// match the original bytes exactly.
	decoded2, err := hss.HssPrivateKeyFromBytes(encoded)
	assert.NoError(t, err)
	assert.Equal(t, encoded, decoded2.ToBytes())
}

func TestHssPrivateKeyFromBytesShort(t *testing.T) {
	for i := 0; i < 8; i++ {
		_, err := hss.HssPrivateKeyFromBytes(make([]byte, i))
		assert.Error(t, err)
	}
}

func TestHssRolloverRefreshesBottomTree(t *testing.T) {
	// L=2 with two H=5 trees: bottom can hold 2^5 = 32 signatures before
	// rollover. Signing 33 times forces one bottom-tree refresh.
	lmsTypes, otsTypes := twoLevelTypes()
	priv, err := hss.NewPrivateKey(lmsTypes, otsTypes)
	assert.NoError(t, err)
	pub := priv.Public()

	for i := 0; i < 33; i++ {
		msg := []byte(fmt.Sprintf("rollover msg %d", i))
		sig, err := priv.Sign(msg, nil)
		assert.NoError(t, err, "Sign failed at i=%d", i)
		assert.True(t, pub.Verify(msg, sig), "Verify failed at i=%d", i)
	}
}

func TestHssExhaustionReturnsError(t *testing.T) {
	// L=1 with H=5 -> 32 signatures total. The 33rd Sign call must error.
	priv, err := hss.NewPrivateKey(
		[]common.LmsAlgorithmType{common.LMS_SHA256_M32_H5},
		[]common.LmsOtsAlgorithmType{common.LMOTS_SHA256_N32_W8},
	)
	assert.NoError(t, err)

	for i := 0; i < 32; i++ {
		_, err := priv.Sign([]byte("msg"), nil)
		assert.NoError(t, err, "Sign unexpectedly failed at i=%d", i)
	}

	_, err = priv.Sign([]byte("one too many"), nil)
	assert.Error(t, err)
}

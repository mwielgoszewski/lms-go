package hss_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/hss"
	"github.com/trailofbits/lms-go/lms/lms"
)

// Build a single LMS signature usable as a fixture.
func fixtureLmsSig(t *testing.T) (lms.LmsSignature, lms.LmsPublicKey) {
	t.Helper()
	priv, err := lms.NewPrivateKey(common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W8)
	assert.NoError(t, err)
	sig, err := priv.Sign([]byte("fixture"), nil)
	assert.NoError(t, err)
	return sig, priv.Public()
}

func TestHssSignatureRoundTripL2(t *testing.T) {
	sig0, pub1 := fixtureLmsSig(t)
	sig1, _ := fixtureLmsSig(t)

	hssSig, err := hss.NewSignature(
		[]lms.LmsSignature{sig0, sig1},
		[]lms.LmsPublicKey{pub1},
	)
	assert.NoError(t, err)

	encoded, err := hssSig.ToBytes()
	assert.NoError(t, err)

	decoded, err := hss.HssSignatureFromBytes(encoded)
	assert.NoError(t, err)

	reEncoded, err := decoded.ToBytes()
	assert.NoError(t, err)
	assert.Equal(t, encoded, reEncoded)
}

func TestHssSignatureRoundTripL1(t *testing.T) {
	sig0, _ := fixtureLmsSig(t)

	hssSig, err := hss.NewSignature(
		[]lms.LmsSignature{sig0},
		nil,
	)
	assert.NoError(t, err)

	encoded, err := hssSig.ToBytes()
	assert.NoError(t, err)

	decoded, err := hss.HssSignatureFromBytes(encoded)
	assert.NoError(t, err)

	reEncoded, err := decoded.ToBytes()
	assert.NoError(t, err)
	assert.Equal(t, encoded, reEncoded)
}

func TestHssSignatureRejectsMismatchedLengths(t *testing.T) {
	sig0, pub1 := fixtureLmsSig(t)
	sig1, _ := fixtureLmsSig(t)

	// Two sigs but zero pubs -> would imply L=2 from sigs, L=1 from pubs.
	_, err := hss.NewSignature(
		[]lms.LmsSignature{sig0, sig1},
		nil,
	)
	assert.Error(t, err)

	// One sig but one pub -> can't form a valid chain.
	_, err = hss.NewSignature(
		[]lms.LmsSignature{sig0},
		[]lms.LmsPublicKey{pub1},
	)
	assert.Error(t, err)
}

func TestHssSignatureFromBytesShort(t *testing.T) {
	for i := 0; i < 8; i++ {
		_, err := hss.HssSignatureFromBytes(make([]byte, i))
		assert.Error(t, err)
	}
}

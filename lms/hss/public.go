package hss

import (
	"encoding/binary"
	"errors"

	"github.com/trailofbits/lms-go/lms/lms"
)

// MaxLevels is the inclusive upper bound on L permitted by RFC 8554 §6.
const MaxLevels uint32 = 8

// NewPublicKey constructs an HssPublicKey from the number of levels L
// and the top-level LMS public key.
func NewPublicKey(levels uint32, lmsPub lms.LmsPublicKey) (HssPublicKey, error) {
	if levels < 1 || levels > MaxLevels {
		return HssPublicKey{}, errors.New("NewPublicKey(): levels must be in [1, 8]")
	}
	return HssPublicKey{levels: levels, lmsPub: lmsPub}, nil
}

// Levels returns L.
func (pub *HssPublicKey) Levels() uint32 { return pub.levels }

// LmsPublic returns a copy of the top-level LMS public key.
func (pub *HssPublicKey) LmsPublic() lms.LmsPublicKey { return pub.lmsPub }

// ToBytes serializes the HSS public key as u32(L) || lms_public_key.
func (pub *HssPublicKey) ToBytes() []byte {
	var out []byte
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], pub.levels)
	out = append(out, be[:]...)
	out = append(out, pub.lmsPub.ToBytes()...)
	return out
}

// HssPublicKeyFromBytes parses the wire format produced by ToBytes.
func HssPublicKeyFromBytes(b []byte) (HssPublicKey, error) {
	if len(b) < 4 {
		return HssPublicKey{}, errors.New("HssPublicKeyFromBytes(): input too short")
	}
	levels := binary.BigEndian.Uint32(b[0:4])
	if levels < 1 || levels > MaxLevels {
		return HssPublicKey{}, errors.New("HssPublicKeyFromBytes(): invalid levels value")
	}
	lmsPub, err := lms.LmsPublicKeyFromBytes(b[4:])
	if err != nil {
		return HssPublicKey{}, err
	}
	return HssPublicKey{levels: levels, lmsPub: lmsPub}, nil
}

// Verify returns true iff sig is a valid HSS signature on msg under pub.
func (pub *HssPublicKey) Verify(msg []byte, sig HssSignature) bool {
	L := int(pub.levels)
	if len(sig.sigs) != L || len(sig.pubs) != L-1 {
		return false
	}

	current := pub.lmsPub
	for i := 0; i < L-1; i++ {
		nextPubBytes := sig.pubs[i].ToBytes()
		if !current.Verify(nextPubBytes, sig.sigs[i]) {
			return false
		}
		current = sig.pubs[i]
	}
	return current.Verify(msg, sig.sigs[L-1])
}

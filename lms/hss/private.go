package hss

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
)

// NewPrivateKey generates a fresh HSS private key with random seeds and IDs
// at every level. len(lmsTypes) must equal len(otsTypes) and be in [1, 8].
func NewPrivateKey(lmsTypes []common.LmsAlgorithmType, otsTypes []common.LmsOtsAlgorithmType) (HssPrivateKey, error) {
	L := uint32(len(lmsTypes))
	if L < 1 || L > MaxLevels {
		return HssPrivateKey{}, errors.New("NewPrivateKey(): levels must be in [1, 8]")
	}
	if uint32(len(otsTypes)) != L {
		return HssPrivateKey{}, errors.New("NewPrivateKey(): lmsTypes and otsTypes must have equal length")
	}

	keys := make([]lms.LmsPrivateKey, L)
	errs := make([]error, L)
	var wg sync.WaitGroup
	for i := uint32(0); i < L; i++ {
		wg.Add(1)
		go func(i uint32) {
			defer wg.Done()
			k, err := lms.NewPrivateKey(lmsTypes[i], otsTypes[i])
			if err != nil {
				errs[i] = err
				return
			}
			keys[i] = k
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return HssPrivateKey{}, e
		}
	}

	return assembleHssPrivateKey(L, lmsTypes, otsTypes, keys)
}

// NewPrivateKeyFromSeed generates an HSS private key whose top-level LMS key
// is derived deterministically from id and seed (via lms.NewPrivateKeyFromSeed).
// Lower-level LMS keys are generated with fresh randomness — they have to be,
// since they're refreshed on q rollover during signing, so determinism below
// the top level would defeat its purpose.
//
// The practical use is making the top-level public key reproducible from a
// stored seed. Sign output is non-deterministic regardless.
func NewPrivateKeyFromSeed(lmsTypes []common.LmsAlgorithmType, otsTypes []common.LmsOtsAlgorithmType, id common.ID, seed []byte) (HssPrivateKey, error) {
	L := uint32(len(lmsTypes))
	if L < 1 || L > MaxLevels {
		return HssPrivateKey{}, errors.New("NewPrivateKeyFromSeed(): levels must be in [1, 8]")
	}
	if uint32(len(otsTypes)) != L {
		return HssPrivateKey{}, errors.New("NewPrivateKeyFromSeed(): lmsTypes and otsTypes must have equal length")
	}

	keys := make([]lms.LmsPrivateKey, L)
	errs := make([]error, L)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		top, err := lms.NewPrivateKeyFromSeed(lmsTypes[0], otsTypes[0], id, seed)
		if err != nil {
			errs[0] = err
			return
		}
		keys[0] = top
	}()
	for i := uint32(1); i < L; i++ {
		wg.Add(1)
		go func(i uint32) {
			defer wg.Done()
			k, err := lms.NewPrivateKey(lmsTypes[i], otsTypes[i])
			if err != nil {
				errs[i] = err
				return
			}
			keys[i] = k
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return HssPrivateKey{}, e
		}
	}

	return assembleHssPrivateKey(L, lmsTypes, otsTypes, keys)
}

// assembleHssPrivateKey signs the chain that links keys[0..L-1] and returns
// the fully populated HssPrivateKey. The input keys slice is taken over.
func assembleHssPrivateKey(L uint32, lmsTypes []common.LmsAlgorithmType, otsTypes []common.LmsOtsAlgorithmType, keys []lms.LmsPrivateKey) (HssPrivateKey, error) {
	sigs := make([]lms.LmsSignature, L-1)
	for i := uint32(0); i < L-1; i++ {
		childPub := keys[i+1].Public()
		s, err := keys[i].Sign(childPub.ToBytes(), nil)
		if err != nil {
			return HssPrivateKey{}, err
		}
		sigs[i] = s
	}

	lt := make([]common.LmsAlgorithmType, L)
	copy(lt, lmsTypes)
	ot := make([]common.LmsOtsAlgorithmType, L)
	copy(ot, otsTypes)

	return HssPrivateKey{
		levels:   L,
		lmsTypes: lt,
		otsTypes: ot,
		keys:     keys,
		sigs:     sigs,
	}, nil
}

// Levels returns L.
func (priv *HssPrivateKey) Levels() uint32 { return priv.levels }

// Public returns the HSS public key, which is the top-level LMS public key
// plus L.
func (priv *HssPrivateKey) Public() HssPublicKey {
	return HssPublicKey{
		levels: priv.levels,
		lmsPub: priv.keys[0].Public(),
	}
}

// Sign signs msg with the HSS private key. The internal state advances: the
// bottom-level LMS q is incremented, and if it reaches 2^h_{L-1}, a fresh
// lower-level tree (or trees) is generated and re-signed by the next level up.
//
// Callers MUST persist priv.ToBytes() after every successful Sign before
// releasing the signature, and MUST NOT load the serialized key into two
// concurrent signers. Failure to do so is a security vulnerability.
//
// rng is optional; nil uses crypto/rand.Reader (matching lms.LmsPrivateKey).
func (priv *HssPrivateKey) Sign(msg []byte, rng io.Reader) (HssSignature, error) {
	L := int(priv.levels)

	bottomParams, err := priv.lmsTypes[L-1].LmsParams()
	if err != nil {
		return HssSignature{}, err
	}
	bottomCap := uint32(1) << bottomParams.H

	if priv.keys[L-1].Q() >= bottomCap {
		d := -1
		for i := 0; i < L; i++ {
			p, err := priv.lmsTypes[i].LmsParams()
			if err != nil {
				return HssSignature{}, err
			}
			if priv.keys[i].Q() < (uint32(1) << p.H) {
				d = i
				break
			}
		}
		if d == -1 {
			return HssSignature{}, errors.New("Sign(): HSS private key exhausted")
		}
		for i := d + 1; i < L; i++ {
			k, err := lms.NewPrivateKey(priv.lmsTypes[i], priv.otsTypes[i])
			if err != nil {
				return HssSignature{}, err
			}
			priv.keys[i] = k
		}
		for i := d; i < L-1; i++ {
			childPub := priv.keys[i+1].Public()
			s, err := priv.keys[i].Sign(childPub.ToBytes(), rng)
			if err != nil {
				return HssSignature{}, err
			}
			priv.sigs[i] = s
		}
	}

	finalSig, err := priv.keys[L-1].Sign(msg, rng)
	if err != nil {
		return HssSignature{}, err
	}

	sigs := make([]lms.LmsSignature, L)
	copy(sigs, priv.sigs)
	sigs[L-1] = finalSig

	pubs := make([]lms.LmsPublicKey, L-1)
	for i := 0; i < L-1; i++ {
		pubs[i] = priv.keys[i+1].Public()
	}

	return HssSignature{sigs: sigs, pubs: pubs}, nil
}

// ToBytes serializes the HSS private key as
//
//	u32(L) || lms_priv_bytes[0] || ... || lms_priv_bytes[L-1]
//	       || lms_sig_bytes[0]  || ... || lms_sig_bytes[L-2]
//
// Each lms_priv_bytes uses lms.LmsPrivateKey.ToBytes (which already encodes q).
// Each lms_sig_bytes uses lms.LmsSignature.ToBytes.
//
// This format is not specified by RFC 8554; it captures the full mutable
// state of an HSS private key for safe round-tripping.
func (priv *HssPrivateKey) ToBytes() []byte {
	var out []byte
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], priv.levels)
	out = append(out, be[:]...)

	for i := uint32(0); i < priv.levels; i++ {
		out = append(out, priv.keys[i].ToBytes()...)
	}
	for i := uint32(0); i < priv.levels-1; i++ {
		// LmsSignature.ToBytes only errors on a malformed typecode; sigs in
		// an HssPrivateKey always come from successful Sign calls so the
		// error is unreachable. Discard it to match the no-error signature
		// of lms.LmsPrivateKey.ToBytes.
		sigBytes, _ := priv.sigs[i].ToBytes()
		out = append(out, sigBytes...)
	}
	return out
}

// HssPrivateKeyFromBytes parses the wire format produced by ToBytes.
func HssPrivateKeyFromBytes(b []byte) (HssPrivateKey, error) {
	if len(b) < 4 {
		return HssPrivateKey{}, errors.New("HssPrivateKeyFromBytes(): input too short")
	}
	L := binary.BigEndian.Uint32(b[0:4])
	if L < 1 || L > MaxLevels {
		return HssPrivateKey{}, errors.New("HssPrivateKeyFromBytes(): invalid levels value")
	}

	pos := 4
	keys := make([]lms.LmsPrivateKey, L)
	lmsTypes := make([]common.LmsAlgorithmType, L)
	otsTypes := make([]common.LmsOtsAlgorithmType, L)
	for i := uint32(0); i < L; i++ {
		privLen, err := peekLmsPrivKeyLen(b[pos:])
		if err != nil {
			return HssPrivateKey{}, err
		}
		if uint64(len(b)-pos) < privLen {
			return HssPrivateKey{}, errors.New("HssPrivateKeyFromBytes(): truncated LMS private key")
		}
		k, err := lms.LmsPrivateKeyFromBytes(b[pos : pos+int(privLen)])
		if err != nil {
			return HssPrivateKey{}, err
		}
		keys[i] = k
		// Rebuild the type slices from the typecodes embedded in the private
		// key's serialized form.
		lmsTypes[i] = common.Uint32ToLmsType(binary.BigEndian.Uint32(b[pos : pos+4]))
		otsTypes[i] = common.Uint32ToLmotsType(binary.BigEndian.Uint32(b[pos+4 : pos+8]))
		pos += int(privLen)
	}

	sigs := make([]lms.LmsSignature, L-1)
	for i := uint32(0); i < L-1; i++ {
		sigLen, err := peekLmsSigLen(b[pos:])
		if err != nil {
			return HssPrivateKey{}, err
		}
		if uint64(len(b)-pos) < sigLen {
			return HssPrivateKey{}, errors.New("HssPrivateKeyFromBytes(): truncated intermediate signature")
		}
		s, err := lms.LmsSignatureFromBytes(b[pos : pos+int(sigLen)])
		if err != nil {
			return HssPrivateKey{}, err
		}
		sigs[i] = s
		pos += int(sigLen)
	}

	if pos != len(b) {
		return HssPrivateKey{}, errors.New("HssPrivateKeyFromBytes(): trailing bytes")
	}

	return HssPrivateKey{
		levels:   L,
		lmsTypes: lmsTypes,
		otsTypes: otsTypes,
		keys:     keys,
		sigs:     sigs,
	}, nil
}

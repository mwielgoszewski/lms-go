package hss

import (
	"encoding/binary"
	"errors"

	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
)

// NewSignature constructs an HssSignature. len(sigs) must be L and len(pubs)
// must be L-1, where L is in [1, MaxLevels].
func NewSignature(sigs []lms.LmsSignature, pubs []lms.LmsPublicKey) (HssSignature, error) {
	if len(sigs) < 1 || uint32(len(sigs)) > MaxLevels {
		return HssSignature{}, errors.New("NewSignature(): len(sigs) must be in [1, 8]")
	}
	if len(pubs) != len(sigs)-1 {
		return HssSignature{}, errors.New("NewSignature(): len(pubs) must equal len(sigs) - 1")
	}
	return HssSignature{sigs: sigs, pubs: pubs}, nil
}

// Levels returns L (== len(sig.sigs)).
func (sig *HssSignature) Levels() uint32 { return uint32(len(sig.sigs)) }

// ToBytes serializes the HSS signature as
//
//	u32(L-1) || (lms_sig[i] || lms_pub[i+1] for i in 0..L-2) || lms_sig[L-1]
func (sig *HssSignature) ToBytes() ([]byte, error) {
	L := len(sig.sigs)
	if L < 1 || L > int(MaxLevels) {
		return nil, errors.New("HssSignature.ToBytes(): invalid levels")
	}
	if len(sig.pubs) != L-1 {
		return nil, errors.New("HssSignature.ToBytes(): pubs/sigs length mismatch")
	}

	var out []byte
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], uint32(L-1))
	out = append(out, be[:]...)

	for i := 0; i < L-1; i++ {
		sigBytes, err := sig.sigs[i].ToBytes()
		if err != nil {
			return nil, err
		}
		out = append(out, sigBytes...)
		out = append(out, sig.pubs[i].ToBytes()...)
	}

	finalBytes, err := sig.sigs[L-1].ToBytes()
	if err != nil {
		return nil, err
	}
	out = append(out, finalBytes...)
	return out, nil
}

// HssSignatureFromBytes parses the wire format produced by ToBytes.
func HssSignatureFromBytes(b []byte) (HssSignature, error) {
	if len(b) < 4 {
		return HssSignature{}, errors.New("HssSignatureFromBytes(): input too short")
	}
	Nspk := binary.BigEndian.Uint32(b[0:4])
	if Nspk+1 < 1 || Nspk+1 > MaxLevels {
		return HssSignature{}, errors.New("HssSignatureFromBytes(): invalid Nspk")
	}
	L := int(Nspk) + 1

	pos := 4
	sigs := make([]lms.LmsSignature, L)
	pubs := make([]lms.LmsPublicKey, L-1)

	for i := 0; i < L-1; i++ {
		sigLen, err := peekLmsSigLen(b[pos:])
		if err != nil {
			return HssSignature{}, err
		}
		if uint64(len(b)-pos) < sigLen {
			return HssSignature{}, errors.New("HssSignatureFromBytes(): truncated signature")
		}
		s, err := lms.LmsSignatureFromBytes(b[pos : pos+int(sigLen)])
		if err != nil {
			return HssSignature{}, err
		}
		sigs[i] = s
		pos += int(sigLen)

		pubLen, err := peekLmsPubLen(b[pos:])
		if err != nil {
			return HssSignature{}, err
		}
		if uint64(len(b)-pos) < pubLen {
			return HssSignature{}, errors.New("HssSignatureFromBytes(): truncated public key")
		}
		p, err := lms.LmsPublicKeyFromBytes(b[pos : pos+int(pubLen)])
		if err != nil {
			return HssSignature{}, err
		}
		pubs[i] = p
		pos += int(pubLen)
	}

	sigLen, err := peekLmsSigLen(b[pos:])
	if err != nil {
		return HssSignature{}, err
	}
	if uint64(len(b)-pos) != sigLen {
		return HssSignature{}, errors.New("HssSignatureFromBytes(): trailing bytes or truncated final signature")
	}
	finalSig, err := lms.LmsSignatureFromBytes(b[pos : pos+int(sigLen)])
	if err != nil {
		return HssSignature{}, err
	}
	sigs[L-1] = finalSig

	return HssSignature{sigs: sigs, pubs: pubs}, nil
}

// peekLmsSigLen reads enough of b to determine the total length of the
// LmsSignature it begins with, without parsing the whole signature.
//
// An LmsSignature is laid out as:
//
//	u32(q) || u32(ots_typecode) || ots_sig[ots_siglen] || u32(lms_typecode) || path[h*m]
func peekLmsSigLen(b []byte) (uint64, error) {
	if len(b) < 8 {
		return 0, errors.New("peekLmsSigLen: input too short for OTS typecode")
	}
	otstc := common.Uint32ToLmotsType(binary.BigEndian.Uint32(b[4:8]))
	if _, err := otstc.LmsOtsType(); err != nil {
		return 0, err
	}
	otsSigLen, err := otstc.LmsOtsSigLength()
	if err != nil {
		return 0, err
	}
	lmsTypecodeOff := uint64(4) + otsSigLen
	if uint64(len(b)) < lmsTypecodeOff+4 {
		return 0, errors.New("peekLmsSigLen: input too short for LMS typecode")
	}
	lmstc := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[lmsTypecodeOff : lmsTypecodeOff+4]))
	if _, err := lmstc.LmsType(); err != nil {
		return 0, err
	}
	return lmstc.LmsSigLength(otstc)
}

// peekLmsPubLen reads the LMS typecode at the start of b and returns the
// total LmsPublicKey byte length.
//
// An LmsPublicKey is laid out as:
//
//	u32(lms_typecode) || u32(ots_typecode) || id[16] || k[m]
func peekLmsPubLen(b []byte) (uint64, error) {
	if len(b) < 4 {
		return 0, errors.New("peekLmsPubLen: input too short")
	}
	lmstc := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[0:4]))
	if _, err := lmstc.LmsType(); err != nil {
		return 0, err
	}
	params, err := lmstc.LmsParams()
	if err != nil {
		return 0, err
	}
	return 24 + params.M, nil
}

// peekLmsPrivKeyLen returns the total LmsPrivateKey byte length given a
// buffer starting with the serialized key.
//
// An LmsPrivateKey is laid out as:
//
//	u32(lms_typecode) || u32(ots_typecode) || u32(q) || id[16] || seed[m]
func peekLmsPrivKeyLen(b []byte) (uint64, error) {
	if len(b) < 4 {
		return 0, errors.New("peekLmsPrivKeyLen: input too short")
	}
	lmstc := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[0:4]))
	if _, err := lmstc.LmsType(); err != nil {
		return 0, err
	}
	params, err := lmstc.LmsParams()
	if err != nil {
		return 0, err
	}
	return 28 + params.M, nil
}

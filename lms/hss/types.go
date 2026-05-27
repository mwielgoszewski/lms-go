// Package hss implements the Hierarchical Signature System (HSS) defined in
// RFC 8554, Section 6. HSS composes multiple LMS trees into a single signature
// scheme that can sign 2^(h_0 + h_1 + ... + h_{L-1}) messages under one
// top-level public key.
package hss

import (
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/lms"
)

// HssPrivateKey is the stateful HSS signing key. It owns one LMS private key
// per level (0..L-1) and the cached intermediate signatures that link each
// level's public key to the level above. Callers MUST persist ToBytes() after
// every successful Sign before releasing the signature.
type HssPrivateKey struct {
	levels   uint32
	lmsTypes []common.LmsAlgorithmType
	otsTypes []common.LmsOtsAlgorithmType
	keys     []lms.LmsPrivateKey
	sigs     []lms.LmsSignature
}

// HssPublicKey is the HSS public key: the number of levels L and the
// top-level LMS public key.
type HssPublicKey struct {
	levels uint32
	lmsPub lms.LmsPublicKey
}

// HssSignature carries the chain of LMS signatures plus the intermediate
// LMS public keys needed to verify the message under the HSS public key.
//
// Invariants: len(sigs) == L and len(pubs) == L-1. sigs[0..L-2] sign the
// next level's public key; sigs[L-1] signs the message.
type HssSignature struct {
	sigs []lms.LmsSignature
	pubs []lms.LmsPublicKey
}

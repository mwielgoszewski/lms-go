package lms

import (
	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"
)

// A LmsPrivateKey is used to sign a finite number of messages.
//
// authtree is the Merkle tree as one contiguous []byte; node T[r] (RFC 8554,
// 1-based) lives at authtree[(r-1)*nodeStride : (r-1)*nodeStride+nodeWidth].
type LmsPrivateKey struct {
	typecode   common.LmsAlgorithmType
	otstype    common.LmsOtsAlgorithmType
	q          uint32
	id         common.ID
	seed       []byte
	authtree   []byte
	nodeStride int
	nodeWidth  int
}

func (priv *LmsPrivateKey) authNode(idx uint32) []byte {
	off := int(idx) * priv.nodeStride
	return priv.authtree[off : off+priv.nodeWidth : off+priv.nodeStride]
}

// A LmsPublicKey is used to verify messages signed by a LmsPrivateKey
type LmsPublicKey struct {
	typecode common.LmsAlgorithmType
	otstype  common.LmsOtsAlgorithmType
	id       common.ID
	k        []byte
}

// A LmsSignature represents a signature produced by an LmsPrivateKey
// which an LmsPublicKey can validate for a given message
type LmsSignature struct {
	typecode common.LmsAlgorithmType
	q        uint32
	ots      ots.LmsOtsSignature
	path     [][]byte
}

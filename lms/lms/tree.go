package lms

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/trailofbits/lms-go/lms/common"
)

// AuthenticationTree is an immutable, shareable Merkle tree. It contains no
// private seed or signing counter. Its key-material digest prevents accidental
// reuse with another key; it is not a replacement for durable counter storage.
// Obtain one from LmsPrivateKey.AuthenticationTree; its zero value is invalid.
type AuthenticationTree struct {
	nodes    []byte
	identity [sha256.Size]byte
	stride   int
	width    int
}

// Size returns the number of bytes of tree backing memory retained by t.
func (t *AuthenticationTree) Size() int64 { return int64(len(t.nodes)) }

// AuthenticationTree returns a read-only handle sharing this key's tree.
// The handle can outlive the private key and be reused concurrently by keys
// restored from independently reserved counters.
func (priv *LmsPrivateKey) AuthenticationTree() *AuthenticationTree {
	return &AuthenticationTree{
		nodes:    priv.authtree,
		identity: treeIdentity(priv.typecode, priv.otstype, priv.id, priv.seed),
		stride:   priv.nodeStride,
		width:    priv.nodeWidth,
	}
}

func treeIdentity(tc common.LmsAlgorithmType, ot common.LmsOtsAlgorithmType, id common.ID, seed []byte) [sha256.Size]byte {
	h := sha256.New()
	lmsType, _ := tc.LmsType()
	otsType, _ := ot.LmsOtsType()
	var algorithms [8]byte
	binary.BigEndian.PutUint32(algorithms[:4], lmsType.ToUint32())
	binary.BigEndian.PutUint32(algorithms[4:], otsType.ToUint32())
	_, _ = h.Write(algorithms[:])
	_, _ = h.Write(id[:])
	_, _ = h.Write(seed)
	var identity [sha256.Size]byte
	h.Sum(identity[:0])
	return identity
}

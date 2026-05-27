// Package lms implements Leighton-Micali Hash-Based Signatures (RFC 8554)
//
// This file implements the private key and signing logic.
package lms

import (
	"encoding/binary"
	"errors"
	"hash"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/trailofbits/lms-go/lms/common"
	"github.com/trailofbits/lms-go/lms/ots"

	"crypto/rand"
	"io"
)

// NewPrivateKey returns a LmsPrivateKey, seeded by a cryptographically secure
// random number generator.
func NewPrivateKey(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType) (LmsPrivateKey, error) {
	var err error
	tc, err = tc.LmsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	params, err := tc.LmsParams()
	if err != nil {
		return LmsPrivateKey{}, err
	}

	seed := make([]byte, params.M)
	_, err = rand.Read(seed)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	idbytes := make([]byte, common.ID_LEN)
	_, err = rand.Read(idbytes)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	id := common.ID(idbytes)

	return NewPrivateKeyFromSeed(tc, otstc, id, seed)
}

// NewPrivateKeyFromSeed returns a new LmsPrivateKey, using the algorithm from
// Appendix A of <https://datatracker.ietf.org/doc/html/rfc8554#appendix-A>
func NewPrivateKeyFromSeed(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType, id common.ID, seed []byte) (LmsPrivateKey, error) {
	tc, err := tc.LmsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	otstc, err = otstc.LmsOtsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	tree, err := GeneratePKTree(tc, otstc, id, seed)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	return LmsPrivateKey{
		typecode: tc,
		otstype:  otstc,
		q:        0,
		id:       id,
		seed:     seed,
		authtree: tree,
	}, nil
}

// Public returns an LmsPublicKey that validates signatures for this private key
func (priv *LmsPrivateKey) Public() LmsPublicKey {
	return LmsPublicKey{
		typecode: priv.typecode,
		otstype:  priv.otstype,
		id:       priv.id,
		k:        priv.authtree[0],
	}
}

// Sign calculates the LMS signature of a chosen message.
// The rng argument is optional. If nil is provided, crypto/rand.Reader will be used.
func (priv *LmsPrivateKey) Sign(msg []byte, rng io.Reader) (LmsSignature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	params, err := priv.typecode.LmsParams()
	if err != nil {
		return LmsSignature{}, err
	}
	height := int(params.H)
	var leaves uint32 = 1 << height
	if priv.q >= leaves {
		return LmsSignature{}, errors.New("Sign(): invalid private key")
	}
	// ots_params := ots_tc.Params()
	ots_priv, err := ots.NewPrivateKeyFromSeed(priv.otstype, priv.q, priv.id, priv.seed)
	if err != nil {
		return LmsSignature{}, err
	}
	ots_sig, err := ots_priv.Sign(msg, rng)
	if err != nil {
		return LmsSignature{}, err
	}
	authpath := make([][]byte, params.H)

	var r uint32 = leaves + priv.q
	var temp uint32
	for i := 0; i < height; i++ {
		temp = (r >> i) ^ 1
		// We use x-1 because T[x] is indexed from 1, not 0, in the spec
		authpath[i] = priv.authtree[temp-1][:]
	}

	// We incremenet q to signal the this keys should not be reused
	priv.incrementQ()

	return LmsSignature{
		priv.typecode,
		priv.q - 1,
		ots_sig,
		authpath,
	}, nil
}

// Private
func (priv *LmsPrivateKey) incrementQ() {
	priv.q++
}

// ToBytes() serialized the private key into a byte string for storage.
// The current value of the internal counter, q, is included.
func (priv *LmsPrivateKey) ToBytes() []byte {
	var serialized []byte
	var u32_be [4]byte

	// First 4 bytes: typecode
	typecode, _ := priv.typecode.LmsType()
	// ToBytes() is only ever called on a valid object, so this will never return an error
	binary.BigEndian.PutUint32(u32_be[:], typecode.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 4 bytes: OTS typecode
	otstype, _ := priv.otstype.LmsOtsType()
	// ToBytes() is only ever called on a valid object, so this will never return an error
	binary.BigEndian.PutUint32(u32_be[:], otstype.ToUint32())
	serialized = append(serialized, u32_be[:]...)

	// Next 4 bytes: q
	binary.BigEndian.PutUint32(u32_be[:], priv.q)
	serialized = append(serialized, u32_be[:]...)

	// Next 16 bytes: id
	serialized = append(serialized, priv.id[:]...)

	// Next 32 bytes: seed
	serialized = append(serialized, priv.seed[:]...)

	// We don't need to serialize the authtree
	return serialized
}

// Retrieve the current value of the internal counter, q.
// Used for unit tests
func (priv *LmsPrivateKey) Q() uint32 {
	return priv.q
}

// LmsPrivateKeyFromBytes returns an LmsPrivateKey that represents b.
// This is the inverse of the ToBytes() method on the LmsPrivateKey object.
func LmsPrivateKeyFromBytes(b []byte) (LmsPrivateKey, error) {
	if len(b) < 8 {
		return LmsPrivateKey{}, errors.New("LmsPrivateKeyFromBytes(): Input is too short")
	}

	// The typecode is bytes 0-3 (4 bytes)
	typecode, err := common.Uint32ToLmsType(binary.BigEndian.Uint32(b[0:4])).LmsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	// The OTS typecode is bytes 4-7 (4 bytes)
	otstype, err := common.Uint32ToLmotsType(binary.BigEndian.Uint32(b[4:8])).LmsOtsType()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	lmsparams, err := typecode.LmsParams()
	if err != nil {
		return LmsPrivateKey{}, err
	}
	if len(b) < int(lmsparams.M+28) {
		return LmsPrivateKey{}, errors.New("LmsPrivateKeyFromBytes(): Input is too short")
	}

	// Internal counter is bytes 8-11 (4 bytes)
	q := binary.BigEndian.Uint32(b[8:12])
	// ID is bytes 12-27 (16 bytes)
	id := common.ID(b[12:28])
	// Seed is bytes 28+ (32 bytes for SHA-256)
	seed_end := lmsparams.M + 28
	seed := b[28:seed_end]

	// Load private key, then set q to what was persisted
	privateKey, err := NewPrivateKeyFromSeed(typecode, otstype, id, seed)
	if err != nil {
		return LmsPrivateKey{}, err
	}
	privateKey.q = q
	return privateKey, nil
}

// leafHash computes the LMS Merkle leaf for tree index r = leaves+i, writing
// the first otsParams.N bytes of the result into dst. The chain step inputs
// are pre-staged into inputBuf so each inner hash takes a single Write; the
// caller owns the hashers and scratch buffers so they can be reused across
// many leaves.
func leafHash(
	otsParams common.LmsOtsParam,
	leafIdx, r uint32,
	id common.ID,
	seed []byte,
	outerHasher, innerHasher, leafHasher hash.Hash,
	chainBuf, inputBuf, dst []byte,
) {
	n := int(otsParams.N)
	seedLen := len(seed)
	chainEnd := (uint64(1) << int(otsParams.W.Window())) - 1

	var rBE [4]byte

	copy(inputBuf[0:16], id[:])
	binary.BigEndian.PutUint32(inputBuf[16:20], leafIdx)
	binary.BigEndian.PutUint32(rBE[:], r)

	outerHasher.Reset()
	common.HashWrite(outerHasher, inputBuf[0:20])
	common.HashWrite(outerHasher, common.D_PBLC[:])

	seedSlice := inputBuf[:23+seedLen]
	chainSlice := inputBuf[:23+n]
	sumDst := inputBuf[23:23]
	for chainI := uint64(0); chainI < otsParams.P; chainI++ {
		binary.BigEndian.PutUint16(inputBuf[20:22], uint16(chainI))

		inputBuf[22] = 0xff
		copy(inputBuf[23:23+seedLen], seed)
		innerHasher.Reset()
		common.HashWrite(innerHasher, seedSlice)
		innerHasher.Sum(sumDst)

		for j := uint64(0); j < chainEnd; j++ {
			inputBuf[22] = byte(j)
			innerHasher.Reset()
			common.HashWrite(innerHasher, chainSlice)
			innerHasher.Sum(sumDst)
		}

		common.HashWrite(outerHasher, inputBuf[23:23+n])
	}

	outerHasher.Sum(chainBuf[:0])

	leafHasher.Reset()
	common.HashWrite(leafHasher, id[:])
	common.HashWrite(leafHasher, rBE[:])
	common.HashWrite(leafHasher, common.D_LEAF[:])
	common.HashWrite(leafHasher, chainBuf[:n])
	leafHasher.Sum(dst[:0])
}

// GeneratePKTree generates the Merkle Tree needed to derive the public key and
// authentication path for any message.
func GeneratePKTree(tc common.LmsAlgorithmType, otstc common.LmsOtsAlgorithmType, id common.ID, seed []byte) ([][]byte, error) {
	params, err := tc.LmsParams()
	if err != nil {
		return nil, err
	}
	ots_params, err := otstc.Params()
	if err != nil {
		return nil, err
	}

	tree_nodes := uint32(1)<<(params.H+1) - 1
	leaves := uint32(1) << params.H

	fullDigest := ots_params.H.New().Size()
	n := int(ots_params.N)
	treeBacking := make([]byte, int(tree_nodes)*fullDigest)
	authtree := make([][]byte, tree_nodes)
	for i := uint32(0); i < tree_nodes; i++ {
		off := int(i) * fullDigest
		authtree[i] = treeBacking[off : off+n : off+fullDigest]
	}

	workers := runtime.NumCPU()
	if uint32(workers) > leaves {
		workers = int(leaves)
	}
	if workers < 1 {
		workers = 1
	}

	var firstErr atomic.Value // stores error
	var wg sync.WaitGroup
	chunk := (leaves + uint32(workers) - 1) / uint32(workers)
	for w := 0; w < workers; w++ {
		start := uint32(w) * chunk
		if start >= leaves {
			break
		}
		end := start + chunk
		if end > leaves {
			end = leaves
		}
		wg.Add(1)
		go func(start, end uint32) {
			defer wg.Done()
			outer := ots_params.H.New()
			inner := ots_params.H.New()
			leaf := ots_params.H.New()
			chainBuf := make([]byte, fullDigest)
			inputCap := 23 + fullDigest
			if 23+len(seed) > inputCap {
				inputCap = 23 + len(seed)
			}
			inputBuf := make([]byte, inputCap)
			for i := start; i < end; i++ {
				if firstErr.Load() != nil {
					return
				}
				r := i + leaves
				leafHash(ots_params, i, r, id, seed,
					outer, inner, leaf, chainBuf, inputBuf, authtree[r-1])
			}
		}(start, end)
	}
	wg.Wait()
	if e := firstErr.Load(); e != nil {
		return nil, e.(error)
	}

	const parallelThreshold = 1024
	for level := int(params.H) - 1; level >= 0; level-- {
		levelNodes := uint32(1) << uint(level)
		rBase := uint32(1) << uint(level)

		if levelNodes < parallelThreshold {
			var r_be [4]byte
			hasher := ots_params.H.New()
			for idx := uint32(0); idx < levelNodes; idx++ {
				r := rBase + idx
				binary.BigEndian.PutUint32(r_be[:], r)
				hasher.Reset()
				common.HashWrite(hasher, id[:])
				common.HashWrite(hasher, r_be[:])
				common.HashWrite(hasher, common.D_INTR[:])
				common.HashWrite(hasher, authtree[2*r-1])
				common.HashWrite(hasher, authtree[2*r])
				hasher.Sum(authtree[r-1][:0])
			}
			continue
		}

		levelWorkers := workers
		if uint32(levelWorkers) > levelNodes {
			levelWorkers = int(levelNodes)
		}
		levelChunk := (levelNodes + uint32(levelWorkers) - 1) / uint32(levelWorkers)
		var lwg sync.WaitGroup
		for w := 0; w < levelWorkers; w++ {
			start := uint32(w) * levelChunk
			if start >= levelNodes {
				break
			}
			end := start + levelChunk
			if end > levelNodes {
				end = levelNodes
			}
			lwg.Add(1)
			go func(start, end uint32) {
				defer lwg.Done()
				var r_be [4]byte
				hasher := ots_params.H.New()
				for idx := start; idx < end; idx++ {
					r := rBase + idx
					binary.BigEndian.PutUint32(r_be[:], r)
					hasher.Reset()
					common.HashWrite(hasher, id[:])
					common.HashWrite(hasher, r_be[:])
					common.HashWrite(hasher, common.D_INTR[:])
					common.HashWrite(hasher, authtree[2*r-1])
					common.HashWrite(hasher, authtree[2*r])
					hasher.Sum(authtree[r-1][:0])
				}
			}(start, end)
		}
		lwg.Wait()
	}

	return authtree, nil
}

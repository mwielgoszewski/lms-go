package lms

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trailofbits/lms-go/lms/common"
)

// A cached tree must restore the persisted counter, never the counter of the
// key that originally built it, and must produce signatures for the same root.
func TestAuthenticationTreeReuse(t *testing.T) {
	for _, tc := range []common.LmsAlgorithmType{common.LMS_SHA256_M32_H5, common.LMS_SHA256_M24_H5} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			ot := common.LMOTS_SHA256_N32_W4
			if tc == common.LMS_SHA256_M24_H5 {
				ot = common.LMOTS_SHA256_N24_W4
			}
			original, err := NewPrivateKey(tc, ot)
			require.NoError(t, err)
			public := original.Public()
			tree := original.AuthenticationTree()
			require.Equal(t, int64(2016), tree.Size()) // 63 nodes * 32-byte stride
			serialized := original.ToBytes()
			for q := uint32(0); q < 32; q++ {
				restored, err := LmsPrivateKeyFromBytesWithTree(context.Background(), serialized, tree)
				require.NoError(t, err)
				require.Equal(t, q, restored.Q())
				require.Same(t, &original.authtree[0], &restored.authtree[0], "must reuse backing memory")
				sig, err := restored.Sign([]byte("message"), nil)
				require.NoError(t, err)
				require.True(t, public.Verify([]byte("message"), sig))
				serialized = restored.ToBytes()
			}
			exhausted, err := LmsPrivateKeyFromBytesWithTree(context.Background(), serialized, tree)
			require.NoError(t, err)
			_, err = exhausted.Sign(nil, nil)
			require.Error(t, err)
		})
	}
}

func TestAuthenticationTreeRejectsDifferentKey(t *testing.T) {
	key, err := NewPrivateKey(common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W4)
	require.NoError(t, err)
	tree := key.AuthenticationTree()
	for _, offset := range []int{3, 7, 12, 28} {
		b := key.ToBytes()
		b[offset]++ // LMS algorithm (H5 -> H10), OTS algorithm, ID, or seed
		_, err := LmsPrivateKeyFromBytesWithTree(context.Background(), b, tree)
		require.Error(t, err, "offset %d", offset)
	}
	_, err = LmsPrivateKeyFromBytesWithTree(context.Background(), key.ToBytes(), &AuthenticationTree{})
	require.Error(t, err)
	b := key.ToBytes()
	binary.BigEndian.PutUint32(b[8:12], 33)
	_, err = LmsPrivateKeyFromBytesWithTree(context.Background(), b, tree)
	require.Error(t, err)
}

func TestAuthenticationTreeCannotBeMutatedThroughPublicKey(t *testing.T) {
	seed := bytes.Repeat([]byte{42}, 32)
	key, err := NewPrivateKeyFromSeed(common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W4, common.ID{}, seed)
	require.NoError(t, err)
	public := key.Public()
	expected := public.ToBytes()
	public.Key()[0] ^= 1
	seed[0] ^= 1
	restored, err := LmsPrivateKeyFromBytesWithTree(context.Background(), key.ToBytes(), key.AuthenticationTree())
	require.NoError(t, err)
	public = restored.Public()
	require.Equal(t, expected, public.ToBytes())
	sig, err := restored.Sign([]byte("message"), nil)
	require.NoError(t, err)
	require.True(t, public.Verify([]byte("message"), sig))
}

func TestTreeConstructionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewPrivateKeyContext(ctx, common.LMS_SHA256_M32_H20, common.LMOTS_SHA256_N32_W8)
	require.ErrorIs(t, err, context.Canceled)
	// An H20/W8 build takes much longer than this deadline. Workers must stop
	// during construction, rather than finishing the tree after cancellation.
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = NewPrivateKeyContext(ctx, common.LMS_SHA256_M32_H20, common.LMOTS_SHA256_N32_W8)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
	require.Less(t, time.Since(start), 5*time.Second)
}

// Every worker owns exactly one preallocated index. Signing twice from any
// restored object would exceed that worker's reservation, even though the
// library's counter has room to advance.
func TestAuthenticationTreeConcurrentReservedIndices(t *testing.T) {
	for _, tc := range []common.LmsAlgorithmType{common.LMS_SHA256_M32_H5, common.LMS_SHA256_M24_H5} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			ot := common.LMOTS_SHA256_N32_W4
			if tc == common.LMS_SHA256_M24_H5 {
				ot = common.LMOTS_SHA256_N24_W4
			}
			key, err := NewPrivateKey(tc, ot)
			require.NoError(t, err)
			public := key.Public()
			tree := key.AuthenticationTree()
			before := append([]byte(nil), tree.nodes...)
			const workers = 32
			// Stand in for the caller's completed durable reservation of [0, 32).
			// Each worker gets a separate serialization with its assigned index.
			inputs := make([][]byte, workers)
			for i := range inputs {
				inputs[i] = key.ToBytes()
				binary.BigEndian.PutUint32(inputs[i][8:12], uint32(i))
			}
			sigs := make([]LmsSignature, workers)
			errs := make([]error, workers)
			var wg sync.WaitGroup
			for i := range inputs {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					restored, err := LmsPrivateKeyFromBytesWithTree(context.Background(), inputs[i], tree)
					if err != nil {
						errs[i] = err
						return
					}
					sigs[i], errs[i] = restored.Sign([]byte(fmt.Sprint("message-", i)), nil)
				}(i)
			}
			wg.Wait()
			for i, sig := range sigs {
				require.NoError(t, errs[i])
				require.Equal(t, uint32(i), sig.q)
				require.True(t, public.Verify([]byte(fmt.Sprint("message-", i)), sig))
			}
			require.Equal(t, before, tree.nodes, "signing must not mutate the shared tree")
		})
	}
}

func TestRestoredKeyOwnsSerializedInput(t *testing.T) {
	key, err := NewPrivateKey(common.LMS_SHA256_M32_H5, common.LMOTS_SHA256_N32_W4)
	require.NoError(t, err)
	public := key.Public()
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprint("cached=", cached), func(t *testing.T) {
			encoded := key.ToBytes()
			q := uint32(0)
			if cached {
				q = 1
			} // disjoint indices for the same key
			binary.BigEndian.PutUint32(encoded[8:12], q)
			var tree *AuthenticationTree
			if cached {
				tree = key.AuthenticationTree()
			}
			restored, err := LmsPrivateKeyFromBytesWithTree(context.Background(), encoded, tree)
			require.NoError(t, err)
			for i := range encoded {
				encoded[i] ^= 0xff
			}
			sig, err := restored.Sign([]byte("message"), nil)
			require.NoError(t, err)
			require.Equal(t, q, sig.q)
			require.True(t, public.Verify([]byte("message"), sig))
		})
	}
}

// Signatures must not retain or alias the entire tree after a cache eviction.
// Mutating a signature path here uses package-private access deliberately:
// an alias would both pin the backing allocation and corrupt other signers.
func TestSignatureOwnsAuthenticationPath(t *testing.T) {
	for _, tc := range []common.LmsAlgorithmType{common.LMS_SHA256_M32_H5, common.LMS_SHA256_M24_H5} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			ot := common.LMOTS_SHA256_N32_W4
			if tc == common.LMS_SHA256_M24_H5 {
				ot = common.LMOTS_SHA256_N24_W4
			}
			key, err := NewPrivateKey(tc, ot)
			require.NoError(t, err)
			public := key.Public()
			before := append([]byte(nil), key.authtree...)
			sig, err := key.Sign([]byte("first"), nil)
			require.NoError(t, err)
			require.True(t, public.Verify([]byte("first"), sig))
			for _, node := range sig.path {
				for i := range node {
					node[i] ^= 0xff
				}
			}
			require.Equal(t, before, key.authtree, "signature paths must not alias tree memory")
			next, err := key.Sign([]byte("second"), nil)
			require.NoError(t, err)
			require.True(t, public.Verify([]byte("second"), next))
		})
	}
}

package ed_ristretto

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"bytes"
)

func TestCombine(testing *testing.T) {
	t := 2
	n := 5

	var secret, _ = NewRandomScalarBytes()

	ids := make([][32]byte, n)
	var temId [32]byte
	for i := 0; i < n; i++ {
		temId, _ = NewRandomScalarBytes()
		ids[i] = temId
	}

	// input: secret [32]byte, ids [][32]byte, t int, n int
	// cotput: cfs, cfsBBytes, shares, error : [][32]byte, [][32]byte, [][32]byte, error
	_, cfsBBytes, shares, _ := Vss(secret, ids, t, n)

	// input: share [32]byte, id [32]byte, cfsBBytes [][32]byte
	// output: bool
	testing.Log("share value and check")
	for i := 0; i < n; i++ {
		assert.True(testing, VerifyVss(shares[i], ids[i], cfsBBytes), "failed to verify the share")
	}

	// intput: shares [][32]byte, ids [][32]byte
	// output: secret: [32]byte
	testing.Log("Combine(shares[:], ids[:])")
	secretRecover := Combine(shares[:], ids[:])
	assert.True(testing, bytes.Equal(secretRecover[:], secret[:]), "failed to recover the secret")
}

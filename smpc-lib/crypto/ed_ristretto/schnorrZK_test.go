package ed_ristretto

import (
	"github.com/stretchr/testify/assert"
	r255 "github.com/gtank/ristretto255"
	"testing"
)

func TestVerify_zk(t *testing.T) {
	sk, err := NewRandomScalar()
	assert.Nil(t, err, "error in key generation")
	pk := new(r255.Element).ScalarBaseMult(sk)

	var skBytes, pkBytes [32]byte
	sk.Encode(skBytes[:0])
	pk.Encode(pkBytes[:0])

	sig, err := Prove2(skBytes, pkBytes)
	assert.Nil(t, err, "error in prove")

	rlt := VerifyZk2(sig, pkBytes)
	assert.True(t, rlt, "failed to verify the proof")
}



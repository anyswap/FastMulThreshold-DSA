package ec2_test

import (
    	"testing"
	"github.com/stretchr/testify/assert"
	"math/big"

	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
)

var (
    testNtildeLength = 2048
    testPaillierKeyLength = 2048
)

func TestMtAZK2Verify_nhh(t *testing.T) {
    publicKey,privateKey := ec2.CreatPair(testPaillierKeyLength)
    assert.NotZero(t, publicKey)
    assert.NotZero(t, privateKey)
    nt,_,_,_,_ := ec2.CreateNt(testNtildeLength)
    assert.NotZero(t, nt)
    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(testPaillierKeyLength-testPaillierKeyLength/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    beta1U1Star := random.GetRandomIntFromZn(NSubN2)
    beta1U1StarCipher, u1BetaR1, _ := publicKey.Encrypt(beta1U1Star)
    u1Gamma := random.GetRandomIntFromZn(secp256k1.S256().N)
    u1K := random.GetRandomIntFromZn(secp256k1.S256().N)
    u1KCipher,_,_ := publicKey.Encrypt(u1K)
    u1KGamma1Cipher := publicKey.HomoMul(u1KCipher,u1Gamma)
    u1KGamma1Cipher = publicKey.HomoAdd(u1KGamma1Cipher,beta1U1StarCipher)
    u1u1MtAZK2Proof := ec2.MtAZK2Prove_nhh(u1Gamma, beta1U1Star, u1BetaR1, u1KCipher,publicKey,nt)
    assert.NotZero(t, u1u1MtAZK2Proof)
    ret := u1u1MtAZK2Proof.MtAZK2Verify_nhh(u1KCipher,u1KGamma1Cipher,publicKey,nt)
    assert.True(t,ret, "must be true")
}



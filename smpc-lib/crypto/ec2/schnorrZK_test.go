/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  changxing@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package ec2_test

import (
    	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"

	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
)

//------------------------------------------------------------------------------------

func TestZkUProveVerify(t *testing.T) {
    u1 := random.GetRandomIntFromZn(secp256k1.S256().N)
    u1zkUProof := ec2.ZkUProve(u1)
    assert.NotZero(t,u1zkUProof)
    u1Gx, u1Gy := secp256k1.S256().ScalarBaseMult(u1.Bytes())
    u1Secrets := make([]*big.Int, 0)
    u1Secrets = append(u1Secrets, u1Gx)
    u1Secrets = append(u1Secrets, u1Gy)
    
    _, u1PolyG, err := ec2.Vss2Init(u1,3)
    assert.NoError(t, err)

    for i := 1; i < len(u1PolyG.PolyG); i++ {
	    u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
	    u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
    }
    commitU1G := new(ec2.Commitment).Commit(u1Secrets...)
    ret, u1G := commitU1G.DeCommit()
    assert.True(t,ret)
    ret = ec2.ZkUVerify(u1G,u1zkUProof)
    assert.True(t,ret)
}

func TestZkABProveVerify(t *testing.T) {
    R,_ := new(big.Int).SetString("35468357718756002954848554035419648178117006496146773150503256230137374067079",10)
    Ry,_ := new(big.Int).SetString("39760012708593904645408329800877740105757428181833470179812638710757067153451",10)
    us1,_ := new(big.Int).SetString("81707785328668160358118153656797582185187660511375257112006130025606702292686",10)
    
    l1 := random.GetRandomIntFromZn(secp256k1.S256().N)
    rho1 := random.GetRandomIntFromZn(secp256k1.S256().N)
    bigV1x, bigV1y := secp256k1.S256().ScalarMult(R, Ry, us1.Bytes())
    l1Gx, l1Gy := secp256k1.S256().ScalarBaseMult(l1.Bytes())
    bigV1x, bigV1y = secp256k1.S256().Add(bigV1x, bigV1y, l1Gx, l1Gy)

    bigA1x, bigA1y := secp256k1.S256().ScalarBaseMult(rho1.Bytes())

    l1rho1 := new(big.Int).Mul(l1, rho1)
    l1rho1 = new(big.Int).Mod(l1rho1, secp256k1.S256().N)
    bigB1x, bigB1y := secp256k1.S256().ScalarBaseMult(l1rho1.Bytes())

    commitBigVAB1 := new(ec2.Commitment).Commit(bigV1x, bigV1y, bigA1x, bigA1y, bigB1x, bigB1y)
    ret, BigVAB1 := commitBigVAB1.DeCommit()
    assert.True(t,ret)

    u1zkABProof := ec2.ZkABProve(rho1, l1, us1, []*big.Int{R, Ry})
    assert.NotZero(t,u1zkABProof)
    ret = ec2.ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{R,Ry},u1zkABProof)
    assert.True(t,ret)
}




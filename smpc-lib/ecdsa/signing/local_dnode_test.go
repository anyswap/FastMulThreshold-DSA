/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
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

// Package signing_test test MPC implementation of signing 
package signing_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/signing"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
)

func TestCheckFull(t *testing.T) {
    signSigniMessages := make([]smpc.Message, 0)
    succ := signing.CheckFull(signSigniMessages)
    assert.False(t, succ, "fail")
    
    threshold := 3
    for i:=0;i<threshold;i++ {
	u1Gamma := random.GetRandomIntFromZn(secp256k1.S256().N)

	u1GammaGx, u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
	commitU1GammaG := new(ec2.Commitment).Commit(u1GammaGx, u1GammaGy)
	if commitU1GammaG == nil {
		return
	}

	srm := &signing.SignRound1Message{
		SignRoundMessage: new(signing.SignRoundMessage),
		C11:              commitU1GammaG.C,
	}
	srm.SetFromID("62472382178168225119626719865491481459304781844424379027070392269894567214882")
	srm.SetFromIndex(i)

	signSigniMessages = append(signSigniMessages,srm)
    }

    succ = signing.CheckFull(signSigniMessages)
    assert.True(t, succ, "success")
}



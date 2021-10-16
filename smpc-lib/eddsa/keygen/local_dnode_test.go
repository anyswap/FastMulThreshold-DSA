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

// Package keygen_test test ED MPC implementation of generating pubkey 
package keygen_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

func TestCheckFull(t *testing.T) {
    kgRoundiMessages := make([]smpc.Message, 0)
    succ := keygen.CheckFull(kgRoundiMessages)
    assert.False(t, succ, "fail")
    
    threshold := 3
    for i:=0;i<threshold;i++ {
	kg := &keygen.KGRound0Message{
		KGRoundMessage: new(keygen.KGRoundMessage),
	}
	kg.SetFromID("62472382178168225119626719865491481459304781844424379027070392269894567214882")
	kg.SetFromIndex(-1)

	kgRoundiMessages = append(kgRoundiMessages,kg)
    }

    succ = keygen.CheckFull(kgRoundiMessages)
    assert.True(t, succ, "success")
}



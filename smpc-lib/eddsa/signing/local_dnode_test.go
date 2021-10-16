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

// Package signing_test test ED MPC implementation of signing
package signing_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"io"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/signing"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	cryptorand "crypto/rand"
)

func TestCheckFull(t *testing.T) {
    signSigniMessages := make([]smpc.Message, 0)
    succ := signing.CheckFull(signSigniMessages)
    assert.False(t, succ, "fail")
    
    threshold := 3
    for i:=0;i<threshold;i++ {
	rand := cryptorand.Reader
	var tmp [32]byte
	if _, err := io.ReadFull(rand, tmp[:]); err != nil {
		return
	}

	comC,_ := ed.Commit(tmp)

	srm := &signing.SignRound1Message{
		SignRoundMessage: new(signing.SignRoundMessage),
		CR:               comC,
	}
	srm.SetFromID("62472382178168225119626719865491481459304781844424379027070392269894567214882")
	srm.SetFromIndex(i)

	signSigniMessages = append(signSigniMessages,srm)
    }

    succ = signing.CheckFull(signSigniMessages)
    assert.True(t, succ, "success")
}



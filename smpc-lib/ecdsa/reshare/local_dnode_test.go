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

// Package reshare_test test MPC implementation of reshare 
package reshare_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/reshare"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

func TestCheckFull(t *testing.T) {
    reshareReshareiMessages := make([]smpc.Message, 0)
    succ := reshare.CheckFull(reshareReshareiMessages)
    assert.False(t, succ, "fail")
    
    threshold := 3
    for i:=0;i<threshold;i++ {
	re := &reshare.ReshareRound0Message{
		ReshareRoundMessage: new(reshare.ReshareRoundMessage),
	}
	re.SetFromID("62472382178168225119626719865491481459304781844424379027070392269894567214882")
	re.SetFromIndex(-1)

	reshareReshareiMessages = append(reshareReshareiMessages,re)
    }

    succ = reshare.CheckFull(reshareReshareiMessages)
    assert.True(t, succ, "success")
}


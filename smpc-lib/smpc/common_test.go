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

// Package smpc_test test the smpc
package smpc_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

func TestGetRandomInt(t *testing.T) {
    length := 1024
    rnd := smpc.GetRandomInt(length)
    assert.NotZero(t, rnd)
}

func TestReadBits(t *testing.T) {
    num,_ := new(big.Int).SetString("62472382178168225119626719865491481459304781844424379027070392269894567214882",10)
    buf := make([]byte, len(num.Bytes()))
    smpc.ReadBits(num,buf)
    assert.Equal(t, new(big.Int).SetBytes(buf), num)

    buf = make([]byte, len(num.Bytes())/2)
    smpc.ReadBits(num,buf)
    m := new(big.Int).SetBytes(buf)
    ret := m.Cmp(num) != 0 
    assert.True(t, ret, "must be true")
}


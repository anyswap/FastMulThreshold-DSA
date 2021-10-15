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

package ec2_test

import (
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestCheckValidate(t *testing.T) {
	q := new(big.Int).SetInt64(5)
	p := ec2.GetP(q)
	sp := ec2.SafePrime{}
	sp.SetQ(q)
	sp.SetP(p)
	ret := sp.CheckValidate()
	assert.True(t, ret)
}

func TestCheckValidate_Bad(t *testing.T) {
	q := new(big.Int).SetInt64(10)
	p := ec2.GetP(q)
	sp := ec2.SafePrime{}
	sp.SetQ(q)
	sp.SetP(p)
	ret := sp.CheckValidate()
	assert.False(t, ret)
}

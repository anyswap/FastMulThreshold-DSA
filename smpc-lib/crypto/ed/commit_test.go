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

// Package ed_test test MPC ed algorithm 
package ed_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	cryptorand "crypto/rand"
	"io"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"fmt"
)

func TestVerify(t *testing.T) {
	rand := cryptorand.Reader
	var secr [32]byte
	if _, err := io.ReadFull(rand, secr[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
		return
	}

	comC,comD := ed.Commit(secr)
	succ := ed.Verify(comC,comD)
	assert.True(t, succ, "success")
}


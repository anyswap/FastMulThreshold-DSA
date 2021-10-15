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

package ed_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	cryptorand "crypto/rand"
	"io"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"fmt"
	"crypto/sha512"
)

func TestVerify_zk(t *testing.T) {
	rand := cryptorand.Reader
	var seed [32]byte

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, seed)")
		return
	}

	var sk [64]byte
	var pk [32]byte
	seedDigest := sha512.Sum512(seed[:])
	seedDigest[0] &= 248
	seedDigest[31] &= 127
	seedDigest[31] |= 64
	copy(sk[:], seedDigest[:])
	var temSk [32]byte
	copy(temSk[:], sk[:32])
	var A ed.ExtendedGroupElement
	ed.GeScalarMultBase(&A, &temSk)
	A.ToBytes(&pk)

	proof := ed.Prove(temSk)
	succ := ed.Verify_zk(proof,pk)
	assert.True(t, succ, "success")
}



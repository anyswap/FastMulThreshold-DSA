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
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
	"sort"
)

func TestVerify_vss(t *testing.T) {
    nodes := 5
    threshold := 3
    rand := cryptorand.Reader

    var ids smpc.SortableIDSSlice
    for i:=0;i<nodes;i++ {
	//get id
	var id [32]byte
	if _, err := io.ReadFull(rand, id[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, id)")
		return
	}

	var zero [32]byte
	var one [32]byte
	one[0] = 1
	ed.ScMulAdd(&id, &id, &one, &zero)

	uid := new(big.Int).SetBytes(id[:])
	ids = append(ids, uid)
    }
    sort.Sort(ids)

    var PkSet []byte
    var DPk2 [64]byte
    var sk2 [64]byte

    for k,_ := range ids {
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
	_, DPk := ed.Commit(pk)

	if k == 0 {
	    copy(DPk2[:], DPk[:])
	    copy(sk2[:], sk[:])
	}

	PkSet = append(PkSet[:], (DPk[32:])...)
    }

    var a [32]byte
    var aDigest [64]byte

    h := sha512.New()
    _, err := h.Write(DPk2[32:])
    if err != nil {
	    return
    }

    _, err = h.Write(PkSet)
    if err != nil {
	    return
    }

    h.Sum(aDigest[:0])
    ed.ScReduce(&a, &aDigest)

    var ask [32]byte
    var temSk2 [32]byte
    copy(temSk2[:], sk2[:32])
    ed.ScMul(&ask, &a, &temSk2)

    var uids [][32]byte
    for _, v := range ids {
	    var tem [32]byte
	    tmp := v.Bytes()
	    copy(tem[:], tmp[:])
	    if len(v.Bytes()) < 32 {
		    l := len(v.Bytes())
		    for j := l; j < 32; j++ {
			    tem[j] = byte(0x00)
		    }
	    }
	    uids = append(uids, tem)
    }

    _, cfsBBytes, shares := ed.Vss(ask, uids, threshold, nodes)
    assert.NotZero(t, cfsBBytes)
    assert.NotZero(t, shares)
    succ := ed.Verify_vss(shares[0],uids[0],cfsBBytes)
    assert.True(t, succ, "success")
}


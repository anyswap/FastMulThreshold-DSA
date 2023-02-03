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

package signing

import (
	"errors"
	"fmt"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
)

// Start calc S and check (R,S)
func (round *round7) Start() error {
	if round.started {
		fmt.Printf("============= ed sign,round7.start fail =======\n")
		return errors.New("ed sign,round already started")
	}
	round.number = 7
	round.started = true
	round.ResetOK()

	var FinalS [32]byte
	for k := range round.idsign {
		msg6, ok := round.temp.signRound6Messages[k].(*SignRound6Message)
		if !ok {
			return errors.New("get s fail")
		}

		var t [32]byte
		copy(t[:], msg6.S[:])

		if round.temp.keyType == smpc.SR25519 {
			ed_ristretto.ScAdd(&FinalS, &FinalS, &t)
		}else {
			ed.ScAdd(&FinalS, &FinalS, &t)
		}
	}

	inputVerify := InputVerify{KeyType: round.temp.keyType, FinalR: round.temp.FinalRBytes, FinalS: FinalS, Message: []byte(round.temp.message), FinalPk: round.temp.pkfinal}

	var pass = EdVerify(inputVerify, round.temp.keyType)
	//fmt.Printf("===========ed verify, pass = %v============\n", pass)
	if !pass {
	    return errors.New("ed verify (r,s) fail")
	}

	//r
	rx := hex.EncodeToString(round.temp.FinalRBytes[:])
	sx := hex.EncodeToString(FinalS[:])
	//fmt.Printf("===========ed sign, round7.start, rx = %v, sx = %v============\n", rx, sx)

	// //////test
	// signature := new([64]byte)
	// copy(signature[:], round.temp.FinalRBytes[:])
	// copy(signature[32:], FinalS[:])

	// suss := ed25519.Verify(&round.temp.pkfinal, []byte(round.temp.message), signature)
	// //fmt.Printf("===========ed verify, success = %v============\n", suss)
	// if !suss {
	//     return errors.New("ed verify (r,s) fail")
	// }

	/////////solana
	/*suss = edlib.Verify(round.temp.pkfinal[:],round.temp.message,signature[:])
	fmt.Printf("===========ed lib verify, success = %v============\n",suss)

	suss = Verify(round.temp.pkfinal[:],round.temp.message,signature[:])
	fmt.Printf("===========ed lib at local verify, success = %v============\n",suss)*/
	/////////solana

	if round.temp.keyType == smpc.SR25519 {
		FinalS[31] |= 128
	}
	round.end <- EdSignData{Rx: round.temp.FinalRBytes, Sx: FinalS}
	fmt.Printf("===========ed sign success, rx = %v, sx = %v============\n", rx, sx)

	return nil
}

// CanAccept end signing 
func (round *round7) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end signing
func (round *round7) Update() (bool, error) {
	return false, nil
}

// NextRound end signing
func (round *round7) NextRound() smpc.Round {
	return nil
}

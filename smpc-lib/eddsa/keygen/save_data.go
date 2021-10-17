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

package keygen

import (
	"fmt"
	"math/big"
	"strings"
	"encoding/hex"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// LocalDNodeSaveData the ed data need to save in local db
type LocalDNodeSaveData struct {
	//
	Sk           [64]byte
	Pk           [32]byte
	TSk          [32]byte
	FinalPkBytes [32]byte
	//

	IDs        smpc.SortableIDSSlice
	CurDNodeID *big.Int
}

// NewLocalDNodeSaveData new LocalDNodeSaveData
func NewLocalDNodeSaveData(DNodeCount int) (saveData LocalDNodeSaveData) {
	saveData.IDs = nil
	saveData.CurDNodeID = nil
	return
}

// OutMap Convert LocalDNodeSaveData into map
func (sd *LocalDNodeSaveData) OutMap() map[string]string {
	sdout := make(map[string]string)

	sk := hex.EncodeToString(sd.Sk[:])
	sdout["Sk"] = sk

	pk := hex.EncodeToString(sd.Pk[:])
	sdout["Pk"] = pk

	tsk := hex.EncodeToString(sd.TSk[:])
	sdout["TSk"] = tsk

	finalpk := hex.EncodeToString(sd.FinalPkBytes[:])
	sdout["FinalPkBytes"] = finalpk

	ids := make([]string, len(sd.IDs))
	for k, v := range sd.IDs {
		ids[k] = fmt.Sprintf("%v", v)
	}
	sdout["IDs"] = strings.Join(ids, "|")

	sdout["CurDNodeID"] = fmt.Sprintf("%v", sd.CurDNodeID)

	return sdout
}

// GetLocalDNodeSaveData get LocalDNodeSaveData from map
func GetLocalDNodeSaveData(data map[string]string) *LocalDNodeSaveData {

	var Sk [64]byte
	sk, _ := hex.DecodeString(data["Sk"])
	copy(Sk[:], sk[:])

	var TSk [32]byte
	tsk, _ := hex.DecodeString(data["TSk"])
	copy(TSk[:], tsk[:])

	var Pk [32]byte
	pk, _ := hex.DecodeString(data["Pk"])
	copy(Pk[:], pk[:])

	var FinalPkBytes [32]byte
	finalpk, _ := hex.DecodeString(data["FinalPkBytes"])
	copy(FinalPkBytes[:], finalpk[:])

	idstmp := strings.Split(data["IDs"], "|")
	ids := make(smpc.SortableIDSSlice, len(idstmp))
	for k, v := range idstmp {
		ids[k], _ = new(big.Int).SetString(v, 10)
	}

	curdnodeid, _ := new(big.Int).SetString(data["CurDNodeID"], 10)

	sd := &LocalDNodeSaveData{Sk: Sk, TSk: TSk, Pk: Pk, FinalPkBytes: FinalPkBytes, IDs: ids, CurDNodeID: curdnodeid}
	return sd
}

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
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"math/big"
	"strings"
)

// LocalDNodeSaveData the data will save to local db after keygen
type LocalDNodeSaveData struct {
	//save to local db
	Pkx *big.Int
	Pky *big.Int
	C   *big.Int

	SkU1         *big.Int
	U1PaillierSk *ec2.PrivateKey
	U1PaillierPk []*ec2.PublicKey
	U1NtildePrivData *ec2.NtildePrivData
	U1NtildeH1H2 []*ec2.NtildeH1H2

	IDs        smpc.SortableIDSSlice
	CurDNodeID *big.Int
}

// NewLocalDNodeSaveData init a LocalDNodeSaveData data struct
func NewLocalDNodeSaveData(DNodeCount int) (saveData LocalDNodeSaveData) {
	saveData.Pkx = nil
	saveData.Pky = nil
	saveData.C = nil
	saveData.SkU1 = nil
	saveData.U1PaillierSk = nil
	saveData.U1PaillierPk = make([]*ec2.PublicKey, DNodeCount)
	saveData.U1NtildePrivData = nil
	saveData.U1NtildeH1H2 = make([]*ec2.NtildeH1H2, DNodeCount)
	saveData.IDs = nil
	saveData.CurDNodeID = nil
	return
}

// OutMap  Convert LocalDNodeSaveData into map
func (sd *LocalDNodeSaveData) OutMap() map[string]string {
	sdout := make(map[string]string)
	sdout["Pkx"] = fmt.Sprintf("%v", sd.Pkx)
	sdout["Pky"] = fmt.Sprintf("%v", sd.Pky)
	sdout["C"] = fmt.Sprintf("%v", sd.C)
	sdout["SkU1"] = fmt.Sprintf("%v", sd.SkU1)

	usk, err := sd.U1PaillierSk.MarshalJSON()
	if err != nil {
		return nil
	}

	sdout["U1PaillierSk"] = string(usk)

	paipk := make([]string, len(sd.U1PaillierPk))
	for k, v := range sd.U1PaillierPk {
		pk, err := v.MarshalJSON()
		if err != nil {
			return nil
		}

		paipk[k] = string(pk)
	}

	sdout["U1PaillierPk"] = strings.Join(paipk, "|")

	ntildepriv, err := sd.U1NtildePrivData.MarshalJSON()
	if err != nil {
		return nil
	}

	sdout["U1NtildePrivData"] = string(ntildepriv)

	nth := make([]string, len(sd.U1NtildeH1H2))
	for k, v := range sd.U1NtildeH1H2 {
		nt, err := v.MarshalJSON()
		if err != nil {
			return nil
		}

		nth[k] = string(nt)
	}

	sdout["U1NtildeH1H2"] = strings.Join(nth, "|")

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
	pkx, _ := new(big.Int).SetString(data["Pkx"], 10)
	pky, _ := new(big.Int).SetString(data["Pky"], 10)
	c, _ := new(big.Int).SetString(data["C"], 10)
	sku1, _ := new(big.Int).SetString(data["SkU1"], 10)

	usk := &ec2.PrivateKey{}
	err := usk.UnmarshalJSON([]byte(data["U1PaillierSk"]))
	if err != nil {
		return nil
	}

	paipk := strings.Split(data["U1PaillierPk"], "|")
	pk := make([]*ec2.PublicKey, len(paipk))
	for k, v := range paipk {
		pktmp := &ec2.PublicKey{}
		err = pktmp.UnmarshalJSON([]byte(v))
		if err != nil {
			return nil
		}

		pk[k] = pktmp
	}

	ntildepriv := &ec2.NtildePrivData{}
	err = ntildepriv.UnmarshalJSON([]byte(data["U1NtildePrivData"]))
	if err != nil {
		return nil
	}

	nth := strings.Split(data["U1NtildeH1H2"], "|")
	nt := make([]*ec2.NtildeH1H2, len(nth))
	for k, v := range nth {
		nttmp := &ec2.NtildeH1H2{}
		err = nttmp.UnmarshalJSON([]byte(v))
		if err != nil {
			return nil
		}

		nt[k] = nttmp
	}

	idstmp := strings.Split(data["IDs"], "|")
	ids := make(smpc.SortableIDSSlice, len(idstmp))
	for k, v := range idstmp {
		ids[k], _ = new(big.Int).SetString(v, 10)
	}

	curdnodeid, _ := new(big.Int).SetString(data["CurDNodeID"], 10)

	sd := &LocalDNodeSaveData{Pkx: pkx, Pky: pky, C: c, SkU1: sku1, U1PaillierSk: usk, U1PaillierPk: pk, U1NtildePrivData:ntildepriv, U1NtildeH1H2: nt, IDs: ids, CurDNodeID: curdnodeid}
	return sd
}


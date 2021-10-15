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
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"math/big"
	"strconv"
	"strings"
)

//keygen
type KGRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
}

func (kg *KGRoundMessage) SetFromID(id string) {
	kg.FromID = id
}

func (kg *KGRoundMessage) SetFromIndex(index int) {
	kg.FromIndex = index
}

func (kg *KGRoundMessage) AppendToID(toid string) {
	kg.ToID = append(kg.ToID, toid)
}

//KGRound0Message
type KGRound0Message struct {
	*KGRoundMessage
}

func (kg *KGRound0Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound0Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound0Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound0Message) IsBroadcast() bool {
	return true
}

func (kg *KGRound0Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["Type"] = "KGRound0Message"
	return m
}

//KGRound1Message
type KGRound1Message struct {
	*KGRoundMessage

	ComC       *big.Int `json:"ComC"`
	ComC_bip32 *big.Int `json:"ComC_bip32"`

	U1PaillierPk *ec2.PublicKey `json:"U1PaillierPk"`
}

func (kg *KGRound1Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound1Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound1Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound1Message) IsBroadcast() bool {
	return true
}

func (kg *KGRound1Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["ComC"] = fmt.Sprintf("%v", kg.ComC)
	m["ComC_bip32"] = fmt.Sprintf("%v", kg.ComC_bip32)

	pk, err := kg.U1PaillierPk.MarshalJSON()
	if err == nil {
		m["U1PaillierPk"] = string(pk)
	}

	m["Type"] = "KGRound1Message"
	return m
}

//KGRound2Message
type KGRound2Message struct {
	*KGRoundMessage

	Id    *big.Int
	Share *big.Int
}

func (kg *KGRound2Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound2Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound2Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound2Message) IsBroadcast() bool {
	return false
}

func (kg *KGRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = strings.Join(kg.ToID, ":")
	m["Id"] = fmt.Sprintf("%v", kg.Id)
	m["Share"] = fmt.Sprintf("%v", kg.Share)
	m["Type"] = "KGRound2Message"
	fmt.Printf("\n===========KGRound2Message.OutMap, kg.Id = %v,kg.Share = %v, ToID = %v ==========\n", m["Id"], m["Share"], m["FromID"])
	return m
}

//KGRound2Message1
type KGRound2Message1 struct {
	*KGRoundMessage

	C1 *big.Int
}

func (kg *KGRound2Message1) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound2Message1) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound2Message1) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound2Message1) IsBroadcast() bool {
	return true
}

func (kg *KGRound2Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["C1"] = fmt.Sprintf("%v", kg.C1)
	m["Type"] = "KGRound2Message1"
	return m
}

//KGRound3Message
type KGRound3Message struct {
	*KGRoundMessage
	ComU1GD  []*big.Int
	ComC1GD  []*big.Int
	U1PolyGG [][]*big.Int
}

func (kg *KGRound3Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound3Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound3Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound3Message) IsBroadcast() bool {
	return true
}

func (kg *KGRound3Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	tmp := make([]string, len(kg.ComU1GD))
	for k, v := range kg.ComU1GD {
		tmp[k] = fmt.Sprintf("%v", v)
	}
	m["ComU1GD"] = strings.Join(tmp, ":")

	tmp2 := make([]string, len(kg.ComC1GD))
	for k, v := range kg.ComC1GD {
		tmp2[k] = fmt.Sprintf("%v", v)
	}
	m["ComC1GD"] = strings.Join(tmp2, ":")

	tmp3 := make([][]string, len(kg.U1PolyGG))
	for k, v := range kg.U1PolyGG {
		tmp4 := make([]string, len(v))
		for kk, vv := range v {
			tmp4[kk] = fmt.Sprintf("%v", vv)
		}

		tmp3[k] = tmp4
	}
	tmp5 := make([]string, len(tmp3))
	for k, v := range tmp3 {
		vv := strings.Join(v, ":")
		tmp5[k] = vv
	}
	m["U1PolyGG"] = strings.Join(tmp5, "|")

	fmt.Printf("\n============KGRound3Message.OutMap, ComU1GD = %v, ComC1GD = %v, U1PolyGG = %v ============\n", m["ComU1GD"], m["ComC1GD"], m["U1PolyGG"])

	m["Type"] = "KGRound3Message"
	return m
}

//KGRound4Message
type KGRound4Message struct {
	*KGRoundMessage
	U1NtildeH1H2 *ec2.NtildeH1H2

	//add for ntilde zk
	NtildeProof1 *ec2.NtildeProof
	NtildeProof2 *ec2.NtildeProof
}

func (kg *KGRound4Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound4Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound4Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound4Message) IsBroadcast() bool {
	return true
}

func (kg *KGRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	nt, err := kg.U1NtildeH1H2.MarshalJSON()
	if err == nil {
		m["U1NtildeH1H2"] = string(nt)
	}

	pf1, err := kg.NtildeProof1.MarshalJSON()
	if err == nil {
		m["NtildeProof1"] = string(pf1)
	}

	pf2, err := kg.NtildeProof2.MarshalJSON()
	if err == nil {
		m["NtildeProof2"] = string(pf2)
	}

	m["Type"] = "KGRound4Message"
	return m
}

//KGRound5Message
type KGRound5Message struct {
	*KGRoundMessage
	U1zkUProof *ec2.ZkUProof
}

func (kg *KGRound5Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound5Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound5Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound5Message) IsBroadcast() bool {
	return true
}

func (kg *KGRound5Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	zk, err := kg.U1zkUProof.MarshalJSON()
	if err == nil {
		m["U1zkUProof"] = string(zk)
	}

	m["Type"] = "KGRound5Message"
	return m
}

//KGRound6Message
type KGRound6Message struct {
	*KGRoundMessage
	Check_Pubkey_Status bool
}

func (kg *KGRound6Message) GetFromID() string {
	return kg.FromID
}

func (kg *KGRound6Message) GetFromIndex() int {
	return kg.FromIndex
}

func (kg *KGRound6Message) GetToID() []string {
	return kg.ToID
}

func (kg *KGRound6Message) IsBroadcast() bool {
	return true
}

func (kg *KGRound6Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	if kg.Check_Pubkey_Status {
		m["Check_Pubkey_Status"] = "true"
	} else {
		m["Check_Pubkey_Status"] = "false"
	}

	m["Type"] = "KGRound6Message"
	return m
}

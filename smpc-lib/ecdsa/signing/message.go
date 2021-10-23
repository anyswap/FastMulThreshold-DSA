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
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"math/big"
	"strconv"
	"strings"
)

// SignRoundMessage base type of sign round message
type SignRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
}

// SetFromID set sending nodes's ID
func (srm *SignRoundMessage) SetFromID(id string) {
	srm.FromID = id
}

// SetFromIndex set sending nodes's serial number in group
func (srm *SignRoundMessage) SetFromIndex(index int) {
	srm.FromIndex = index
}

// AppendToID get the ID of nodes that the message will broacast to
func (srm *SignRoundMessage) AppendToID(toid string) {
	srm.ToID = append(srm.ToID, toid)
}

// SignRound1Message  Round 1 sending message 
type SignRound1Message struct {
	*SignRoundMessage

	C11 *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound1Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound1Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound1Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound1Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound5Message to map
func (srm *SignRound1Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound1Message"
	m["C11"] = fmt.Sprintf("%v", srm.C11)

	return m
}

// SignRound2Message  Round 2 sending message 
type SignRound2Message struct {
	*SignRoundMessage

	U1u1MtAZK1Proof *ec2.MtAZK1Proofnhh
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound2Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound2Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound2Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound2Message) IsBroadcast() bool {
	return false
}

// OutMap transfer *SignRound2Message to map
func (srm *SignRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound2Message"

	proof, err := srm.U1u1MtAZK1Proof.MarshalJSON()
	if err == nil {
		m["U1u1MtAZK1Proof"] = string(proof)
	}

	return m
}

// SignRound3Message  Round 3 sending message 
type SignRound3Message struct {
	*SignRoundMessage
	Kc *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound3Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound3Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound3Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound3Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound3Message to map
func (srm *SignRound3Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound3Message"
	m["Kc"] = fmt.Sprintf("%v", srm.Kc)

	return m
}

// SignRound4Message  Round 4 sending message 
type SignRound4Message struct {
	*SignRoundMessage
	U1KGamma1Cipher *big.Int
	U1u1MtAZK2Proof *ec2.MtAZK2Proofnhh
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound4Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound4Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound4Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound4Message) IsBroadcast() bool {
	return false
}

// OutMap transfer *SignRound4Message to map
func (srm *SignRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound4Message"

	proof, err := srm.U1u1MtAZK2Proof.MarshalJSON()
	if err == nil {
		m["U1u1MtAZK2Proof"] = string(proof)
	}

	m["U1KGamma1Cipher"] = fmt.Sprintf("%v", srm.U1KGamma1Cipher)

	return m
}

// SignRound4Message1  Round 5 sending message 
type SignRound4Message1 struct {
	*SignRoundMessage
	U1Kw1Cipher     *big.Int
	U1u1MtAZK3Proof *ec2.MtAZK3Proofnhh
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound4Message1) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound4Message1) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound4Message1) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound4Message1) IsBroadcast() bool {
	return false
}

// OutMap transfer *SignRound4Message1 to map
func (srm *SignRound4Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound4Message1"

	proof, err := srm.U1u1MtAZK3Proof.MarshalJSON()
	if err == nil {
		m["U1u1MtAZK3Proof"] = string(proof)
	}

	m["U1Kw1Cipher"] = fmt.Sprintf("%v", srm.U1Kw1Cipher)

	return m
}

// SignRound5Message  Round 5 sending message 
type SignRound5Message struct {
	*SignRoundMessage
	Delta1 *big.Int
	T1X *big.Int
	T1Y *big.Int
	Tpf *ec2.TProof
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound5Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound5Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound5Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound5Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound5Message to map
func (srm *SignRound5Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound5Message"

	m["Delta1"] = fmt.Sprintf("%v", srm.Delta1)
	m["T1X"] = fmt.Sprintf("%v", srm.T1X)
	m["T1Y"] = fmt.Sprintf("%v", srm.T1Y)

	proof, err := srm.Tpf.MarshalJSON()
	if err == nil {
	    m["Tpf"] = string(proof) 
	}

	return m
}

// SignRound6Message  Round 6 sending message 
type SignRound6Message struct {
	*SignRoundMessage
	CommU1D        []*big.Int
	U1GammaZKProof *ec2.ZkUProof
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound6Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound6Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound6Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound6Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound6Message to map
func (srm *SignRound6Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound6Message"

	proof, err := srm.U1GammaZKProof.MarshalJSON()
	if err == nil {
		m["U1GammaZKProof"] = string(proof)
	}

	dtmp := make([]string, len(srm.CommU1D))
	for k, v := range srm.CommU1D {
		dtmp[k] = fmt.Sprintf("%v", v)
	}

	m["CommU1D"] = strings.Join(dtmp, ":")

	return m
}

// SignRound7Message  Round 7 sending message 
type SignRound7Message struct {
	*SignRoundMessage
	Us1 *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound7Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound7Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound7Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound7Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound7Message to map
func (srm *SignRound7Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound7Message"

	m["Us1"] = fmt.Sprintf("%v", srm.Us1)

	return m
}

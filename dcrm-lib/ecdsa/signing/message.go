
package signing 

import (
    "github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
    "math/big"
    "strings"
    "fmt"
    "strconv"
)

//signing
type SignRoundMessage struct {
    FromID string  `json:"FromID"` //DNodeID
    FromIndex int  `json:"FromIndex"`
    ToID []string  `json:"ToID"`
}

func (srm *SignRoundMessage) SetFromID(id string) {
    srm.FromID = id
}

func (srm *SignRoundMessage) SetFromIndex(index int) {
    srm.FromIndex = index
}

func (srm *SignRoundMessage) AppendToID(toid string) {
    srm.ToID = append(srm.ToID,toid)
}

//SignRound1Message
type SignRound1Message struct {
    *SignRoundMessage

    C11 *big.Int
}

func (srm *SignRound1Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound1Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound1Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound1Message) IsBroadcast() bool {
    return true
}

func (srm *SignRound1Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = ""
    m["Type"] = "SignRound1Message"
    m["C11"] = fmt.Sprintf("%v",srm.C11)

    return m
}

//SignRound2Message
type SignRound2Message struct {
    *SignRoundMessage

    U1u1MtAZK1Proof *ec2.MtAZK1Proof_nhh
}

func (srm *SignRound2Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound2Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound2Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound2Message) IsBroadcast() bool {
    return false 
}

func (srm *SignRound2Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = strings.Join(srm.ToID,":")
    m["Type"] = "SignRound2Message"

    proof,err := srm.U1u1MtAZK1Proof.MarshalJSON()
    if err == nil {
	m["U1u1MtAZK1Proof"] = string(proof)
    }

    return m
}

//SignRound3Message
type SignRound3Message struct {
    *SignRoundMessage
    Kc *big.Int
}

func (srm *SignRound3Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound3Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound3Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound3Message) IsBroadcast() bool {
    return true
}

func (srm *SignRound3Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = ""
    m["Type"] = "SignRound3Message"
    m["Kc"] = fmt.Sprintf("%v",srm.Kc)

    return m
}

//SignRound4Message
type SignRound4Message struct {
    *SignRoundMessage
    U1KGamma1Cipher *big.Int
    U1u1MtAZK2Proof *ec2.MtAZK2Proof_nhh
}

func (srm *SignRound4Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound4Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound4Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound4Message) IsBroadcast() bool {
    return false 
}

func (srm *SignRound4Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = strings.Join(srm.ToID,":")
    m["Type"] = "SignRound4Message"

    proof,err := srm.U1u1MtAZK2Proof.MarshalJSON()
    if err == nil {
	m["U1u1MtAZK2Proof"] = string(proof)
    }

    m["U1KGamma1Cipher"] = fmt.Sprintf("%v",srm.U1KGamma1Cipher)

    return m
}

//SignRound4Message1
type SignRound4Message1 struct {
    *SignRoundMessage
    U1Kw1Cipher *big.Int
    U1u1MtAZK3Proof *ec2.MtAZK3Proof_nhh
}

func (srm *SignRound4Message1) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound4Message1) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound4Message1) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound4Message1) IsBroadcast() bool {
    return false 
}

func (srm *SignRound4Message1) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = strings.Join(srm.ToID,":")
    m["Type"] = "SignRound4Message1"

    proof,err := srm.U1u1MtAZK3Proof.MarshalJSON()
    if err == nil {
	m["U1u1MtAZK3Proof"] = string(proof)
    }

    m["U1Kw1Cipher"] = fmt.Sprintf("%v",srm.U1Kw1Cipher)

    return m
}

//SignRound5Message
type SignRound5Message struct {
    *SignRoundMessage
    Delta1 *big.Int
}

func (srm *SignRound5Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound5Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound5Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound5Message) IsBroadcast() bool {
    return true 
}

func (srm *SignRound5Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = ""
    m["Type"] = "SignRound5Message"

    m["Delta1"] = fmt.Sprintf("%v",srm.Delta1)

    return m
}

//SignRound6Message
type SignRound6Message struct {
    *SignRoundMessage
    CommU1D []*big.Int
    U1GammaZKProof *ec2.ZkUProof
}

func (srm *SignRound6Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound6Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound6Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound6Message) IsBroadcast() bool {
    return true 
}

func (srm *SignRound6Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = ""
    m["Type"] = "SignRound6Message"

    proof,err := srm.U1GammaZKProof.MarshalJSON()
    if err == nil {
	m["U1GammaZKProof"] = string(proof)
    }

    dtmp := make([]string,len(srm.CommU1D))
    for k,v := range srm.CommU1D {
	dtmp[k] = fmt.Sprintf("%v",v)
    }

    m["CommU1D"] = strings.Join(dtmp,":")

    return m
}

//SignRound7Message
type SignRound7Message struct {
    *SignRoundMessage
    Us1 *big.Int
}

func (srm *SignRound7Message) GetFromID() string {
    return srm.FromID
}

func (srm *SignRound7Message) GetFromIndex() int {
    return srm.FromIndex
}

func (srm *SignRound7Message) GetToID() []string {
    return srm.ToID
}

func (srm *SignRound7Message) IsBroadcast() bool {
    return true 
}

func (srm *SignRound7Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = srm.FromID
    m["FromIndex"] = strconv.Itoa(srm.FromIndex) 
    m["ToID"] = ""
    m["Type"] = "SignRound7Message"

    m["Us1"] = fmt.Sprintf("%v",srm.Us1)

    return m
}


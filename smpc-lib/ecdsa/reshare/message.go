
package reshare

import (
    "github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
    "math/big"
    "strings"
    "fmt"
    "strconv"
)

//reshare
type ReshareRoundMessage struct {
    FromID string  `json:"FromID"` //DNodeID
    FromIndex int  `json:"FromIndex"`
    ToID []string  `json:"ToID"`
}

func (re *ReshareRoundMessage) SetFromID(id string) {
    re.FromID = id
}

func (re *ReshareRoundMessage) SetFromIndex(index int) {
    re.FromIndex = index
}

func (re *ReshareRoundMessage) AppendToID(toid string) {
    re.ToID = append(re.ToID,toid)
}

//ReshareRound0Message
type ReshareRound0Message struct {
    *ReshareRoundMessage
}

func (re *ReshareRound0Message) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound0Message) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound0Message) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound0Message) IsBroadcast() bool {
    return true
}

func (re *ReshareRound0Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = "" 
    m["Type"] = "ReshareRound0Message"
    return m
}

//ReshareRound1Message
type ReshareRound1Message struct {
    *ReshareRoundMessage
    ComC *big.Int
}

func (re *ReshareRound1Message) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound1Message) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound1Message) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound1Message) IsBroadcast() bool {
    return true
}

func (re *ReshareRound1Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = ""
    m["ComC"] = fmt.Sprintf("%v",re.ComC)
    m["Type"] = "ReshareRound1Message"
    return m
}

//ReshareRound2Message
type ReshareRound2Message struct {
    *ReshareRoundMessage
    
    Id *big.Int
    Share *big.Int
}

func (re *ReshareRound2Message) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound2Message) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound2Message) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound2Message) IsBroadcast() bool {
    return false
}

func (re *ReshareRound2Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = strings.Join(re.ToID,":")
    m["Id"] = fmt.Sprintf("%v",re.Id)
    m["Share"] = fmt.Sprintf("%v",re.Share)
    m["Type"] = "ReshareRound2Message"
    fmt.Printf("\n===========ReshareRound2Message.OutMap, re.Id = %v,re.Share = %v, FromID = %v ==========\n",m["Id"],m["Share"],m["FromID"])
    return m
}

//ReshareRound2Message1
type ReshareRound2Message1 struct {
    *ReshareRoundMessage
    
    ComD []*big.Int
    SkP1PolyG [][]*big.Int
}

func (re *ReshareRound2Message1) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound2Message1) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound2Message1) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound2Message1) IsBroadcast() bool {
    return true
}

func (re *ReshareRound2Message1) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = ""
    
    tmp := make([]string,len(re.ComD))
    for k,v := range re.ComD {
	tmp[k] = fmt.Sprintf("%v",v) 
    }
    m["ComD"] = strings.Join(tmp,":")

    tmp3 := make([][]string,len(re.SkP1PolyG))
    for k,v := range re.SkP1PolyG {
	tmp4 := make([]string,len(v))
	for kk,vv := range v {
	    tmp4[kk] = fmt.Sprintf("%v",vv)
	}

	tmp3[k] = tmp4
    }
    tmp5 := make([]string,len(tmp3))
    for k,v := range tmp3 {
	vv := strings.Join(v,":")
	tmp5[k] = vv
    }
    m["SkP1PolyG"] = strings.Join(tmp5,"|")

    m["Type"] = "ReshareRound2Message1"
    return m
}

//ReshareRound3Message
type ReshareRound3Message struct {
    *ReshareRoundMessage
    U1PaillierPk *ec2.PublicKey
}

func (re *ReshareRound3Message) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound3Message) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound3Message) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound3Message) IsBroadcast() bool {
    return true 
}

func (re *ReshareRound3Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = "" 
    
    pk,err := re.U1PaillierPk.MarshalJSON()
    if err == nil {
	m["U1PaillierPk"] = string(pk)
    }

    m["Type"] = "ReshareRound3Message"
    return m
}

//ReshareRound4Message
type ReshareRound4Message struct {
    *ReshareRoundMessage
    U1NtildeH1H2 *ec2.NtildeH1H2
    
    //add for ntilde zk
    NtildeProof1 *ec2.NtildeProof
    NtildeProof2 *ec2.NtildeProof
}

func (re *ReshareRound4Message) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound4Message) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound4Message) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound4Message) IsBroadcast() bool {
    return true 
}

func (re *ReshareRound4Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = ""

    nt,err := re.U1NtildeH1H2.MarshalJSON()
    if err == nil {
	m["U1NtildeH1H2"] = string(nt) 
    }

    pf1,err := re.NtildeProof1.MarshalJSON()
    if err == nil {
	m["NtildeProof1"] = string(pf1) 
    }

    pf2,err := re.NtildeProof2.MarshalJSON()
    if err == nil {
	m["NtildeProof2"] = string(pf2) 
    }

    m["Type"] = "ReshareRound4Message"
    return m
}

//ReshareRound5Message
type ReshareRound5Message struct {
    *ReshareRoundMessage
    NewSkOk string
}

func (re *ReshareRound5Message) GetFromID() string {
    return re.FromID
}

func (re *ReshareRound5Message) GetFromIndex() int {
    return re.FromIndex
}

func (re *ReshareRound5Message) GetToID() []string {
    return re.ToID
}

func (re *ReshareRound5Message) IsBroadcast() bool {
    return true 
}

func (re *ReshareRound5Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = re.FromID
    m["FromIndex"] = strconv.Itoa(re.FromIndex) 
    m["ToID"] = ""
    m["NewSkOk"] = re.NewSkOk
    m["Type"] = "ReshareRound4Message"
    return m
}


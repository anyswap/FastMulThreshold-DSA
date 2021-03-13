
package keygen 

import (
    //"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
    //"math/big"
    "strings"
    //"fmt"
    "strconv"
    "encoding/hex"
)

//keygen
type KGRoundMessage struct {
    FromID string  `json:"FromID"` //DNodeID
    FromIndex int  `json:"FromIndex"`
    ToID []string  `json:"ToID"`
}

func (kg *KGRoundMessage) SetFromID(id string) {
    kg.FromID = id
}

func (kg *KGRoundMessage) SetFromIndex(index int) {
    kg.FromIndex = index
}

func (kg *KGRoundMessage) AppendToID(toid string) {
    kg.ToID = append(kg.ToID,toid)
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

    CPk [32]byte
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

    cpk := hex.EncodeToString(kg.CPk[:])
    m["CPk"] = cpk

    m["Type"] = "KGRound1Message"
    return m
}

//KGRound2Message
type KGRound2Message struct {
    *KGRoundMessage

    ZkPk [64]byte
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
    return true
}

func (kg *KGRound2Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = kg.FromID
    m["FromIndex"] = strconv.Itoa(kg.FromIndex) 
    m["ToID"] = ""
    
    zkpk := hex.EncodeToString(kg.ZkPk[:])
    m["ZkPk"] = zkpk
    
    m["Type"] = "KGRound2Message"
    return m
}

//KGRound3Message
type KGRound3Message struct {
    *KGRoundMessage

    DPk [64]byte
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
    
    dpk := hex.EncodeToString(kg.DPk[:])
    m["DPk"] = dpk

    m["Type"] = "KGRound3Message"
    return m
}

//KGRound4Message
type KGRound4Message struct {
    *KGRoundMessage

    Share [32]byte
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
    return false
}

func (kg *KGRound4Message) OutMap() map[string]string {
    m := make(map[string]string)
    m["FromID"] = kg.FromID
    m["FromIndex"] = strconv.Itoa(kg.FromIndex) 
    m["ToID"] = ""
    
    shares := hex.EncodeToString(kg.Share[:])
    m["Share"] = shares
    m["Type"] = "KGRound4Message"
    return m
}

//KGRound5Message
type KGRound5Message struct {
    *KGRoundMessage

    CfsBBytes [][32]byte
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

    tmp := make([]string,len(kg.CfsBBytes))
    for k,v := range kg.CfsBBytes {
	vv := hex.EncodeToString(v[:])
	tmp[k] = vv
    }
    s := strings.Join(tmp,":")
    m["CfsBBytes"] = s

    m["Type"] = "KGRound5Message"
    return m
}


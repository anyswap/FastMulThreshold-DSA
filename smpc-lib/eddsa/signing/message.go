package signing

import (
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	//"math/big"
	"strings"
	//"fmt"
	"encoding/hex"
	"strconv"
)

//signing
type SignRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
}

func (srm *SignRoundMessage) SetFromID(id string) {
	srm.FromID = id
}

func (srm *SignRoundMessage) SetFromIndex(index int) {
	srm.FromIndex = index
}

func (srm *SignRoundMessage) AppendToID(toid string) {
	srm.ToID = append(srm.ToID, toid)
}

//SignRound1Message
type SignRound1Message struct {
	*SignRoundMessage
	CR [32]byte
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

	cr := hex.EncodeToString(srm.CR[:])
	m["CR"] = cr

	return m
}

//SignRound2Message
type SignRound2Message struct {
	*SignRoundMessage
	ZkR [64]byte
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
	return true
}

func (srm *SignRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound2Message"

	zkr := hex.EncodeToString(srm.ZkR[:])
	m["ZkR"] = zkr

	return m
}

//SignRound3Message
type SignRound3Message struct {
	*SignRoundMessage
	DR [64]byte
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

	dr := hex.EncodeToString(srm.DR[:])
	m["DR"] = dr

	return m
}

//SignRound4Message
type SignRound4Message struct {
	*SignRoundMessage
	CSB [32]byte
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
	return true
}

func (srm *SignRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound4Message"

	csb := hex.EncodeToString(srm.CSB[:])
	m["CSB"] = csb

	return m
}

//SignRound5Message
type SignRound5Message struct {
	*SignRoundMessage
	DSB [64]byte
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

	dsb := hex.EncodeToString(srm.DSB[:])
	m["DSB"] = dsb

	return m
}

//SignRound6Message
type SignRound6Message struct {
	*SignRoundMessage
	S [32]byte
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

	s := hex.EncodeToString(srm.S[:])
	m["S"] = s

	return m
}

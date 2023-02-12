package socket 

import (
	"encoding/json"
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/log"
)

//-------------------------------------------------------

type SocketMessage interface {
    SetBase(kt string,keyid string)
    ToJson() ([]byte,error)
    ToObj(raw []byte) error
    GetMsgType() string
}

type Base struct {
    KeyType string
    MsgPrex string
}

func (b *Base) SetBase(kt string,keyid string) {
    log.Info("===========Base.SetBase==========","msgprex",keyid)
    b.KeyType = kt
    b.MsgPrex = keyid
}

//--------------------------------------------------------

type KGRound1Msg struct {
   
    Base

    ThresHold int
    DNodeCount int
    PaillierKeyLen int
}

func (kg *KGRound1Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound1Msg) ToJson() ([]byte,error) {
    log.Info("===============KGRound1Msg.ToJson============","kg",kg)
    return json.Marshal(kg)
}

func (kg *KGRound1Msg) ToObj(raw []byte) error {
    log.Info("===============KGRound1Msg.ToObj===========","kg",kg)
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound1Msg) GetMsgType() string {
    log.Info("===============KGRound1Msg.GetMsgType===========","kg",kg)
    return "KGRound1Msg"
}

//-----------------------------------------------------

type KGRound2Msg2 struct {
    Base

    PaillierSkNLen int
    PaillierSkN *big.Int
    PaillierSkL *big.Int
}

func (kg *KGRound2Msg2) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound2Msg2) ToJson() ([]byte,error) {
    log.Info("===============KGRound2Msg2.ToJson============","kg",kg)
    return json.Marshal(kg)
}

func (kg *KGRound2Msg2) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound2Msg2) GetMsgType() string {
    return "KGRound2Msg2"
}

//--------------------------------------------------

type IdsVss struct {
    Base

    Ids []*big.Int
    U1Poly []*big.Int
}

func (kg *IdsVss) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *IdsVss) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *IdsVss) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *IdsVss) GetMsgType() string {
    return "IdsVss"
}

//---------------------------------------------------

type KGRound3Msg struct {
    Base

    N *big.Int
    Num *big.Int
    SfPf *ec2.SquareFreeProof 
}

func (kg *KGRound3Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

// MarshalJSON marshal KGRound3 data struct to json byte
func (ps *KGRound3Msg) ToJson() ([]byte, error) {

    str,err := ps.SfPf.MarshalJSON()
    if err != nil {
	return nil,err
    }

    return json.Marshal(struct {
	    KeyType   string `json:"KeyType"`
	    MsgPrex   string `json:"MsgPrex"`
	    N   *big.Int `json:"N"`
	    Num   *big.Int `json:"Num"`
	    S   string `json:"S"`
    }{
	    KeyType:   ps.Base.KeyType,
	    MsgPrex:   ps.Base.MsgPrex,
	    N: ps.N,
	    Num: ps.Num,
	    S: string(str),
    })
}

// UnmarshalJSON unmarshal json byte to KGRound3 data struct
func (ps *KGRound3Msg) ToObj(raw []byte) error {
	var pre struct {
		KeyType   string `json:"KeyType"`
		MsgPrex   string `json:"MsgPrex"`
		N   *big.Int `json:"N"`
		Num   *big.Int `json:"Num"`
		S   string `json:"S"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	sfpf := &ec2.SquareFreeProof{}
	if err := sfpf.UnmarshalJSON([]byte(pre.S));err != nil {
	    return err
	}

	ps.Base.KeyType = pre.KeyType
	ps.Base.MsgPrex = pre.MsgPrex
	ps.N = pre.N
	ps.Num = pre.Num
	ps.SfPf = sfpf
	return nil
}

func (kg *KGRound3Msg) GetMsgType() string {
    return "KGRound3Msg"
}

//---------------------------------------------------

type KGRound4VssCheck struct {
    Base

    ID *big.Int
    Share *big.Int
    PolyG [][]*big.Int

    C *big.Int
    D []*big.Int

    Bip32C *big.Int
    Bip32D []*big.Int

    Msg21C *big.Int
}

func (kg *KGRound4VssCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound4VssCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound4VssCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound4VssCheck) GetMsgType() string {
    return "KGRound4VssCheck"
}

//-----------------------------------------------------

type KGRound4DeCom struct {
    Base

    ID *big.Int
    Share *big.Int

    C *big.Int
    D []*big.Int

    Msg21C *big.Int
}

func (kg *KGRound4DeCom) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound4DeCom) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound4DeCom) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound4DeCom) GetMsgType() string {
    return "KGRound4DeCom"
}

//------------------------------------------------------

type KGRound4DeCom2 struct {

    Base 

    ID *big.Int
    Share *big.Int

    C *big.Int
    D []*big.Int

    Msg21C *big.Int
}

func (kg *KGRound4DeCom2) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound4DeCom2) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound4DeCom2) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound4DeCom2) GetMsgType() string {
    return "KGRound4DeCom2"
}

//-------------------------------------------------------

type KGRound4XiCom struct {

    Base

    C *big.Int
    Sk *big.Int
}

func (kg *KGRound4XiCom) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound4XiCom) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound4XiCom) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound4XiCom) GetMsgType() string {
    return "KGRound4XiCom"
}

//---------------------------------------------------------

type KGRound4Msg struct {

    Base

    Sk *big.Int
    NtildeLen int
}

func (kg *KGRound4Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound4Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound4Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound4Msg) GetMsgType() string {
    return "KGRound4Msg"
}

//------------------------------------------------------------

type KGRound5SquareFee struct {

    Base

    Ntilde *big.Int
    P1 *big.Int
    P2 *big.Int
}

func (kg *KGRound5SquareFee) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound5SquareFee) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound5SquareFee) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound5SquareFee) GetMsgType() string {
    return "KGRound5SquareFee"
}

//------------------------------------------------------------

type KGRound5Hv struct {
    Base

    Ntilde *big.Int
    P1 *big.Int
    P2 *big.Int
}

func (kg *KGRound5Hv) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound5Hv) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound5Hv) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound5Hv) GetMsgType() string {
    return "KGRound5Hv"
}

//------------------------------------------------------------

type KGRound6ComCheck struct {
    Base

    C *big.Int
    D []*big.Int
}

func (kg *KGRound6ComCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound6ComCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound6ComCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound6ComCheck) GetMsgType() string {
    return "KGRound6ComCheck"
}

//-------------------------------------------------------------

type KGRound6SquareFeeCheck struct {
    Base 

    Ntilde *big.Int
    Num *big.Int
    Sfp *ec2.SquareFreeProof
}

func (kg *KGRound6SquareFeeCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound6SquareFeeCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound6SquareFeeCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound6SquareFeeCheck) GetMsgType() string {
    return "KGRound6SquareFeeCheck"
}

//------------------------------------------------------------

type KGRound6HvCheck struct {
    Base

    Ntilde *big.Int
    Num *big.Int
    HvPf *ec2.HvProof
}

func (kg *KGRound6HvCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound6HvCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound6HvCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound6HvCheck) GetMsgType() string {
    return "KGRound6HvCheck"
}

//-------------------------------------------------------------

type KGRound6Msg struct {
    Base

    Sk *big.Int
}

func (kg *KGRound6Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound6Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound6Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound6Msg) GetMsgType() string {
    return "KGRound6Msg"
}

//------------------------------------------------------------

type KGRound7Msg struct {
    Base

    C *big.Int
    D []*big.Int
    XiPf *ec2.ZkXiProof
}

func (kg *KGRound7Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *KGRound7Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *KGRound7Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *KGRound7Msg) GetMsgType() string {
    return "KGRound7Msg"
}


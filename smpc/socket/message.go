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

//-------------------------------------------------

type SigningRound1Msg struct {
    Base

    Index int
    IdSign []*big.Int
    SkU1 *big.Int
}

func (kg *SigningRound1Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound1Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound1Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound1Msg) GetMsgType() string {
    return "SigningRound1Msg"
}

//--------------------------------------------------

type SigningRound2PaiEnc struct {
    Base

    U1K *big.Int
    U1PaillierPk *ec2.PublicKey
}

func (kg *SigningRound2PaiEnc) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound2PaiEnc) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound2PaiEnc) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound2PaiEnc) GetMsgType() string {
    return "SigningRound2PaiEnc"
}

//------------------------------------------------------

type SigningRound2Msg struct {
    Base

    UKC *big.Int
    U1K *big.Int
    UKC2 *big.Int
    U1PaiPK *ec2.PublicKey
    U1Nt *ec2.NtildeH1H2
}

func (kg *SigningRound2Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound2Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound2Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound2Msg) GetMsgType() string {
    return "SigningRound2Msg"
}

//---------------------------------------------------

type SigningRound4MtARangeProofCheck struct {
    Base

    MtAZK1Proof *ec2.MtARangeProof
    KC *big.Int
    PaiPk *ec2.PublicKey
    Nt *ec2.NtildeH1H2
}

func (kg *SigningRound4MtARangeProofCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound4MtARangeProofCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound4MtARangeProofCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound4MtARangeProofCheck) GetMsgType() string {
    return "SigningRound4MtARangeProofCheck"
}

//--------------------------------------------------

type SigningRound4ComCheck struct {
    Base

    C *big.Int
    D []*big.Int
}

func (kg *SigningRound4ComCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound4ComCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound4ComCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound4ComCheck) GetMsgType() string {
    return "SigningRound4ComCheck"
}

//-------------------------------------------------

type SigningRound4Beta struct {
    Base

    PaiKeyLen int
    ThresHold int
}

func (kg *SigningRound4Beta) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound4Beta) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound4Beta) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound4Beta) GetMsgType() string {
    return "SigningRound4Beta"
}

//------------------------------------------------

type SigningRound4Msg struct {
    Base

    KC *big.Int
    U1Gamma *big.Int
    CurPaiPk *ec2.PublicKey
    BetaStar *big.Int
    UKC *big.Int
    OldPaiPk *ec2.PublicKey
    OldNt *ec2.NtildeH1H2
}

func (kg *SigningRound4Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound4Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound4Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound4Msg) GetMsgType() string {
    return "SigningRound4Msg"
}

//-------------------------------------------------

type SigningRound4Msg1 struct {
    Base

    KC *big.Int
    W1 *big.Int
    CurPaiPk *ec2.PublicKey
    VU1Star *big.Int
    UKC *big.Int
    OldPaiPk *ec2.PublicKey
    OldNt *ec2.NtildeH1H2
}

func (kg *SigningRound4Msg1) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound4Msg1) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound4Msg1) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound4Msg1) GetMsgType() string {
    return "SigningRound4Msg1"
}

//-----------------------------------------------

type SigningRound5MtARespZKProofCheck struct {
    Base

    UKC *big.Int
    Clipher *big.Int
    PaiPk *ec2.PublicKey
    Nt *ec2.NtildeH1H2
    MtAZK2Proof *ec2.MtARespZKProof
}

func (kg *SigningRound5MtARespZKProofCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound5MtARespZKProofCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound5MtARespZKProofCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound5MtARespZKProofCheck) GetMsgType() string {
    return "SigningRound5MtARespZKProofCheck"
}

//-------------------------------------------------

type SigningRound5ComCheck struct {
    Base

    C *big.Int
    D []*big.Int
    MtAZK3Proof *ec2.MtAwcRespZKProof
    UKC *big.Int
    Cipher *big.Int
    PaiPk *ec2.PublicKey
    Nt *ec2.NtildeH1H2
    PaiSk *ec2.PrivateKey
    U1KGamma1Cipher *big.Int
}

func (kg *SigningRound5ComCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound5ComCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound5ComCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound5ComCheck) GetMsgType() string {
    return "SigningRound5ComCheck"
}

//--------------------------------------------

type SigningRound5Msg struct {
    Base

    Alpha1 []*big.Int
    UU1 []*big.Int
    ThresHold int
    BetaU1 []*big.Int
    VU1 []*big.Int
}

func (kg *SigningRound5Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound5Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound5Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound5Msg) GetMsgType() string {
    return "SigningRound5Msg"
}

//---------------------------------------------

type SigningRound6Msg struct {
    Base

    Delt []*big.Int
    U1Gamma *big.Int
}

func (kg *SigningRound6Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound6Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound6Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound6Msg) GetMsgType() string {
    return "SigningRound6Msg"
}

//--------------------------------------------------

type SigningRound7ComCheck struct {
    Base

    C *big.Int
    D []*big.Int

    ZKProof *ec2.ZkUProof
}

func (kg *SigningRound7ComCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound7ComCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound7ComCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound7ComCheck) GetMsgType() string {
    return "SigningRound7ComCheck"
}

//----------------------------------------

type SigningRound7DeCom struct {
    Base

    C *big.Int
    D []*big.Int
}

func (kg *SigningRound7DeCom) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound7DeCom) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound7DeCom) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound7DeCom) GetMsgType() string {
    return "SigningRound7DeCom"
}

//-------------------------------------------------

type SigningRound7Msg struct {
    Base

    DeltaSum *big.Int
    GammaX *big.Int
    GammaY *big.Int
    U1K *big.Int
    PaiPk *ec2.PublicKey
    Nt *ec2.NtildeH1H2
    UKC *big.Int
    PaiSk *ec2.PrivateKey
    U1Ra *big.Int
}

func (kg *SigningRound7Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound7Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound7Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound7Msg) GetMsgType() string {
    return "SigningRound7Msg"
}

//---------------------------------------------

type SigningRound8PDLwSlackCheck struct {
    Base

    PdlwSlackPf *ec2.PDLwSlackProof
    PdlWSlackStatement *ec2.PDLwSlackStatement
}

func (kg *SigningRound8PDLwSlackCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound8PDLwSlackCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound8PDLwSlackCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound8PDLwSlackCheck) GetMsgType() string {
    return "SigningRound8PDLwSlackCheck"
}

//---------------------------------------

type SigningRound8CalcK1R struct {
    Base

    OldK1Rx *big.Int
    OldK1Ry *big.Int
    IncK1Rx *big.Int
    IncK1Ry *big.Int
}

func (kg *SigningRound8CalcK1R) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound8CalcK1R) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound8CalcK1R) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound8CalcK1R) GetMsgType() string {
    return "SigningRound8CalcK1R"
}

//--------------------------------------------

type SigningRound8Msg struct {
    Base

    K1Rx *big.Int
    K1Ry *big.Int
    DeltaGammaGx *big.Int
    DeltaGammaGy *big.Int
    Sigma1 *big.Int
    T1X *big.Int
    T1Y *big.Int
    L1 *big.Int
}

func (kg *SigningRound8Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound8Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound8Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound8Msg) GetMsgType() string {
    return "SigningRound8Msg"
}

//-------------------------------------------

type SigningRound9Msg struct {
    Base

    S1X []*big.Int
    S1Y []*big.Int
    T1X []*big.Int
    T1Y []*big.Int
    DeltaGammaGx *big.Int
    DeltaGammaGy *big.Int
    Pkx *big.Int
    Pky *big.Int
    STProof []*ec2.STProof
}

func (kg *SigningRound9Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound9Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound9Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound9Msg) GetMsgType() string {
    return "SigningRound9Msg"
}

//----------------------------------------

type SigningRound10Msg struct {
    Base

    TxHash *big.Int
    K1 *big.Int
    R *big.Int
    Sigma1 *big.Int
}

func (kg *SigningRound10Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound10Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound10Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound10Msg) GetMsgType() string {
    return "SigningRound10Msg"
}

//-------------------------------------------

type SigningRound11Msg struct {
    Base

    S []*big.Int
}

func (kg *SigningRound11Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *SigningRound11Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *SigningRound11Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *SigningRound11Msg) GetMsgType() string {
    return "SigningRound11Msg"
}

//---------------------------------------------

type EDKGRound1Msg struct {
    Base
}

func (kg *EDKGRound1Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDKGRound1Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDKGRound1Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDKGRound1Msg) GetMsgType() string {
    return "EDKGRound1Msg"
}

//-------------------------------------------------

type EDKGRound4ComCheck struct {
    Base

    CPk [32]byte
    DPk [64]byte
    ZkPk [64]byte
}

func (kg *EDKGRound4ComCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDKGRound4ComCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDKGRound4ComCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDKGRound4ComCheck) GetMsgType() string {
    return "EDKGRound4ComCheck"
}

//------------------------------------------------------

type EDKGRound4Msg struct {
    Base

    PkSet []byte
    DPk [64]byte
    ThresHold int
    DnodeCount int
    Sk [32]byte

    Ids []*big.Int
}

func (kg *EDKGRound4Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDKGRound4Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDKGRound4Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDKGRound4Msg) GetMsgType() string {
    return "EDKGRound4Msg"
}

//-------------------------------------------

type EDKGRound6VssCheck struct {
    Base

    Share [32]byte 
    ID [32]byte
    CfsBBytes [][32]byte
}

func (kg *EDKGRound6VssCheck) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDKGRound6VssCheck) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDKGRound6VssCheck) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDKGRound6VssCheck) GetMsgType() string {
    return "EDKGRound6VssCheck"
}

//------------------------------------------------

type EDKGRound6Msg struct {
    Base

    PkSet2 []byte
    Shares [][32]byte 
    DPks [][64]byte
    CfsBBytes [][][32]byte
}

func (kg *EDKGRound6Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDKGRound6Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDKGRound6Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDKGRound6Msg) GetMsgType() string {
    return "EDKGRound6Msg"
}

//------------------------------------------------

type EDSigningRound1Msg struct {
    Base

    Sk [32]byte
    TSk [32]byte 
    FinalPkBytes [32]byte
    IDs []*big.Int
}

func (kg *EDSigningRound1Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDSigningRound1Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDSigningRound1Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDSigningRound1Msg) GetMsgType() string {
    return "EDSigningRound1Msg"
}

//-------------------------------------------------

type EDSigningRound4Msg struct {
    Base

    CRs [][32]byte
    DRs [][64]byte 
    ZkRs [][64]byte
    Message []byte
    Pkfinal [32]byte
    CurDNodeID *big.Int
    IdSign []*big.Int
    Index int
    TSk [32]byte
    R [32]byte
}

func (kg *EDSigningRound4Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDSigningRound4Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDSigningRound4Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDSigningRound4Msg) GetMsgType() string {
    return "EDSigningRound4Msg"
}

//-------------------------------------------------

type EDSigningRound6Msg struct {
    Base

    CSBs [][32]byte
    DSBs [][64]byte 
    Message []byte
    Pkfinal [32]byte
    FinalRBytes [32]byte
}

func (kg *EDSigningRound6Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDSigningRound6Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDSigningRound6Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDSigningRound6Msg) GetMsgType() string {
    return "EDSigningRound6Msg"
}

//-------------------------------------------------

type EDSigningRound7Msg struct {
    Base

    S [][32]byte
    Message []byte
    Pkfinal [32]byte
    FinalRBytes [32]byte
}

func (kg *EDSigningRound7Msg) SetBase(kt string,keyid string) {
    kg.Base.SetBase(kt,keyid)
}

func (kg *EDSigningRound7Msg) ToJson() ([]byte,error) {
    return json.Marshal(kg)
}

func (kg *EDSigningRound7Msg) ToObj(raw []byte) error {
    return json.Unmarshal(raw,kg)
}

func (kg *EDSigningRound7Msg) GetMsgType() string {
    return "EDSigningRound7Msg"
}









package keygen 

import (
	"math/big"
	"strings"
	"fmt"
	//"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
)

type LocalDNodeSaveData struct {
    //
    Sk [64]byte
    Pk [32]byte
    TSk [32]byte
    FinalPkBytes [32]byte
    //

    Ids dcrm.SortableIDSSlice 
    CurDNodeID *big.Int
}

func NewLocalDNodeSaveData(DNodeCount int) (saveData LocalDNodeSaveData) {
	saveData.Ids = nil
	saveData.CurDNodeID = nil
	return
}

func (sd *LocalDNodeSaveData) OutMap() map[string]string {
    sdout := make(map[string]string)
    sdout["Sk"] = string(sd.Sk[:])
    sdout["Pk"] = string(sd.Pk[:])
    sdout["TSk"] = string(sd.TSk[:])
    sdout["FinalPkBytes"] = string(sd.FinalPkBytes[:])

    ids := make([]string,len(sd.Ids))
    for k,v := range sd.Ids {
	ids[k] = fmt.Sprintf("%v",v)
    }
    sdout["Ids"] = strings.Join(ids,"|")

    sdout["CurDNodeID"] = fmt.Sprintf("%v",sd.CurDNodeID)

    return sdout
}

func GetLocalDNodeSaveData(data map[string]string) *LocalDNodeSaveData {

    var Sk [64]byte
    copy(Sk[:],[]byte(data["Sk"]))
    var TSk [32]byte
    copy(TSk[:],[]byte(data["TSk"]))
    var Pk [32]byte
    copy(Pk[:],[]byte(data["Pk"]))
    var FinalPkBytes [32]byte
    copy(FinalPkBytes[:],[]byte(data["FinalPkBytes"]))
    
    idstmp := strings.Split(data["Ids"],"|")
    ids := make(dcrm.SortableIDSSlice,len(idstmp))
    for k,v := range idstmp {
	ids[k],_ = new(big.Int).SetString(v,10)
    }

    curdnodeid, _ := new(big.Int).SetString(data["CurDNodeID"],10)

    sd := &LocalDNodeSaveData{Sk:Sk,TSk:TSk,Pk:Pk,FinalPkBytes:FinalPkBytes,Ids:ids,CurDNodeID:curdnodeid}
    return sd
}


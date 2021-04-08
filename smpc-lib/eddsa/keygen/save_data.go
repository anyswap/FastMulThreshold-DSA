package keygen 

import (
	"math/big"
	"strings"
	"fmt"
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"encoding/hex"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

type LocalDNodeSaveData struct {
    //
    Sk [64]byte
    Pk [32]byte
    TSk [32]byte
    FinalPkBytes [32]byte
    //

    Ids smpc.SortableIDSSlice 
    CurDNodeID *big.Int
}

func NewLocalDNodeSaveData(DNodeCount int) (saveData LocalDNodeSaveData) {
	saveData.Ids = nil
	saveData.CurDNodeID = nil
	return
}

func (sd *LocalDNodeSaveData) OutMap() map[string]string {
    sdout := make(map[string]string)

    sk := hex.EncodeToString(sd.Sk[:])
    sdout["Sk"] = sk

    pk := hex.EncodeToString(sd.Pk[:])
    sdout["Pk"] = pk

    tsk := hex.EncodeToString(sd.TSk[:])
    sdout["TSk"] = tsk

    finalpk := hex.EncodeToString(sd.FinalPkBytes[:])
    sdout["FinalPkBytes"] = finalpk

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
    sk,_ := hex.DecodeString(data["Sk"])
    copy(Sk[:],sk[:])

    var TSk [32]byte
    tsk,_ := hex.DecodeString(data["TSk"])
    copy(TSk[:],tsk[:])
    
    var Pk [32]byte
    pk,_ := hex.DecodeString(data["Pk"])
    copy(Pk[:],pk[:])
    
    var FinalPkBytes [32]byte
    finalpk,_ := hex.DecodeString(data["FinalPkBytes"])
    copy(FinalPkBytes[:],finalpk[:])
    
    idstmp := strings.Split(data["Ids"],"|")
    ids := make(smpc.SortableIDSSlice,len(idstmp))
    for k,v := range idstmp {
	ids[k],_ = new(big.Int).SetString(v,10)
    }

    curdnodeid, _ := new(big.Int).SetString(data["CurDNodeID"],10)

    sd := &LocalDNodeSaveData{Sk:Sk,TSk:TSk,Pk:Pk,FinalPkBytes:FinalPkBytes,Ids:ids,CurDNodeID:curdnodeid}

    //fmt.Printf("===============ed sign,GetLocalDNodeSaveData, save.Sk = %v,save.Pk = %v,save.TSk = %v,save.FinalPkBytes = %v, save.Ids = %v, save.CurDNodeID = %v =================\n",hex.EncodeToString(sd.Sk[:]),hex.EncodeToString(sd.Pk[:]),hex.EncodeToString(sd.TSk[:]),hex.EncodeToString(sd.FinalPkBytes[:]),sd.Ids,sd.CurDNodeID)
    return sd
}


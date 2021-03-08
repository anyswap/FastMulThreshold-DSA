package keygen 

import (
	"math/big"
	"strings"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
)

type LocalDNodeSaveData struct {
    //save to local db
    Pkx *big.Int
    Pky *big.Int
    C *big.Int

    SkU1 *big.Int
    U1PaillierSk *ec2.PrivateKey
    U1PaillierPk []*ec2.PublicKey
    U1NtildeH1H2 []*ec2.NtildeH1H2

    Ids dcrm.SortableIDSSlice 
    CurDNodeID *big.Int
}

func NewLocalDNodeSaveData(DNodeCount int) (saveData LocalDNodeSaveData) {
    	saveData.Pkx = nil
	saveData.Pky = nil
	saveData.C = nil
	saveData.SkU1 = nil
	saveData.U1PaillierSk = nil
	saveData.U1PaillierPk = make([]*ec2.PublicKey, DNodeCount)
	saveData.U1NtildeH1H2 = make([]*ec2.NtildeH1H2, DNodeCount)
	saveData.Ids = nil
	saveData.CurDNodeID = nil
	return
}

func (sd *LocalDNodeSaveData) OutMap() map[string]string {
    sdout := make(map[string]string)
    sdout["Pkx"] = fmt.Sprintf("%v",sd.Pkx)
    sdout["Pky"] = fmt.Sprintf("%v",sd.Pky)
    sdout["C"] = fmt.Sprintf("%v",sd.C)
    sdout["SkU1"] = fmt.Sprintf("%v",sd.SkU1)

    usk,err := sd.U1PaillierSk.MarshalJSON()
    if err != nil {
	return nil
    }

    sdout["U1PaillierSk"] = string(usk)

    paipk := make([]string,len(sd.U1PaillierPk))
    for k,v := range sd.U1PaillierPk {
	pk,err := v.MarshalJSON()
	if err != nil {
	    return nil
	}

	paipk[k] = string(pk)
    }

    sdout["U1PaillierPk"] = strings.Join(paipk,"|")

    nth := make([]string,len(sd.U1NtildeH1H2))
    for k,v := range sd.U1NtildeH1H2 {
	nt,err := v.MarshalJSON()
	if err != nil {
	    return nil
	}

	nth[k] = string(nt)
    }

    sdout["U1NtildeH1H2"] = strings.Join(nth,"|")

    ids := make([]string,len(sd.Ids))
    for k,v := range sd.Ids {
	ids[k] = fmt.Sprintf("%v",v)
    }
    sdout["Ids"] = strings.Join(ids,"|")

    sdout["CurDNodeID"] = fmt.Sprintf("%v",sd.CurDNodeID)

    return sdout
}

func GetLocalDNodeSaveData(data map[string]string) *LocalDNodeSaveData {
    pkx,_ := new(big.Int).SetString(data["Pkx"],10)
    pky,_ := new(big.Int).SetString(data["Pky"],10)
    c,_ := new(big.Int).SetString(data["C"],10)
    sku1,_ := new(big.Int).SetString(data["SkU1"],10)

    usk := &ec2.PrivateKey{}
    err := usk.UnmarshalJSON([]byte(data["U1PaillierSk"]))
    if err != nil {
	return nil
    }

    paipk := strings.Split(data["U1PaillierPk"],"|")
    pk := make([]*ec2.PublicKey,len(paipk))
    for k,v := range paipk {
	pktmp := &ec2.PublicKey{}
	err = pktmp.UnmarshalJSON([]byte(v))
	if err != nil {
	    return nil
	}

	pk[k] = pktmp
    }

    nth := strings.Split(data["U1NtildeH1H2"],"|")
    nt := make([]*ec2.NtildeH1H2,len(nth))
    for k,v := range nth {
	nttmp := &ec2.NtildeH1H2{}
	err = nttmp.UnmarshalJSON([]byte(v))
	if err != nil {
	    return nil
	}

	nt[k] = nttmp
    }

    idstmp := strings.Split(data["Ids"],"|")
    ids := make(dcrm.SortableIDSSlice,len(idstmp))
    for k,v := range idstmp {
	ids[k],_ = new(big.Int).SetString(v,10)
    }

    curdnodeid, _ := new(big.Int).SetString(data["CurDNodeID"],10)

    sd := &LocalDNodeSaveData{Pkx:pkx,Pky:pky,C:c,SkU1:sku1,U1PaillierSk:usk,U1PaillierPk:pk,U1NtildeH1H2:nt,Ids:ids,CurDNodeID:curdnodeid}
    return sd
}


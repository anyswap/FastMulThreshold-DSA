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

package smpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"compress/zlib"
	"container/list"
	"encoding/gob"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/sha3"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/hexutil"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ed"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"io"
	"errors"
	"sort"
	"github.com/anyswap/FastMulThreshold-DSA/crypto"
       "github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
       "encoding/hex"
       "github.com/fsn-dev/cryptoCoins/coins"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	msgsigsha3 "golang.org/x/crypto/sha3"
)

//---------------------------------------------------------------------------

// CmdReq interface of request keygen/sign/reshare
type CmdReq interface {
	GetReplyFromGroup(wid int, gid string, initiator string) []NodeReply
	GetReqAddrKeyByKey(key string) string
	GetRawReply(ret *common.SafeMap, reply *RawReply)
	CheckReply(ac *AcceptReqAddrData, l *list.List, key string) bool
	DoReq(raw string, workid int, sender string, ch chan interface{}) bool
	GetGroupSigs(txdata []byte) (string, string, string, string)
	CheckTxData(txdata []byte, from string, nonce uint64) (string, string, string, interface{}, error)
	DisAcceptMsg(raw string, workid int, key string)
}

//-----------------------------------------------------------------------

// RPCSmpcRes smpc rpc result
type RPCSmpcRes struct {
	Ret string
	Tip string
	Err error
}

// GetChannelValue get channel value within the specified timeout 
func GetChannelValue(t int, obj interface{}) (string, string, error) {
    	if t <= 0 || obj == nil {
	    return "","",errors.New("param error")
	}

	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(time.Duration(t) * time.Second) //1000 == 1s
		timeout <- true
	}()

	switch ch := obj.(type) {
	case chan interface{}:
		select {
		case v := <-ch:
			ret, ok := v.(RPCSmpcRes)
			if ok {
				return ret.Ret, ret.Tip, ret.Err
			}
		case <-timeout:
			return "", "", fmt.Errorf("get RpcSmpcRes result fail")
		}
	case chan string:
		select {
		case v := <-ch:
			return v, "", nil
		case <-timeout:
			return "", "", fmt.Errorf("get string result fail")
		}
	case chan int64:
		select {
		case v := <-ch:
			return strconv.Itoa(int(v)), "", nil
		case <-timeout:
			return "", "", fmt.Errorf("get int64 result fail")
		}
	case chan int:
		select {
		case v := <-ch:
			return strconv.Itoa(v), "", nil
		case <-timeout:
			return "", "", fmt.Errorf("get int result fail")
		}
	case chan bool:
		select {
		case v := <-ch:
			if !v {
				return "false", "", nil
			}

			return "true", "", nil
		case <-timeout:
			return "", "", fmt.Errorf("get bool result fail")
		}
	default:
		return "", "unknown channel type", fmt.Errorf("unknown channel type")
	}

	return "", "unknown error", fmt.Errorf("unknown channel type")
}

//----------------------------------------------------------------------------------------

// Encode2 encode obj to string
func Encode2(obj interface{}) (string, error) {
    	if obj == nil {
	    return "",errors.New("param error")
	}

	switch ch := obj.(type) {
	case *PubKeyData:
		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptReqAddrData:
		ret, err := json.Marshal(ch)
		if err != nil {
		    log.Error("========================Encode2,marshal AcceptReqAddrData type fail====================","err",err)
			return "", err
		}
		return string(ret), nil
	case *AcceptSignData:
		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptReShareData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	default:
		return "", fmt.Errorf("encode fail")
	}
}

// Decode2 decode string to obj by data type
func Decode2(s string, datatype string) (interface{}, error) {
    	if s == "" || datatype == "" {
	    return nil,errors.New("param error")
	}

	if datatype == "PubKeyData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PubKeyData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReqAddrData" {
		var m AcceptReqAddrData
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    log.Error("========================Decode2,unmarshal AcceptReqAddrData type fail====================","err",err)
			return nil, err
		}

		log.Debug("========================Decode2,unmarshal AcceptReqAddrData type success====================","m.FixedApprover",m.FixedApprover)
		return &m, nil
	}

	if datatype == "AcceptSignData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptSignData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReShareData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReShareData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	return nil, fmt.Errorf("decode fail")
}

//--------------------------------------------------------------------------------------

// Compress compress the bytes,and return the result
func Compress(c []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("compress fail")
	}

	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, zlib.BestCompression-1)
	if err != nil {
		return "", err
	}

	_, err = w.Write(c)
	if err != nil {
		return "", err
	}

	w.Close()

	s := in.String()
	return s, nil
}

// UnCompress uncompress the string
func UnCompress(s string) (string, error) {

	if s == "" {
		return "", fmt.Errorf("param error")
	}

	var data bytes.Buffer
	data.Write([]byte(s))

	r, err := zlib.NewReader(&data)
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

//---------------------------------------------------------------------------------------

// ByteHash bytehash type define
type ByteHash [32]byte

// Hex hash to hex string
func (h ByteHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h ByteHash) {
    	if data == nil {
	    return h
	}

	d := sha3.NewKeccak256()
	for _, b := range data {
		_, err := d.Write(b)
		if err != nil {
			return h
		}
		if err != nil {
			return h
		}
	}
	d.Sum(h[:0])
	return h
}

//----------------------------------------------------------------------------------------------

// DoubleHash  The EnodeID is converted into a hash value according to different keytypes 
func DoubleHash(id string, keytype string) *big.Int {
    	if id == "" {
	    return nil
	}

	// Generate the random num
	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	_, err := keccak256.Write([]byte(id))
	if err != nil {
		return nil
	}

	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	_, err = sha3256.Write(digestKeccak256)
	if err != nil {
		return nil
	}

	if keytype == "ED25519" {
		var digest [32]byte
		copy(digest[:], sha3256.Sum(nil))

		//////
		var zero [32]byte
		var one [32]byte
		one[0] = 1
		ed.ScMulAdd(&digest, &digest, &one, &zero)
		//////
		digestBigInt := new(big.Int).SetBytes(digest[:])
		return digestBigInt
	}

	digest := sha3256.Sum(nil)
	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)
	return digestBigInt
}

// GetIDs Convert each ID into a hash value according to different keytypes and put it into an array for sorting 
func GetIDs(keytype string, groupid string) smpclib.SortableIDSSlice {
    	if groupid == "" {
	    return nil
	}

	var ids smpclib.SortableIDSSlice
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid := DoubleHash(node2, keytype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)
	return ids
}

// GetCurNodeUID get current node uid,gid is the `keygen gid`
// return (index,UID)
func GetCurNodeUID(EnodeID string, keytype string, gid string) (int,*big.Int) {
	UID, err := crypto.LoadDNodeIDInTEE(IdFile)
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory"){
			k, UID := GetNodeUID(EnodeID, keytype, gid)
			err = crypto.SaveDNodeIDInTEE(IdFile, UID)
			if err != nil {
				common.Error("==========GetCurNodeUID, save dnodeid failed in TEE============","err",err)
				return -1, nil
			}
			return k, UID
		}else{
			common.Error("==========GetCurNodeUID, load dnodeid failed in TEE============","err",err)
			return -1, nil
		}
	} else {
		return 0, UID
	}
}

func GetNodeUID(EnodeID string,keytype string,gid string) (int,*big.Int) {
    if EnodeID == "" || gid == "" {
	return -1,nil
    }

    uid := DoubleHash(EnodeID,keytype)
    if uid == nil {
	return -1,nil
    }
    
    _, nodes := GetGroup(gid)
    others := strings.Split(nodes, common.Sep2)
    
    ids := GetIDs(keytype,gid)
    if len(ids) == 0 {
	return -1,nil
    }

    for k,v := range ids {
	if v.Cmp(uid) == 0 {
	    if (k+1) <= len(others) {
		return k,big.NewInt(int64(k+1))
	    }
	}
    }

    return -1,nil
}

// GetGroupNodeUIDs get the uids of node in group subgid
// gid is the `keygen gid`
func GetGroupNodeUIDs(keytype string,gid string,subgid string) smpclib.SortableIDSSlice {
    if gid == "" || subgid == "" {
	return nil
    }

    allids := GetIDs(keytype,gid)
    if len(allids) == 0 {
	return nil
    }

    var ids smpclib.SortableIDSSlice
    _, nodes := GetGroup(subgid)
    others := strings.Split(nodes, common.Sep2)
    for _, v := range others {
	    node2 := ParseNode(v) //bug??
	    id := DoubleHash(node2, keytype)
	    if id == nil {
		continue
	    }

	    for kk,vv := range allids {
		if vv == nil {
		    continue
		}

		if vv.Cmp(id) == 0 {
		    ids = append(ids,big.NewInt(int64(kk+1)))
		    break
		}
	    }
    }

    sort.Sort(ids)
    return ids
}

//-----------------------------------------------------------------------------

// GetKeyFromData get special tx data type from command data or accept data
func GetKeyFromData(txdata []byte) string {
	if txdata == nil {
		return ""
	}

	req := TxDataReqAddr{}
	err := json.Unmarshal(txdata, &req)
	if err == nil && req.TxType == "REQSMPCADDR" {
		return ""
	}

	sig := TxDataSign{}
	err = json.Unmarshal(txdata, &sig)
	if err == nil && sig.TxType == "SIGN" {
		return ""
	}

	pre := TxDataPreSignData{}
	err = json.Unmarshal(txdata, &pre)
	if err == nil && pre.TxType == "PRESIGNDATA" {
		return ""
	}

	rh := TxDataReShare{}
	err = json.Unmarshal(txdata, &rh)
	if err == nil && rh.TxType == "RESHARE" {
		return ""
	}

	acceptreq := TxDataAcceptReqAddr{}
	err = json.Unmarshal(txdata, &acceptreq)
	if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
		return acceptreq.Key
	}

	acceptsig := TxDataAcceptSign{}
	err = json.Unmarshal(txdata, &acceptsig)
	if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
		return acceptsig.Key
	}

	acceptrh := TxDataAcceptReShare{}
	err = json.Unmarshal(txdata, &acceptrh)
	if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
		return ""
	}

	return ""
}

// GetTxTypeFromData get special tx data type from command data or accept data
func GetTxTypeFromData(txdata []byte) string {
	if txdata == nil {
		return ""
	}

	req := TxDataReqAddr{}
	err := json.Unmarshal(txdata, &req)
	if err == nil && req.TxType == "REQSMPCADDR" {
		return "REQSMPCADDR"
	}

	sig := TxDataSign{}
	err = json.Unmarshal(txdata, &sig)
	if err == nil && sig.TxType == "SIGN" {
		return "SIGN"
	}

	pre := TxDataPreSignData{}
	err = json.Unmarshal(txdata, &pre)
	if err == nil && pre.TxType == "PRESIGNDATA" {
		return "PRESIGNDATA"
	}

	rh := TxDataReShare{}
	err = json.Unmarshal(txdata, &rh)
	if err == nil && rh.TxType == "RESHARE" {
		return "RESHARE"
	}

	acceptreq := TxDataAcceptReqAddr{}
	err = json.Unmarshal(txdata, &acceptreq)
	if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
		return "ACCEPTREQADDR"
	}

	acceptsig := TxDataAcceptSign{}
	err = json.Unmarshal(txdata, &acceptsig)
	if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
		return "ACCEPTSIGN"
	}

	acceptrh := TxDataAcceptReShare{}
	err = json.Unmarshal(txdata, &acceptrh)
	if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
		return "ACCEPTRESHARE"
	}

	return ""
}

// GetKeyTypeFromData get special tx data type from command data or accept data
func GetKeyTypeFromData(txdata []byte) string {
	if txdata == nil {
		return ""
	}

	req := TxDataReqAddr{}
	err := json.Unmarshal(txdata, &req)
	if err == nil && req.TxType == "REQSMPCADDR" {
		return req.Keytype
	}

	sig := TxDataSign{}
	err = json.Unmarshal(txdata, &sig)
	if err == nil && sig.TxType == "SIGN" {
		return sig.Keytype
	}

	pre := TxDataPreSignData{}
	err = json.Unmarshal(txdata, &pre)
	if err == nil && pre.TxType == "PRESIGNDATA" {
		return pre.KeyType 
	}

	rh := TxDataReShare{}
	err = json.Unmarshal(txdata, &rh)
	if err == nil && rh.TxType == "RESHARE" {
		return rh.Keytype 
	}

	acceptreq := TxDataAcceptReqAddr{}
	err = json.Unmarshal(txdata, &acceptreq)
	if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
	    exsit, da := GetPubKeyData([]byte(acceptreq.Key))
	    if !exsit {
		exsit, da = GetReqAddrInfoData([]byte(acceptreq.Key))
		if !exsit {
		    return ""
		}
	    }

	    ac, ok := da.(*AcceptReqAddrData)
	    if !ok {
		return ""
	    }

	    return ac.Cointype
	}

	acceptsig := TxDataAcceptSign{}
	err = json.Unmarshal(txdata, &acceptsig)
	if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
	    exsit, da := GetPubKeyData([]byte(acceptsig.Key))
	    if !exsit {
		exsit, da = GetSignInfoData([]byte(acceptsig.Key))
		if !exsit {
		    return ""
		}
	    }

	    ac, ok := da.(*AcceptSignData)
	    if !ok {
		return ""
	    }

	    return ac.Keytype
	}

	acceptrh := TxDataAcceptReShare{}
	err = json.Unmarshal(txdata, &acceptrh)
	if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
	    exsit, da := GetPubKeyData([]byte(acceptrh.Key))
	    if !exsit {
		exsit, da = GetReShareInfoData([]byte(acceptrh.Key))
		if !exsit {
		    return ""
		}
	    }

	    ac, ok := da.(*AcceptReShareData)
	    if !ok {
		return ""
	    }

	    return ac.Keytype
	}

	return ""
}

type MsgSig struct {
    Rsv string
    MsgType string
    Msg string
}

func GetMsgSigHash(message []byte) []byte {
    msglen := []byte(strconv.Itoa(len(message)))

    hash := msgsigsha3.NewLegacyKeccak256()
    hash.Write([]byte{0x19})
    hash.Write([]byte("Ethereum Signed Message:"))
    hash.Write([]byte{0x0A})
    hash.Write(msglen)
    hash.Write(message)
    buf := hash.Sum([]byte{})
    return buf
}

// CheckRaw check command data or accept data
func CheckRaw(raw string) (string, string, string, interface{}, error) {
	if raw == "" {
		return "", "", "", nil, fmt.Errorf("raw data empty")
	}

	var key string
	var from string
	var txtype string
	var nonce uint64
	var msgsig bool
	var data []byte
	var rsv string
	var keytype string

	m := MsgSig{}
       err := json.Unmarshal([]byte(raw), &m)
       if err == nil {
	   txtype = m.MsgType
	   msgsig = true
	   data = []byte(m.Msg)
	   rsv = m.Rsv
	   log.Debug("======================CheckRaw,get msg sig data===================","txtype",txtype,"msgsig",msgsig,"data",string(data),"wallet rsv",rsv,"raw",raw)
       } else {
	    tx := new(types.Transaction)
	    raws := common.FromHex(raw)
	    if err := rlp.DecodeBytes(raws, tx); err != nil {
		log.Error("======================CheckRaw,decode raw tx data fail===================","raw",raw,"err",err)
		    return "", "", "", nil, err
	    }
 
	    signer := types.NewEIP155Signer(big.NewInt(30400)) //
	    from2, err := types.Sender(signer, tx)
	    if err != nil {
		log.Error("======================CheckRaw,check raw tx data fail===================","raw",raw,"err",err)
		    return "", "", "", nil, err
	    }
	   
	    data = tx.Data()
	    txtype = GetTxTypeFromData(data)
	    nonce = tx.Nonce()
	    from = from2.Hex()
	    msgsig = false 
	    key = GetKeyFromData(data)
	    keytype = GetKeyTypeFromData(data)
	    log.Debug("======================CheckRaw,get raw tx data===================","from",from,"txtype",txtype,"data",string(data),"nonce",nonce,"msgsig",msgsig,"key",key,"raw",raw,"tx",*tx,"keytype",keytype)
       }
 
	var smpcreq CmdReq
	switch txtype {
	case "REQSMPCADDR":
		smpcreq = &ReqSmpcAddr{}
		if msgsig {
		    req := TxDataReqAddr{}
		   err := json.Unmarshal(data, &req)
		   if err == nil {
		       from = req.Account
		       non,err := strconv.Atoi(req.Nonce)
		       if err != nil {
			    log.Error("======================CheckRaw,get keygen tx data with msg sig,get nonce fail,set to 0===================","from",from,"data",string(data),"err",err,"raw",raw,"data.nonce",req.Nonce)
			   nonce = 0
		       } else {
			   nonce = uint64(non)
		       }

		       keytype = req.Keytype
			log.Debug("======================CheckRaw,get keygen tx data with msg sig===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"keytype",keytype)
		   } else {
			log.Error("======================CheckRaw,get keygen tx data with msg sig,unmarshal data error===================","from",from,"data",string(data),"err",err,"raw",raw)
		   }
		}
               break
	case "SIGN":
		smpcreq = &ReqSmpcSign{}
		if msgsig {
		    req := TxDataSign{}
		      err := json.Unmarshal(data, &req)
		      if err == nil {
			   from = req.Account
			   non,err := strconv.Atoi(req.Nonce)
			   if err != nil {
			       nonce = 0
				log.Error("======================CheckRaw,get sign tx data with msg sig,get nonce fail,set to 0===================","from",from,"data",string(data),"err",err,"raw",raw,"data.nonce",req.Nonce)
			   } else {
			       nonce = uint64(non)
			   }

			   keytype = req.Keytype
			log.Debug("======================CheckRaw,get sign tx data with msg sig===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"keytype",keytype)
		       } else {
			    log.Error("======================CheckRaw,get sign tx data with msg sig,unmarshal data error===================","from",from,"data",string(data),"err",err,"raw",raw)
		       }
		}
		break
	case "PRESIGNDATA":
		smpcreq = &ReqSmpcSign{}
		if msgsig {
		    req := TxDataPreSignData{}
		   err := json.Unmarshal(data, &req)
		   if err == nil {
		       from = req.Account
		       non,err := strconv.Atoi(req.Nonce)
		       if err != nil {
			   nonce = 0
		       } else {
			   nonce = uint64(non)
		       }

		       keytype = req.KeyType
			log.Debug("======================CheckRaw,get pre-sign data with msg sig===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"key",key,"keytype",keytype)
		   }
		}
		break
	case "RESHARE":
		smpcreq = &ReqSmpcReshare{}
		if msgsig {
		    req := TxDataReShare{}
		   err := json.Unmarshal(data, &req)
		   if err == nil {
		       from = req.Account
		       non,err := strconv.Atoi(req.Nonce)
		       if err != nil {
			   nonce = 0
		       } else {
			   nonce = uint64(non)
		       }

		       keytype = req.Keytype
		   }
		}
		break
	case "ACCEPTREQADDR":
		smpcreq = &ReqSmpcAddr{}
		if msgsig {
		    req := TxDataAcceptReqAddr{}
		   err := json.Unmarshal(data, &req)
		   if err == nil {
		       from = req.Account
		       non,err := strconv.Atoi(req.Nonce)
		       if err != nil {
			   nonce = 0
			    log.Error("======================CheckRaw,get keygen accept data with msg sig,get nonce fail,set to 0===================","from",from,"data",string(data),"err",err,"raw",raw,"data.nonce",req.Nonce,"key",req.Key)
		       } else {
			   nonce = uint64(non)
		       }

			key = req.Key
			keytype = GetKeyTypeFromData(data)
			log.Debug("======================CheckRaw,get keygen accept data with msg sig===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"key",key,"keytype",keytype)
		   } else {
			log.Debug("======================CheckRaw,get keygen accept data with msg sig,unmarsh data error===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"key",key,"err",err)
		   }
		}
		break
	case "ACCEPTSIGN":
		smpcreq = &ReqSmpcSign{}
		if msgsig {
		    req := TxDataAcceptSign{}
		   err := json.Unmarshal(data, &req)
		   if err == nil {
		       from = req.Account
		       non,err := strconv.Atoi(req.Nonce)
		       if err != nil {
			   nonce = 0
			    log.Error("======================CheckRaw,get sign accept data with msg sig,get nonce fail,set to 0===================","from",from,"data",string(data),"err",err,"raw",raw,"data.nonce",req.Nonce,"key",req.Key)
		       } else {
			   nonce = uint64(non)
		       }

			key = req.Key
			keytype = GetKeyTypeFromData(data)
			log.Debug("======================CheckRaw,get sign accept data with msg sig===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"key",key,"keytype",keytype)
		   } else {
			log.Debug("======================CheckRaw,get sign accept data with msg sig,unmarsh data error===================","from",from,"data",string(data),"raw",raw,"nonce",nonce,"key",key,"err",err)
		   }
		}
		break
	case "ACCEPTRESHARE":
		smpcreq = &ReqSmpcReshare{}
		if msgsig {
		    req := TxDataAcceptReShare{}
		   err := json.Unmarshal(data, &req)
		   if err == nil {
		       from = req.Account
			log.Debug("======================CheckRaw,get accept signing data with msg sig===================","from",from)
		       non,err := strconv.Atoi(req.Nonce)
		       if err != nil {
			   nonce = 0
		       } else {
			   nonce = uint64(non)
		       }
			
		       keytype = GetKeyTypeFromData(data)
		   }
		}
		break
	default:
		return "", "", "", nil, fmt.Errorf("Unsupported request type")
	}

	//check msg sig
	if msgsig {
	   sig := common.FromHex(rsv)
	   if sig == nil {
		log.Error("======================CheckRaw,get sig fail===================","from",from,"rsv",rsv,"data",string(data),"raw",raw)
	       return "", "", "", nil, fmt.Errorf("verify sig fail")
	   }

	   //hash := crypto.Keccak256([]byte(header),data)
	   hash := GetMsgSigHash(data)
	   hashtmp := hex.EncodeToString(hash) // 04.....
	   public,err := crypto.SigToPub(hash,sig)
	   if err != nil {
		log.Error("======================CheckRaw,recover pubkey fail===================","from",from,"rsv",rsv,"data",string(data),"err",err,"hash",hashtmp,"raw",raw)
	       return "", "", "", nil,err
	   }

	   pub := secp256k1.S256(keytype).Marshal(public.X,public.Y)
	   pub2 := hex.EncodeToString(pub) // 04.....
	   // pub2: 04730c8fc7142d15669e8329138953d9484fd4cce0c690e35e105a9714deb741f10b52be1c5d49eeeb6f00aab8f3d2dec4e3352d0bf    56bdbc2d86cb5f89c8e90d0
	   h := coins.NewCryptocoinHandler("ETH")
	   if h == nil {
		log.Error("======================CheckRaw,get smpc addr fail===================","from",from,"rsv",rsv,"data",string(data),"hash",hashtmp,"pub",pub2,"raw",raw)
	       return "", "", "", nil,errors.New("get smpc addr fail")
	   }
	   ctaddr, err := h.PublicKeyToAddress(pub2)
	   if err != nil {
		log.Error("======================CheckRaw,pubkey to addr fail===================","from",from,"rsv",rsv,"data",string(data),"err",err,"hash",hashtmp,"pub",pub2,"raw",raw)
	       return "", "", "", nil,err
	   }
	   if !strings.EqualFold(ctaddr,from) {
		log.Error("======================CheckRaw,verify sig fail===================","from",from,"rsv",rsv,"data",string(data),"ctaddr",ctaddr,"pub",pub2,"hash",hashtmp,"raw",raw)
	       return "", "", "", nil, fmt.Errorf("verify sig fail")
	   }
	   //
	}

	//
	if key != "" {
	    w, err := FindWorker(key)
	    if err != nil || w == nil {
		    log.Debug("======================CheckRaw,not found worker===================","from",from,"data",string(data),"nonce",nonce,"key",key)
		    c1data := strings.ToLower(key + "-" + from)
		    C1Data.WriteMap(c1data, raw)
	    }
	}
	//
       return smpcreq.CheckTxData(data, from, nonce)
}

func IsInGroup(gid string) bool {
    if gid == "" {
	return false
    }
    
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	if strings.EqualFold(curEnode,node2) {
	    return true 
	}
    }

    return false
}


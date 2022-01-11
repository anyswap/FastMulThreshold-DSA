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
			return "", "", fmt.Errorf("get RpcDcrmRes result fail")
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
			return nil, err
		}

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
	}
	d.Sum(h[:0])
	return h
}

//----------------------------------------------------------------------------------------------

// DoubleHash  The EnodeID is converted into a hash value according to different keytypes 
func DoubleHash(id string, keytype string) *big.Int {
    	if id == "" || keytype == "" {
	    return nil
	}

	// Generate the random num
	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	_, err := keccak256.Write([]byte(id))
	if err != nil {
		return nil
	}

	_,err = keccak256.Write([]byte("hello multichain"))
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

	_,err = sha3256.Write([]byte("hello multichain"))
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
    	if keytype == "" || groupid == "" {
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

// GetNodeUID get current node uid,gid is the `keygen gid`
// return (index,UID)
func GetNodeUID(EnodeID string,keytype string,gid string) (int,*big.Int) {
    if EnodeID == "" || keytype == "" || gid == "" {
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
    if keytype == "" || gid == "" || subgid == "" {
	return nil
    }

    allids := GetIDs(keytype,gid)

    var ids smpclib.SortableIDSSlice
    _, nodes := GetGroup(subgid)
    others := strings.Split(nodes, common.Sep2)
    for _, v := range others {
	    node2 := ParseNode(v) //bug??
	    id := DoubleHash(node2, keytype)
	    for kk,vv := range allids {
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

// CheckRaw check command data or accept data
func CheckRaw(raw string) (string, string, string, interface{}, error) {
	if raw == "" {
		return "", "", "", nil, fmt.Errorf("raw data empty")
	}

	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", "", "", nil, err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	from, err := types.Sender(signer, tx)
	if err != nil {
		return "", "", "", nil, err
	}

	var smpcreq CmdReq
	txtype := GetTxTypeFromData(tx.Data())
	switch txtype {
	case "REQSMPCADDR":
		smpcreq = &ReqSmpcAddr{}
	case "SIGN":
		smpcreq = &ReqSmpcSign{}
	case "PRESIGNDATA":
		smpcreq = &ReqSmpcSign{}
	case "RESHARE":
		smpcreq = &ReqSmpcReshare{}
	case "ACCEPTREQADDR":
		smpcreq = &ReqSmpcAddr{}
	case "ACCEPTSIGN":
		smpcreq = &ReqSmpcSign{}
	case "ACCEPTRESHARE":
		smpcreq = &ReqSmpcReshare{}
	default:
		return "", "", "", nil, fmt.Errorf("Unsupported request type")
	}

	return smpcreq.CheckTxData(tx.Data(), from.Hex(), tx.Nonce())
}


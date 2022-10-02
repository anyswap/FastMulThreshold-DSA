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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	dberrors "github.com/syndtr/goleveldb/leveldb/errors"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
    	// PrePubDataCount the max count of pre-sign data of special groupid and pubkey
	PrePubDataCount   = 2000

	// PreBip32DataCount the max count of pre-sign data of special groupid and pubkey for bip32
	PreBip32DataCount = 4

	// PreSigal map
	PreSigal          = common.NewSafeMap(10)

	// PrePubGids map
	PrePubGids        = common.NewSafeMap(10)
)

//------------------------------------------------

// PreSign the data of presign cmd 
type PreSign struct {
	Pub       string
	InputCode string //for bip32
	Gid       string
	Nonce     string
	Index     int // pre-sign data index
	KeyType string
}

// MarshalJSON marshal PreSign data struct to json byte
func (ps *PreSign) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Pub   string `json:"Pub"`
		Gid   string `json:"Gid"`
		Nonce string `json:"Nonce"`
		Index string `json:"Index"`
		KeyType string `json:"KeyType"`
	}{
		Pub:   ps.Pub,
		Gid:   ps.Gid,
		Nonce: ps.Nonce,
		Index: strconv.Itoa(ps.Index),
		KeyType: ps.KeyType,
	})
}

// UnmarshalJSON unmarshal json byte to PreSign data struct
func (ps *PreSign) UnmarshalJSON(raw []byte) error {
	var pre struct {
		Pub   string `json:"Pub"`
		Gid   string `json:"Gid"`
		Nonce string `json:"Nonce"`
		Index string `json:"Index"`
		KeyType string `json:"KeyType"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	ps.Pub = pre.Pub
	ps.Gid = pre.Gid
	ps.Nonce = pre.Nonce
	ps.Index, _ = strconv.Atoi(pre.Index)
	ps.KeyType = pre.KeyType
	return nil
}

//-------------------------------------------

// PreSignData the pre-sign data
type PreSignData struct {
	Key    string
	K1     *big.Int
	R      *big.Int
	Ry     *big.Int
	Sigma1 *big.Int
	Gid    string
	Used   bool
	Index  int
}

// MarshalJSON marshal PreSignData data struct to json byte
func (psd *PreSignData) MarshalJSON() ([]byte, error) {
	used := "false"
	if psd.Used == true {
		used = "true"
	}

	return json.Marshal(struct {
		Key    string `json:"Key"`
		K1     string `json:"K1"`
		R      string `json:"R"`
		Ry     string `json:"Ry"`
		Sigma1 string `json:"Sigma1"`
		Gid    string `json:"Gid"`
		Used   string `json:"Used"`
		Index  string `json:"Index"`
	}{
		Key:    psd.Key,
		K1:     fmt.Sprintf("%v", psd.K1),
		R:      fmt.Sprintf("%v", psd.R),
		Ry:     fmt.Sprintf("%v", psd.Ry),
		Sigma1: fmt.Sprintf("%v", psd.Sigma1),
		Gid:    psd.Gid,
		Used:   used,
		Index:  strconv.Itoa(psd.Index),
	})
}

// UnmarshalJSON unmarshal json byte to PreSignData data struct
func (psd *PreSignData) UnmarshalJSON(raw []byte) error {
	var pre struct {
		Key    string `json:"Key"`
		K1     string `json:"K1"`
		R      string `json:"R"`
		Ry     string `json:"Ry"`
		Sigma1 string `json:"Sigma1"`
		Gid    string `json:"Gid"`
		Used   string `json:"Used"`
		Index  string `json:"Index"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	psd.Key = pre.Key
	psd.K1, _ = new(big.Int).SetString(pre.K1, 10)
	psd.R, _ = new(big.Int).SetString(pre.R, 10)
	psd.Ry, _ = new(big.Int).SetString(pre.Ry, 10)
	psd.Sigma1, _ = new(big.Int).SetString(pre.Sigma1, 10)
	psd.Gid = pre.Gid
	if pre.Used == "true" {
		psd.Used = true
	} else {
		psd.Used = false
	}
	psd.Index, _ = strconv.Atoi(pre.Index)

	return nil
}

//---------------------------------------

// PickHashData hash -- > pre-sign data that be picked
type PickHashData struct {
	Hash string
	Pre  *PreSignData
}

// MarshalJSON marshal *PickHashData  to json byte
func (Phd *PickHashData) MarshalJSON() ([]byte, error) {
	if Phd.Pre == nil {
		return nil, errors.New("get pre-sign data fail")
	}

	s, err := Phd.Pre.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return json.Marshal(struct {
		Hash     string `json:"Hash"`
		PickData string `json:"PickData"`
	}{
		Hash:     Phd.Hash,
		PickData: string(s),
	})
}

// UnmarshalJSON unmarshal json byte to *PiskHashData
func (Phd *PickHashData) UnmarshalJSON(raw []byte) error {
	var phd struct {
		Hash     string `json:"Hash"`
		PickData string `json:"PickData"`
	}
	if err := json.Unmarshal(raw, &phd); err != nil {
		return err
	}

	Phd.Hash = phd.Hash

	pre := &PreSignData{}
	err := pre.UnmarshalJSON([]byte(phd.PickData))
	if err != nil {
		return err
	}

	Phd.Pre = pre

	return nil
}

//--------------------------------------------------

// PickHashKey hash --- > the key of picked pre-sign data
type PickHashKey struct {
	Hash    string
	PickKey string
}

// MarshalJSON marshal *PickHashKey to json byte
func (Phk *PickHashKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Hash    string `json:"Hash"`
		PickKey string `json:"PickKey"`
	}{
		Hash:    Phk.Hash,
		PickKey: Phk.PickKey,
	})
}

// UnmarshalJSON unmarshal json byte to *PickHashKey
func (Phk *PickHashKey) UnmarshalJSON(raw []byte) error {
	var phk struct {
		Hash    string `json:"Hash"`
		PickKey string `json:"PickKey"`
	}
	if err := json.Unmarshal(raw, &phk); err != nil {
		return err
	}

	Phk.Hash = phk.Hash
	Phk.PickKey = phk.PickKey

	return nil
}

//----------------------------------------------------------------

// SignBrocastData the data (sign raw + the key of picked pre-sign data ) brocast to group
type SignBrocastData struct {
	Raw      string
	PickHash []*PickHashKey
}

// MarshalJSON marshal *SignBrocastData to json byte
func (Sbd *SignBrocastData) MarshalJSON() ([]byte, error) {
	ph := make([]string, 0)
	for _, v := range Sbd.PickHash {
		s, err := v.MarshalJSON()
		if err != nil {
			return nil, err
		}

		ph = append(ph, string(s))
	}

	var phs string

	if len(ph) != 0 {
	    phs = strings.Join(ph, "|")
	}

	return json.Marshal(struct {
		Raw      string `json:"Raw"`
		PickHash string `json:"PickHash"`
	}{
		Raw:      Sbd.Raw,
		PickHash: phs,
	})
}

// UnmarshalJSON unmarshal json byte to *SignBrocastData
func (Sbd *SignBrocastData) UnmarshalJSON(raw []byte) error {
	var sbd struct {
		Raw      string `json:"Raw"`
		PickHash string `json:"PickHash"`
	}
	if err := json.Unmarshal(raw, &sbd); err != nil {
		return err
	}

	Sbd.Raw = sbd.Raw

	pickhash := make([]*PickHashKey, 0)
	var phs []string
	if sbd.PickHash != "" {
	    phs = strings.Split(sbd.PickHash, "|")
	    for _, v := range phs {
		    vv := &PickHashKey{}
		    if err := vv.UnmarshalJSON([]byte(v)); err != nil {
			    return err
		    }

		    pickhash = append(pickhash, vv)
	    }
	}

	Sbd.PickHash = pickhash
	return nil
}

//-------------------------------------------------------

// SignSubGidBrocastData the data (sign raw + the key of picked pre-sign data ) brocast to group
type SignSubGidBrocastData struct {
	Raw      string
	PickHash []*PickHashKey
	SubGid string
}

// MarshalJSON marshal *SignSubGidBrocastData to json byte
func (Sbd *SignSubGidBrocastData) MarshalJSON() ([]byte, error) {
	ph := make([]string, 0)
	for _, v := range Sbd.PickHash {
		s, err := v.MarshalJSON()
		if err != nil {
			return nil, err
		}

		ph = append(ph, string(s))
	}

	var phs string

	if len(ph) != 0 {
	    phs = strings.Join(ph, "|")
	}

	return json.Marshal(struct {
		Raw      string `json:"Raw"`
		PickHash string `json:"PickHash"`
		SubGid      string `json:"SubGid"`
	}{
		Raw:      Sbd.Raw,
		PickHash: phs,
		SubGid: Sbd.SubGid,
	})
}

// UnmarshalJSON unmarshal json byte to *SignSubGidBrocastData
func (Sbd *SignSubGidBrocastData) UnmarshalJSON(raw []byte) error {
	var sbd struct {
		Raw      string `json:"Raw"`
		PickHash string `json:"PickHash"`
		SubGid      string `json:"SubGid"`
	}
	if err := json.Unmarshal(raw, &sbd); err != nil {
		return err
	}

	Sbd.Raw = sbd.Raw

	pickhash := make([]*PickHashKey, 0)
	var phs []string
	if sbd.PickHash != "" {
	    phs = strings.Split(sbd.PickHash, "|")
	    for _, v := range phs {
		    vv := &PickHashKey{}
		    if err := vv.UnmarshalJSON([]byte(v)); err != nil {
			    return err
		    }

		    pickhash = append(pickhash, vv)
	    }
	}

	Sbd.PickHash = pickhash
	Sbd.SubGid = sbd.SubGid
	return nil
}

//-------------------------------------------------------

// SignPickData raw + (hash,picked pre-sign data)
type SignPickData struct {
	Raw      string
	PickData []*PickHashData
}

// MarshalJSON marshal *SignPickData to json byte
func (Spd *SignPickData) MarshalJSON() ([]byte, error) {
	ph := make([]string, 0)
	for _, v := range Spd.PickData {
		s, err := v.MarshalJSON()
		if err != nil {
			return nil, err
		}

		ph = append(ph, string(s))
	}

	var phs string
	if len(ph) != 0 {
	    phs = strings.Join(ph, "|")
	}

	return json.Marshal(struct {
		Raw      string `json:"Raw"`
		PickData string `json:"PickData"`
	}{
		Raw:      Spd.Raw,
		PickData: phs,
	})
}

// UnmarshalJSON unmarshal json byte to *SignPickData
func (Spd *SignPickData) UnmarshalJSON(raw []byte) error {
	var spd struct {
		Raw      string `json:"Raw"`
		PickData string `json:"PickData"`
	}
	if err := json.Unmarshal(raw, &spd); err != nil {
		return err
	}

	Spd.Raw = spd.Raw

	pickdata := make([]*PickHashData, 0)
	var phs []string

	if spd.PickData != "" {
	    phs = strings.Split(spd.PickData, "|")
	    for _, v := range phs {
		    vv := &PickHashData{}
		    if err := vv.UnmarshalJSON([]byte(v)); err != nil {
			    return err
		    }

		    pickdata = append(pickdata, vv)
	    }
	}

	Spd.PickData = pickdata
	return nil
}

//-------------------------------------------------------------

// CompressSignData marshal *SignPickData to json string
func CompressSignData(raw string, pickdata []*PickHashData) (string, error) {
	if raw == "" || pickdata == nil {
		return "", fmt.Errorf("sign data error")
	}

	s := &SignPickData{Raw: raw, PickData: pickdata}
	data, err := s.MarshalJSON()
	if err != nil {
		return "", err
	}

	// compress ...

	return string(data), nil
}

// UnCompressSignData unmarshal json string to *SignPickData
func UnCompressSignData(data string) (*SignPickData, error) {
	if data == "" {
		return nil, fmt.Errorf("Sign Data error")
	}

	//uncompress ...

	s := &SignPickData{}
	if err := s.UnmarshalJSON([]byte(data)); err != nil {
		return nil, err
	}

	return s, nil
}

//---------------------------------------------------------------

// CompressSignBrocastData marshal *SignBrocastData to json string
func CompressSignBrocastData(raw string, pickhash []*PickHashKey) (string, error) {
	if raw == "" || pickhash == nil {
		return "", fmt.Errorf("sign brocast data error")
	}

	s := &SignBrocastData{Raw: raw, PickHash: pickhash}
	data, err := s.MarshalJSON()
	if err != nil {
		return "", err
	}

	// compress ...

	return string(data), nil
}

// UnCompressSignBrocastData unmarshal json string to *SignBrocastData
func UnCompressSignBrocastData(data string) (*SignBrocastData, error) {
	if data == "" {
		return nil, fmt.Errorf("Sign Brocast Data error")
	}

	// uncompress ...

	s := &SignBrocastData{}
	if err := s.UnmarshalJSON([]byte(data)); err != nil {
		return nil, err
	}

	return s, nil
}

// CompressSignSubGidBrocastData marshal *SignSubGidBrocastData to json string
func CompressSignSubGidBrocastData(raw string, pickhash []*PickHashKey,subgid string) (string, error) {
	if raw == "" || pickhash == nil || subgid == "" {
		return "", fmt.Errorf("sign brocast data error")
	}

	s := &SignSubGidBrocastData{Raw: raw, PickHash: pickhash,SubGid:subgid}
	data, err := s.MarshalJSON()
	if err != nil {
		return "", err
	}

	// compress ...

	return string(data), nil
}

// UnCompressSignSubGidBrocastData unmarshal json string to *SignBrocastData
func UnCompressSignSubGidBrocastData(data string) (*SignSubGidBrocastData, error) {
	if data == "" {
		return nil, fmt.Errorf("Sign Brocast Data error")
	}

	// uncompress ...

	s := &SignSubGidBrocastData{}
	if err := s.UnmarshalJSON([]byte(data)); err != nil {
		return nil, err
	}

	return s, nil
}

//-----------------------------------------------------------------------

// GetPreSignKey get the key of level db that saving pre-sign data
// strings.ToLower(256Hash(pubkey:inputcode:gid:index)) ---> PreSignData
func GetPreSignKey(pubkey string, inputcode string, gid string, index string) (string, error) {
	if pubkey == "" || gid == "" || index == "" {
		return "", fmt.Errorf("get pre-sign key fail,param error")
	}

	if inputcode != "" {
		key := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + inputcode + ":" + gid + ":" + index))).Hex())
		return key, nil
	}

	key := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid + ":" + index))).Hex())
	return key, nil
}

// BinarySearchVacancy Binary search the unused key among the set of hash(pubkey:inputcode:gid:i),  (i = start,start + 1,start + 2, .... , end)
// [start,end]
// mid = (end + 1 - start)/2
// left = [start,start - 1 + mid]
// right = [start + mid,end]
func BinarySearchVacancy(pubkey string, inputcode string, gid string, start int, end int) int {
	if predb == nil || pubkey == "" || gid == "" {
		return -1
	}

	if start < 0 || end < 0 || start > end {
		return -1
	}

	if start == end {
		key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(start))
		if err != nil {
			return -1
		}
		_, err = predb.Get([]byte(key))
		if IsNotFoundErr(err) {
			return start
		}

		return -1
	}

	mid := (end + 1 - start) / 2
	left := BinarySearchVacancy(pubkey, inputcode, gid, start, start+mid-1)
	if left >= 0 {
		return left
	}
	right := BinarySearchVacancy(pubkey, inputcode, gid, start+mid, end)
	return right
}

// NeedPreSign Binary search the unused key among the set of hash(pubkey:inputcode:gid:i),  (i = start,start + 1,start + 2, .... , end)
// if this value index is found,return (index,true),otherwise return (-1,false)
func NeedPreSign(pubkey string, inputcode string, gid string) (int, bool) {

	if predb == nil || pubkey == "" || gid == "" || PrePubDataCount < 1 {
		return -1, false
	}

	index := BinarySearchVacancy(pubkey, inputcode, gid, 0, PrePubDataCount-1)
	if index < 0 {
		return index, false
	}

	return index, true
}

// Pre-Sign Data Database:
// Key : Value
// hash(pubkey:inputcode:gid:0) : (*PreSignData).MarshalJSON
// hash(pubkey:inputcode:gid:1) : (*PreSignData).MarshalJSON
// .......
// hash(pubkey:inputcode:gid:PrePubDataCount-1) : (*PreSignData).MarshalJSON

// GetTotalCount Gets the number of currently generated pre-sign data under the specified pubkey/gid/inputcode
func GetTotalCount(pubkey string, inputcode string, gid string) int {
	if predb == nil || pubkey == "" || gid == "" || PrePubDataCount < 1 {
		return 0
	}

	index := BinarySearchVacancy(pubkey, inputcode, gid, 0, PrePubDataCount-1)
	if index < 0 {
		count := 0
		var wg sync.WaitGroup
		for i := 0; i < PrePubDataCount; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(index))
				if err != nil {
					return
				}

				exsit, err := predb.Has([]byte(key))
				if exsit && err == nil {
					count++
				}
			}(i)
		}
		wg.Wait()

		return count
	}

	return index
}

// PutPreSignData put pre-sign data to local db under the specified pubkey/gid/inputcode
func PutPreSignData(pubkey string, inputcode string, gid string, index int, val *PreSignData, force bool) error {
	if predb == nil || val == nil {
		return fmt.Errorf("put pre-sign data fail,param error")
	}

	var tmp string
	if index < 0 {
	    tmp = val.Key
	} else {
	    tmp = strconv.Itoa(index)
	}

	key, err := GetPreSignKey(pubkey, inputcode, gid, tmp)
	if err != nil {
		return err
	}

	_, err = predb.Get([]byte(key))
	if IsNotFoundErr(err) {
		value, err := val.MarshalJSON()
		if err != nil {
			common.Error("====================PutPreSignData,marshal pre-sign data error ======================", "pubkey", pubkey, "gid", gid, "index", index, "val", val, "err", err)
			return err
		}

		err = predb.Put([]byte(key), value)
		if err != nil {
			common.Error("====================PutPreSignData,put pre-sign data to db fail ======================", "pubkey", pubkey, "gid", gid, "index", index, "datakey", val.Key, "err", err)
		}

		common.Debug("====================PutPreSignData,put pre-sign data to db success ======================","pubkey",pubkey,"gid",gid,"index",index,"datakey",val.Key)
		return err
	}

	if force {
		value, err := val.MarshalJSON()
		if err != nil {
			common.Error("====================PutPreSignData,force update,marshal pre-sign data error ======================", "pubkey", pubkey, "gid", gid, "index", index, "val", val, "err", err)
			return nil //force update fail,but still return nil
		}

		err = predb.Put([]byte(key), value)
		if err != nil {
			common.Error("====================PutPreSignData,force update,put pre-sign data to db fail ======================", "pubkey", pubkey, "gid", gid, "index", index, "datakey", val.Key, "err", err)
			return nil //force update fail,but still return nil
		}

		common.Debug("====================PutPreSignData,force update,put pre-sign data to db success ======================","pubkey",pubkey,"gid",gid,"index",index,"datakey",val.Key)
		return nil
	}

	return fmt.Errorf(" The pre-sign data of the key has been put to db before")
}

// BinarySearchPreSignData binary search pre-sign data by datakey under the specified pubkey/gid/inputcode from local db
// [start,end]
// mid = (end + 1 - start)/2
// left = [start,start - 1 + mid]
// right = [start + mid,end]
func BinarySearchPreSignData(pubkey string, inputcode string, gid string, datakey string, start int, end int) (int, *PreSignData) {
	if predb == nil || pubkey == "" || gid == "" {
		return -1, nil
	}

	if start < 0 || end < 0 || start > end {
		return -1, nil
	}

	if start == end {
		key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(start))
		if err != nil {
		    common.Error("=======================BinarySearchPreSignData,get pre-sign key fail======================","err",err,"pubkey",pubkey,"gid",gid,"datakey",datakey,"start",start)
			return -1, nil
		}
		da, err := predb.Get([]byte(key))
		if da != nil && err == nil {
			psd := &PreSignData{}
			if err = psd.UnmarshalJSON(da); err == nil {
				if strings.EqualFold(psd.Key, datakey) {
					return start, psd
				}
			}
		}

		return -1, nil
	}

	mid := (end + 1 - start) / 2
	left, data := BinarySearchPreSignData(pubkey, inputcode, gid, datakey, start, start+mid-1)
	if left >= 0 {
		return left, data
	}
	right, data := BinarySearchPreSignData(pubkey, inputcode, gid, datakey, start+mid, end)
	return right, data
}

// GetPreSignData binary search pre-sign data by datakey under the specified pubkey/gid/inputcode from local db
func GetPreSignData(pubkey string, inputcode string, gid string, datakey string) *PreSignData {
	if predb == nil || pubkey == "" || gid == "" || datakey == "" || PrePubDataCount < 1 {
		return nil
	}

	_, data := BinarySearchPreSignData(pubkey, inputcode, gid, datakey, 0, PrePubDataCount-1)
	//find in the other area
	if data == nil {
	    key, err := GetPreSignKey(pubkey, inputcode, gid, datakey)
	    if err != nil {
		    return nil
	    }
	    da, err := predb.Get([]byte(key))
	    if da != nil && err == nil {
		    psd := &PreSignData{}
		    if err = psd.UnmarshalJSON(da); err == nil {
			    if strings.EqualFold(psd.Key, datakey) {
				    return psd
			    }
		    }
	    }

	    return nil
	}
	//

	return data
}

// DeletePreSignData delete pre-sign data from local db under the specified pubkey/gid/inputcode
func DeletePreSignData(pubkey string, inputcode string, gid string, datakey string) error {
	if predb == nil || pubkey == "" || gid == "" || datakey == "" || PrePubDataCount < 1 {
		common.Error("=======================DeletePreSignData,delete pre-sign data from db fail========================", "pubkey", pubkey, "gid", gid, "datakey", datakey)
		return fmt.Errorf("delete pre-sign data from db error")
	}

	index, data := BinarySearchPreSignData(pubkey, inputcode, gid, datakey, 0, PrePubDataCount-1)
	if data == nil || index < 0 {
	    //find in the other area
	    key, err := GetPreSignKey(pubkey, inputcode, gid, datakey)
	    if err != nil {
		    return err
	    }
	    da, err := predb.Get([]byte(key))
	    if da != nil && err == nil {
		    psd := &PreSignData{}
		    if err = psd.UnmarshalJSON(da); err == nil {
			    if strings.EqualFold(psd.Key, datakey) {
				    err = predb.Delete([]byte(key))
				    if err != nil {
					    common.Error("======================DeletePreSignData,delete pre-sign data from db fail.==========================", "pubkey", pubkey, "gid", gid, "index", index, "datakey", datakey, "err", err)
					return err
				    }

				    return nil
			    }
		    }
	    }
	    //

	    return fmt.Errorf("pre-sign data was not found")
	}

	key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(index))
	if err != nil {
		return err
	}

	err = predb.Delete([]byte(key))
	if err != nil {
		common.Error("======================DeletePreSignData,delete pre-sign data from db fail.==========================", "pubkey", pubkey, "gid", gid, "index", index, "datakey", datakey, "err", err)
	}

	return err
}

// BinarySearchPick Pick the pre-sign data from local db under the specified pubkey/gid/inputcode
// [start,end]
// mid = (end + 1 - start)/2
// left = [start,start - 1 + mid]
// right = [start + mid,end]
func BinarySearchPick(pubkey string, inputcode string, gid string, start int, end int) (int, *PreSignData) {
	if predb == nil || pubkey == "" || gid == "" {
		return -1, nil
	}

	if start < 0 || end < 0 || start > end {
		return -1, nil
	}

	if start == end {
		key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(start))
		if err != nil {
			return -1, nil
		}
		da, err := predb.Get([]byte(key))
		if da != nil && err == nil {
			psd := &PreSignData{}
			if err = psd.UnmarshalJSON(da); err == nil {
				return start, psd
			}
		}

		return -1, nil
	}

	mid := (end + 1 - start) / 2
	left, data := BinarySearchPick(pubkey, inputcode, gid, start, start+mid-1)
	if left >= 0 {
		return left, data
	}
	right, data := BinarySearchPick(pubkey, inputcode, gid, start+mid, end)
	return right, data
}

// PickPreSignData Pick the pre-sign data from local db under the specified pubkey/gid/inputcode
func PickPreSignData(pubkey string, inputcode string, gid string) *PreSignData {
	if predb == nil || pubkey == "" || gid == "" || PrePubDataCount < 1 {
		common.Error("=======================PickPreSignData,param error.========================", "pubkey", pubkey, "gid", gid)
		return nil
	}

	index, data := BinarySearchPick(pubkey, inputcode, gid, 0, PrePubDataCount-1)
	if index < 0 || data == nil {
		return nil
	}

	key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(index))
	if err != nil {
		return nil
	}

	err = predb.Delete([]byte(key))
	if err != nil {
		common.Error("=====================PickPreSignData,delete pre-sign data from db fail.==========================", "pubkey", pubkey, "gid", gid, "err", err)
		return nil
	}

	return data
}

//-----------------------------------------------------------------------

// TxDataPreSignData the data of the special tx of pre-generating sign data
type TxDataPreSignData struct {
	TxType string
	Account string
	Nonce string
	PubKey string
	SubGid []string
	KeyType string
}

// PreGenSignData generate the pre-sign data under the specified pubkey/gid
func PreGenSignData(raw string) (string, error) {
	_, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================PreGenSignData,check raw data error================", "raw", raw, "from", from, "err", err)
		return err.Error(), err
	}

	pre, ok := txdata.(*TxDataPreSignData)
	if !ok {
		common.Error("=====================PreGenSignData, get tx data error================", "raw", raw, "from", from)
		return "", fmt.Errorf("get tx data error")
	}

	ExcutePreSignData(pre)
	return "", nil
}

// ExcutePreSignData generate the pre-sign data under the specified pubkey/gid
func ExcutePreSignData(pre *TxDataPreSignData) {
	if pre == nil {
		return
	}

	common.Debug("=========================ExcutePreSignData=======================", "pubkey", pre.PubKey, "gid", pre.SubGid, "keytype", pre.KeyType)

	for _, gid := range pre.SubGid {
		go func(gg string) {
			pub := Keccak256Hash([]byte(strings.ToLower(pre.PubKey + ":" + gg))).Hex()
			PutPreSigal(pub, true)
			err := SavePrekeyToDb(pre.PubKey, "", gg,pre.KeyType)
			if err != nil {
				common.Error("=========================ExcutePreSignData,save (pubkey,gid) to db fail.=======================", "pubkey", pre.PubKey, "gid", gg, "err", err)
				return
			}

			var contfail int = 0

			common.Info("================================ExcutePreSignData,before pre-generation of sign data ==================================", "current total number of the data ", GetTotalCount(pre.PubKey, "", gg), "pubkey", pre.PubKey, "sub-groupid", gg,"keytype",pre.KeyType)
			for {
				b := GetPreSigal(pub)
				if b {
					index, need := NeedPreSign(pre.PubKey, "", gg)

					if need && index != -1 {
						tt := fmt.Sprintf("%v", time.Now().UnixNano()/1e6)
						nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt + strconv.Itoa(index)))).Hex()
						ps := &PreSign{Pub: pre.PubKey, Gid: gg, Nonce: nonce, Index: index,KeyType:pre.KeyType}

						m := make(map[string]string)
						psjson, err := ps.MarshalJSON()
						if err == nil {
							m["PreSign"] = string(psjson)
						}
						m["Type"] = "PreSign"
						val, err := json.Marshal(m)
						if err != nil {
							time.Sleep(time.Duration(10000000))
							continue
						}
						SendMsgToSmpcGroup(string(val), gg)
						//check msg
						msghash := Keccak256Hash([]byte(strings.ToLower(string(val)))).Hex()
						_,exist := MsgReceiv.ReadMap(msghash)
						if exist {
						    continue
						}

						MsgReceiv.WriteMap(msghash,NowMilliStr())

						rch := make(chan interface{}, 1)
						SetUpMsgList3(string(val), curEnode, rch)

						/*reply := false
						timeout := make(chan bool, 1)
						go func() {
							syncWaitTime := 600 * time.Second
							syncWaitTimeOut := time.NewTicker(syncWaitTime)

							for {
								select {
								case <-rch:
									reply = true
									timeout <- false
									return
								case <-syncWaitTimeOut.C:
									reply = false
									timeout <- true
									return
								}
							}
						}()*/
						reply := false
						timeout := make(chan bool, 1)
						go func() {
							syncWaitTime := 600 * time.Second
							syncWaitTimeOut := time.NewTicker(syncWaitTime)

							for {
								select {
								case v := <-rch:
									ret, ok := v.(RPCSmpcRes)
									if ok {
										if ret.Err != nil {
										    reply = false 
										    timeout <- false
										} else {
										    reply = true 
										    timeout <- false
										}
									} else {
									    reply = false
									    timeout <- false
									}

									return
								case <-syncWaitTimeOut.C:
									reply = false
									timeout <- true
									return
								}
							}
						}()
						<-timeout

						if !reply {
						    contfail++
						    if contfail == 20 {
							common.Error("=====================ExcutePreSignData, failed to pre-generate sign data.delete the prekey and exit the loop.========================", "pubkey", pre.PubKey, "sub-groupid", gg, "Index", index)
							DelPrekeyFromDb(pre.PubKey, "", gg,pre.KeyType)
							DeletePreSignData(pre.PubKey, "", gg, nonce)
							return
						    }

							common.Error("=====================ExcutePreSignData, failed to pre-generate sign data and continue.========================", "pubkey", pre.PubKey, "sub-groupid", gg, "Index", index,"contfail",contfail)
							time.Sleep(time.Duration(1000000))
							continue
						}

						contfail = 0
						common.Info("================================ExcutePreSignData,after pre-generation of sign data==================================", "current total number of the data ", GetTotalCount(pre.PubKey, "", gg), "pubkey", pre.PubKey, "sub-groupid", gg, "Index", index)
					}
				}

				time.Sleep(time.Duration(1000000))
			}
		}(gid)
	}
}

// AutoPreGenSignData Automatically generate pre-sign data based on database that saving public key group information. 
func AutoPreGenSignData() {
	if prekey == nil {
		return
	}

	iter := prekey.NewIterator()
	for iter.Next() {
		value := []byte(string(iter.Value()))
		if len(value) == 0 {
			continue
		}

		go func(val string) {
			common.Debug("======================AutoPreGenSignData=========================", "val", val)
			tmp := strings.Split(val, ":") // val = pubkey:gid:keytype
			if len(tmp) < 3 || tmp[0] == "" || tmp[1] == "" {
				return
			}

			subgid := make([]string, 0)
			subgid = append(subgid, tmp[1])
			pre := &TxDataPreSignData{TxType: "PRESIGNDATA", PubKey: tmp[0], SubGid: subgid,KeyType:tmp[2]}
			ExcutePreSignData(pre)
		}(string(value))
	}

	iter.Release()
}

// SavePrekeyToDb save pubkey gid information to the specified batabase
func SavePrekeyToDb(pubkey string, inputcode string, gid string,keytype string) error {
	if prekey == nil {
		return fmt.Errorf("db open fail")
	}

	var pub string
	var val string
	if inputcode != "" {
		pub = strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + inputcode + ":" + gid))).Hex())
		val = pubkey + ":" + inputcode + ":" + gid + ":" + keytype
	} else {
		pub = strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid))).Hex())
		val = pubkey + ":" + gid + ":" + keytype
	}

	_, err := prekey.Get([]byte(pub))
	if IsNotFoundErr(err) {
		common.Debug("==================SavePrekeyToDb, Not Found pub.=====================", "pub", pub, "pubkey", pubkey, "gid", gid)
		err = prekey.Put([]byte(pub), []byte(val))
		if err != nil {
			common.Error("==================SavePrekeyToDb, put prekey to db fail.=====================", "pub", pub, "pubkey", pubkey, "gid", gid, "err", err)
			return err
		}
	}

	return nil
}

// DelPrekeyFromDb delete pubkey gid information to the specified batabase
func DelPrekeyFromDb(pubkey string, inputcode string, gid string,keytype string) error {
	if prekey == nil {
		return fmt.Errorf("db open fail")
	}

	var pub string
	if inputcode != "" {
		pub = strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + inputcode + ":" + gid))).Hex())
	} else {
		pub = strings.ToLower(Keccak256Hash([]byte(strings.ToLower(pubkey + ":" + gid))).Hex())
	}

	_, err := prekey.Get([]byte(pub))
	if IsNotFoundErr(err) {
	    return nil
	}

	err = prekey.Delete([]byte(pub))
	if err != nil {
		common.Error("==================DelPrekeyFromDb, delete prekey from db fail.=====================", "pub", pub, "pubkey", pubkey, "gid", gid, "err", err)
		return err
	}

	return nil
}

// IsNotFoundErr weather it is "Not Found in db" error
func IsNotFoundErr(err error) bool {
	return errors.Is(err, dberrors.ErrNotFound)
}

//--------------------------------------------------------------

// GetPreSigal Return whether to continue generating pre-sign data  
// pub = hash256(pubkey : gid)
// true  yes
// false no
func GetPreSigal(pub string) bool {
	data, exsit := PreSigal.ReadMap(strings.ToLower(pub))
	if exsit {
		sigal := data.(string)
		if sigal == "false" {
			return false
		}
	}

	return true
}

// PutPreSigal set the value "true" or "false" to map to decide whether to continue generating pre-sign data
func PutPreSigal(pub string, val bool) {
	if val {
		PreSigal.WriteMap(strings.ToLower(pub), "true")
		return
	}

	PreSigal.WriteMap(strings.ToLower(pub), "false")
}

//-------------------------------------------------------------------------

// NeedToStartPreBip32 need to generate pre-sign data for bip32 ??
func NeedToStartPreBip32(pub string) bool {
	_, exsit := PreSigal.ReadMap(strings.ToLower(pub))
	return !exsit
}

// NeedPreSignForBip32 find the unused key among the set of hash(pubkey:inputcode:gid:i),  (i = start,start + 1,start + 2, .... , end)
// if this value index is found,return (index,true),otherwise return (-1,false)
func NeedPreSignForBip32(pubkey string, inputcode string, gid string) (int, bool) {

	if predb == nil || pubkey == "" || inputcode == "" || gid == "" {
		return -1, false
	}

	idx := make(chan int, 1)

	for i := 0; i < PreBip32DataCount; i++ {
		go func(index int) {

			key, err := GetPreSignKey(pubkey, inputcode, gid, strconv.Itoa(index))
			if err != nil {
				return
			}

			_, err = predb.Get([]byte(key))
			if IsNotFoundErr(err) {
				if len(idx) == 0 {
					idx <- index
				}
			}
		}(i)
	}

	WaitTime := 60 * time.Second
	getIndexTimeOut := time.NewTicker(WaitTime)

	select {
	case ret := <-idx:
		return ret, true
	case <-getIndexTimeOut.C:
		return -1, false
	}

	return -1, false
}

// GetPrePubGids get gids by pub
// pub = hash256(pubkey : gid)
func GetPrePubGids(pub string) []string {
	data, exsit := PrePubGids.ReadMap(strings.ToLower(pub))
	if exsit {
		gids := data.([]string)
		return gids
	}

	return nil
}

// PutPrePubGids put gids to map by pub
// pub = hash256(pubkey : gid)
func PutPrePubGids(pub string, gids []string) {
	old := GetPrePubGids(pub)
	if old == nil {
		old = make([]string, 0)
		old = append(old, gids...)
		PrePubGids.WriteMap(strings.ToLower(pub), old)
		return
	}

	old = append(old, gids...)
	PrePubGids.WriteMap(strings.ToLower(pub), gids)
}

//-----------------------------------------------------------

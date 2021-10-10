/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  haijun.cai@anyswap.exchange
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
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/ethdb"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/fdlimit"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
)

var (
	cache   = (75 * 1024) / 1000
	handles = makeDatabaseHandles()

	db      *ethdb.LDBDatabase
	dbsk    *ethdb.LDBDatabase
	dbbip32 *ethdb.LDBDatabase
	predb   *ethdb.LDBDatabase
	prekey  *ethdb.LDBDatabase

	reqaddrinfodb *ethdb.LDBDatabase
	signinfodb    *ethdb.LDBDatabase
	reshareinfodb *ethdb.LDBDatabase
	accountsdb    *ethdb.LDBDatabase
)

func makeDatabaseHandles() int {
	limit, err := fdlimit.Current()
	if err != nil {
		//Fatalf("Failed to retrieve file descriptor allowance: %v", err)
		common.Info("Failed to retrieve file descriptor allowance: " + err.Error())
		return 0
	}
	if limit < 2048 {
		if err := fdlimit.Raise(2048); err != nil {
			//Fatalf("Failed to raise file descriptor allowance: %v", err)
			common.Info("Failed to raise file descriptor allowance: " + err.Error())
		}
	}
	if limit > 2048 { // cap database file descriptors even if more is available
		limit = 2048
	}
	return limit / 2 // Leave half for networking and other stuff
}

//------------------------------------------------------------------------------

func GetPubKeyData(key []byte) (bool, interface{}) {
	if key == nil || db == nil {
		common.Error("========================GetPubKeyData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := db.Get(key)
	if da == nil || err != nil {
		common.Error("========================GetPubKeyData, get pubkey data from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Error("========================GetPubKeyData, uncompress err=======================", "err", err, "key", string(key))
		return true, da
	}

	pubs3, err := Decode2(ss, "PubKeyData")
	if err == nil {
		pd, ok := pubs3.(*PubKeyData)
		if ok && pd.Key != "" && pd.Save != "" {
			return true, pd
		}
	}

	pubs4, err := Decode2(ss, "AcceptSignData")
	if err == nil {
		pd, ok := pubs4.(*AcceptSignData)
		if ok && pd.Keytype != "" {
			return true, pd
		}
	}

	pubs5, err := Decode2(ss, "AcceptReShareData")
	if err == nil {
		pd, ok := pubs5.(*AcceptReShareData)
		if ok && pd.TSGroupId != "" {
			return true, pd
		}
	}

	pubs, err := Decode2(ss, "AcceptReqAddrData")
	if err == nil {
		pd, ok := pubs.(*AcceptReqAddrData)
		if ok {
			return true, pd
		}
	}

	return false, nil
}

//------------------------------------------------------------------------------------------

func PutPubKeyData(key []byte, value []byte) error {
	if db == nil || key == nil || value == nil {
		return fmt.Errorf("put pubkey data to db fail")
	}

	err := db.Put(key, value)
	if err == nil {
		common.Debug("===============PutPubKeyData, put pubkey data into db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============PutPubKeyData, put pubkey data into db fail.=================", "key", string(key), "err", err)
	return err
}

//----------------------------------------------------------------------------------------------

func DeletePubKeyData(key []byte) error {
	if key == nil || db == nil {
		return fmt.Errorf("delete pubkey data from db fail.")
	}

	err := db.Delete(key)
	if err == nil {
		common.Debug("===============DeletePubKeyData, del pubkey data from db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============DeletePubKeyData, delete pubkey data from db fail.=================", "key", string(key), "err", err)
	return err
}

//--------------------------------------------------------------------------------------------------------------

func getSkU1FromLocalDb(key []byte) []byte {
	if key == nil || dbsk == nil {
		return nil
	}

	da, err := dbsk.Get(key)
	if err != nil || da == nil {
		common.Error("========================getSkU1FromLocalDb,get sku1 from local db error.=========================", "err", err)
		return nil
	}

	sk, err := DecryptMsg(string(da))
	if err != nil {
		common.Error("========================getSkU1FromLocalDb,decrypt sku1 data error.=========================", "err", err)
		return da
	}

	return []byte(sk)
}

//----------------------------------------------------------------------------------------------------------------

func getBip32cFromLocalDb(key []byte) []byte {
	if key == nil || dbbip32 == nil {
		return nil
	}

	da, err := dbbip32.Get(key)
	if err != nil || da == nil {
		common.Error("========================getBip32cFromLocalDb,get bip32c from local db error.=========================", "err", err)
		return nil
	}

	c, err := DecryptMsg(string(da))
	if err != nil {
		common.Error("========================getBip32cFromLocalDb,decrypt bip32c data error.=========================", "err", err)
		return da
	}

	return []byte(c)
}

//--------------------------------------------------------------------------------------------------------------------

func putSkU1ToLocalDb(key []byte, value []byte) error {
	if dbsk == nil || key == nil || value == nil {
		return fmt.Errorf("put sku1 data to db fail")
	}

	cm, err := EncryptMsg(string(value), cur_enode)
	if err != nil {
		common.Error("===============putSkU1ToLocalDb, encrypt sku1 data fail.=================", "err", err)
		return err
	}

	err = dbsk.Put(key, []byte(cm))
	if err == nil {
		common.Debug("===============putSkU1ToLocalDb, put sku1 data into db success.=================")
		return nil
	}

	common.Error("===============putSkU1ToLocalDb, put sku1 data to db fail.=================", "err", err)
	return err
}

//-------------------------------------------------------------------------------------------------------------

func putBip32cToLocalDb(key []byte, value []byte) error {
	if dbbip32 == nil || key == nil || value == nil {
		return fmt.Errorf("put bip32c to db fail")
	}

	cm, err := EncryptMsg(string(value), cur_enode)
	if err != nil {
		common.Error("===============putBip32cToLocalDb, encrypt bip32c fail.=================", "err", err)
		return err
	}

	err = dbbip32.Put(key, []byte(cm))
	if err == nil {
		common.Debug("===============putBip32cToLocalDb, put bip32c into db success.=================")
		return nil
	}

	common.Error("===============putBip32cToLocalDb, put bip32c to db fail.=================", "err", err)
	return err
}

//------------------------------------------------------------------------------------------------------

func deleteSkU1FromLocalDb(key []byte) error {
	if key == nil || dbsk == nil {
		return fmt.Errorf("delete sku1 from db fail,param error.")
	}

	err := dbsk.Delete(key)
	if err == nil {
		common.Debug("===============deleteSkU1FromLocalDb, delete sku1 data from db success.=================")
		return nil
	}

	common.Error("===============deleteSkU1FromLocalDb, delete sku1 data from db fail.=================", "err", err)
	return err
}

//------------------------------------------------------------------------------------------------

func deleteBip32cFromLocalDb(key []byte) error {
	if key == nil || dbbip32 == nil {
		return fmt.Errorf("delete bip32c from db fail,param error.")
	}

	err := dbbip32.Delete(key)
	if err == nil {
		common.Debug("===============deleteBip32cFromLocalDb, delete bip32c from db success.=================")
		return nil
	}

	common.Error("===============deleteBip32cFromLocalDb, delete bip32c from db fail.=================", "err", err)
	return err
}

//-------------------------------------------------------------

func GetReqAddrInfoData(key []byte) (bool, interface{}) {
	if key == nil || reqaddrinfodb == nil {
		common.Error("========================GetReqAddrInfoData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := reqaddrinfodb.Get(key)
	if da == nil || err != nil {
		common.Error("========================GetReqAddrInfoData, get reqaddr info from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Error("========================GetReqAddrInfoData, uncompress err=======================", "err", err, "key", string(key))
		return true, da
	}

	pubs, err := Decode2(ss, "AcceptReqAddrData")
	if err == nil {
		pd, ok := pubs.(*AcceptReqAddrData)
		if ok {
			return true, pd
		}
	}

	return false, nil
}

//----------------------------------------------------------------

func PutReqAddrInfoData(key []byte, value []byte) error {
	if reqaddrinfodb == nil || key == nil || value == nil {
		return fmt.Errorf("put reqaddr info to db fail")
	}

	err := reqaddrinfodb.Put(key, value)
	if err == nil {
		common.Debug("===============PutReqAddrInfoData, put reqaddr info into db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============PutReqAddrInfoData, put reqaddr info into db fail.=================", "key", string(key), "err", err)
	return err
}

//----------------------------------------------------------------

func DeleteReqAddrInfoData(key []byte) error {
	if key == nil || reqaddrinfodb == nil {
		return fmt.Errorf("delete reqaddr info from db fail.")
	}

	err := reqaddrinfodb.Delete(key)
	if err == nil {
		common.Debug("===============DeleteReqAddrInfoData, del reqaddr info from db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============DeleteReqAddrInfoData, delete reqaddr info from db fail.=================", "key", string(key), "err", err)
	return err
}

//--------------------------------------------------------------

func GetSignInfoData(key []byte) (bool, interface{}) {
	if key == nil || signinfodb == nil {
		common.Error("========================GetSignInfoData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := signinfodb.Get(key)
	if da == nil || err != nil {
		common.Error("========================GetSignInfoData, get sign info from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Error("========================GetSignInfoData, uncompress err=======================", "err", err, "key", string(key))
		return true, da
	}

	pubs, err := Decode2(ss, "AcceptSignData")
	if err == nil {
		pd, ok := pubs.(*AcceptSignData)
		if ok && pd.Keytype != "" {
			return true, pd
		}
	}

	return false, nil
}

//-------------------------------------------------------

func PutSignInfoData(key []byte, value []byte) error {
	if signinfodb == nil || key == nil || value == nil {
		return fmt.Errorf("put sign info to db fail")
	}

	err := signinfodb.Put(key, value)
	if err == nil {
		common.Debug("===============PutSignInfoData, put sign info into db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============PutSignInfoData, put sign info into db fail.=================", "key", string(key), "err", err)
	return err
}

//-----------------------------------------------------------

func DeleteSignInfoData(key []byte) error {
	if key == nil || signinfodb == nil {
		return fmt.Errorf("delete sign info from db fail.")
	}

	err := signinfodb.Delete(key)
	if err == nil {
		common.Debug("===============DeleteSignInfoData, del sign info from db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============DeleteSignInfoData, delete sign info from db fail.=================", "key", string(key), "err", err)
	return err
}

//------------------------------------------------------

func GetReShareInfoData(key []byte) (bool, interface{}) {
	if key == nil || reshareinfodb == nil {
		common.Error("========================GetReShareInfoData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := reshareinfodb.Get(key)
	if da == nil || err != nil {
		common.Error("========================GetReShareInfoData, get reshare info from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Error("========================GetReShareInfoData, uncompress err=======================", "err", err, "key", string(key))
		return true, da
	}

	pubs, err := Decode2(ss, "AcceptReShareData")
	if err == nil {
		pd, ok := pubs.(*AcceptReShareData)
		if ok && pd.TSGroupId != "" {
			return true, pd
		}
	}

	return false, nil
}

//-------------------------------------------------------

func PutReShareInfoData(key []byte, value []byte) error {
	if reshareinfodb == nil || key == nil || value == nil {
		return fmt.Errorf("put reshare info to db fail")
	}

	err := reshareinfodb.Put(key, value)
	if err == nil {
		common.Debug("===============PutReShareInfoData, put reshare info into db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============PutReShareInfoData, put reshare info into db fail.=================", "key", string(key), "err", err)
	return err
}

//-------------------------------------------------------

func DeleteReShareInfoData(key []byte) error {
	if key == nil || reshareinfodb == nil {
		return fmt.Errorf("delete reshare info from db fail.")
	}

	err := reshareinfodb.Delete(key)
	if err == nil {
		common.Debug("===============DeleteReShareInfoData, del reshare info from db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============DeleteReShareInfoData, delete reshare info from db fail.=================", "key", string(key), "err", err)
	return err
}

//-------------------------------------------------------

func GetGroupDir() string { //TODO
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/dcrmdb" + discover.GetLocalID().String() + "group"
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/smpcdb" + discover.GetLocalID().String() + "group"
	return dir
}

//--------------------------------------------------------

func GetDbDir() string {
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/dcrmdb" + cur_enode
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/smpcdb" + cur_enode
	return dir
}

func GetSmpcDb() *ethdb.LDBDatabase {
	dir := GetDbDir()
	db, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================GetSmpcDb,open db fail======================", "err", err, "dir", dir)
		return nil
	}

	return db
}

//-----------------------------------------------------------

func GetSkU1Dir() string {
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/sk" + cur_enode
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/sk" + cur_enode
	return dir
}

func GetSmpcSkDb() *ethdb.LDBDatabase {
	dir := GetSkU1Dir()
	dbsk, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open dbsk fail======================", "err", err, "dir", dir)
		return nil
	}

	return dbsk
}

//----------------------------------------------------------

func GetBip32CDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/bip32" + cur_enode
	return dir
}

func GetSmpcBip32Db() *ethdb.LDBDatabase {
	dir := GetBip32CDir()
	dbbip32, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open dbbip32 fail======================", "err", err, "dir", dir)
		return nil
	}

	return dbbip32
}

//----------------------------------------------------------

func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcpredb" + cur_enode
	return dir
}

func GetSmpcPreDb() *ethdb.LDBDatabase {
	dir := GetPreDbDir()
	predb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open predb fail======================", "err", err, "dir", dir)
		return nil
	}

	return predb
}

//-------------------------------------------------------------

func GetPreKeyDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcprekey" + cur_enode
	return dir
}

func GetSmpcPreKeyDb() *ethdb.LDBDatabase {
	dir := GetPreKeyDir()
	prekey, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open prekey fail======================", "err", err, "dir", dir)
		return nil
	}

	return prekey
}

//---------------------------------------------------------------

func GetReqAddrInfoDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcreqaddrinfo" + cur_enode
	return dir
}

func GetSmpcReqAddrInfoDb() *ethdb.LDBDatabase {
	dir := GetReqAddrInfoDir()
	reqaddrinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open reqaddrinfodb fail======================", "err", err, "dir", dir)
		return nil
	}

	return reqaddrinfodb
}

//--------------------------------------------------------------

func GetSignInfoDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcsigninfo" + cur_enode
	return dir
}

func GetSmpcSignInfoDb() *ethdb.LDBDatabase {
	dir := GetSignInfoDir()
	signinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open signinfodb fail======================", "err", err, "dir", dir)
		return nil
	}

	return signinfodb
}

//--------------------------------------------------------------

func GetReShareInfoDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcreshareinfo" + cur_enode
	return dir
}

func GetSmpcReShareInfoDb() *ethdb.LDBDatabase {
	dir := GetReShareInfoDir()
	reshareinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open reshareinfodb fail======================", "err", err, "dir", dir)
		return nil
	}

	return reshareinfodb
}

//--------------------------------------------------------------

func StartSmpcLocalDb() error {
	db = GetSmpcDb()
	if db == nil {
		common.Error("======================StartSmpcLocalDb,open db fail=====================")
		return errors.New("open db fail")
	}

	dbsk = GetSmpcSkDb()
	if dbsk == nil {
		common.Error("======================StartSmpcLocalDb,open dbsk fail=====================")
		return errors.New("open dbsk fail")
	}

	dbbip32 = GetSmpcBip32Db()
	if dbbip32 == nil {
		common.Error("======================StartSmpcLocalDb,open dbbip32 fail=====================")
		return errors.New("open dbbip32 fail")
	}

	predb = GetSmpcPreDb()
	if predb == nil {
		common.Error("======================StartSmpcLocalDb,open predb fail=====================")
		return errors.New("open predb fail")
	}

	prekey = GetSmpcPreKeyDb()
	if prekey == nil {
		common.Error("======================StartSmpcLocalDb,open prekey fail=====================")
		return errors.New("open prekey fail")
	}

	reqaddrinfodb = GetSmpcReqAddrInfoDb()
	if reqaddrinfodb == nil {
		common.Error("======================StartSmpcLocalDb,open reqaddrinfodb fail=====================")
		return errors.New("open reqaddrinfodb fail")
	}

	signinfodb = GetSmpcSignInfoDb()
	if signinfodb == nil {
		common.Error("======================StartSmpcLocalDb,open signinfodb fail=====================")
		return errors.New("open signinfodb fail")
	}

	reshareinfodb = GetSmpcReShareInfoDb()
	if reshareinfodb == nil {
		common.Error("======================StartSmpcLocalDb,open reshareinfodb fail=====================")
		return errors.New("open reshareinfodb fail")
	}

	accountsdb = GetSmpcAccountsDirDb()
	if accountsdb == nil {
		common.Error("======================StartSmpcLocalDb,open accountsdb fail=====================")
		return errors.New("open accountsdb fail")
	}

	return nil
}

//--------------------------------------------------------

func CleanUpAllReqAddrInfo() {
	if reqaddrinfodb == nil {
		return
	}

	iter := reqaddrinfodb.NewIterator()
	for iter.Next() {
		key := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		if len(key) == 0 {
			continue
		}

		exsit, da := GetReqAddrInfoData(key)
		if !exsit || da == nil {
			continue
		}

		vv, ok := da.(*AcceptReqAddrData)
		if vv == nil || !ok {
			continue
		}

		vv.Status = "Timeout"

		e, err := Encode2(vv)
		if err != nil {
			continue
		}

		es, err := Compress([]byte(e))
		if err != nil {
			continue
		}

		DeleteReqAddrInfoData(key)
		PutPubKeyData(key, []byte(es))
	}
	iter.Release()
}

//----------------------------------------------------------------------------------

func CleanUpAllSignInfo() {
	if signinfodb == nil {
		return
	}

	iter := signinfodb.NewIterator()
	for iter.Next() {
		key := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		if len(key) == 0 {
			continue
		}

		exsit, da := GetSignInfoData(key)
		if !exsit || da == nil {
			continue
		}

		vv, ok := da.(*AcceptSignData)
		if vv == nil || !ok {
			continue
		}

		vv.Status = "Timeout"

		e, err := Encode2(vv)
		if err != nil {
			continue
		}

		es, err := Compress([]byte(e))
		if err != nil {
			continue
		}

		DeleteSignInfoData(key)
		PutPubKeyData(key, []byte(es))
	}
	iter.Release()
}

//------------------------------------------------------------------------------------------------

func CleanUpAllReshareInfo() {
	if reshareinfodb == nil {
		return
	}

	iter := reshareinfodb.NewIterator()
	for iter.Next() {
		key := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		if len(key) == 0 {
			continue
		}

		exsit, da := GetReShareInfoData(key)
		if !exsit || da == nil {
			continue
		}

		vv, ok := da.(*AcceptReShareData)
		if vv == nil || !ok {
			continue
		}

		vv.Status = "Timeout"

		e, err := Encode2(vv)
		if err != nil {
			continue
		}

		es, err := Compress([]byte(e))
		if err != nil {
			continue
		}

		DeleteReShareInfoData(key)
		PutPubKeyData(key, []byte(es))
	}
	iter.Release()
}

//-----------------------------------------------------------------------------------------------------

func GetAccountsDir() string {
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/dcrmaccounts" + cur_enode
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/smpcaccounts" + cur_enode
	return dir
}

func AccountLoaded() bool {
	dir := GetAccountsDir()
	return common.FileExist(dir)
}

func GetSmpcAccountsDirDb() *ethdb.LDBDatabase {
	dir := GetAccountsDir()
	accountsdb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================GetSmpcAccountsDirDb,open accountsdb fail======================", "err", err, "dir", dir)
		return nil
	}

	return accountsdb
}

func CopyAllAccountsFromDb() {
	if db == nil {
		return
	}

	iter := db.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())

		ss, err := UnCompress(value)
		if err != nil {
			continue
		}

		pubs, err := Decode2(ss, "PubKeyData")
		if err != nil {
			continue
		}

		pd, ok := pubs.(*PubKeyData)
		if !ok {
			continue
		}

		if pd.Pub == "" {
			continue
		}

		pubkey := hex.EncodeToString([]byte(pd.Pub))

		//key: ys (marshal(pkx,pky))
		//key: []byte(hash256(tolower(dcrmaddr)))
		//value: []byte(pubkey)
		PutAccountDataToDb([]byte(key), []byte(pubkey))
	}

	iter.Release()
}

func GetAccountFromDb(key []byte) (bool, interface{}) {
	if key == nil || accountsdb == nil {
		common.Error("========================GetAccountFromDb, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := accountsdb.Get(key)
	if da == nil || err != nil {
		common.Error("========================GetAccountFromDb, get account from local db fail =======================", "key", string(key))
		return false, nil
	}

	return true, string(da)
}

//----------------------------------------------------------------

func PutAccountDataToDb(key []byte, value []byte) error {
	if accountsdb == nil || key == nil || value == nil {
		return fmt.Errorf("put account data to db fail")
	}

	err := accountsdb.Put(key, value)
	if err == nil {
		common.Debug("===============PutAccountDataToDb, put account data into db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============PutAccountDataToDb, put account data into db fail.=================", "key", string(key), "err", err)
	return err
}

//----------------------------------------------------------------

func DeleteAccountDataFromDb(key []byte) error {
	if key == nil || accountsdb == nil {
		return fmt.Errorf("delete account data from db fail.")
	}

	err := accountsdb.Delete(key)
	if err == nil {
		common.Debug("===============DeleteAccountDataFromDb, del account data from db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============DeleteAccountDataFromDb, delete account data from db fail.=================", "key", string(key), "err", err)
	return err
}

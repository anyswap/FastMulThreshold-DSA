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
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/ethdb"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/fdlimit"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	tsslib "github.com/anyswap/FastMulThreshold-DSA/tss-lib/common"
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
	giddb    *ethdb.LDBDatabase
)

// makeDatabaseHandles get database file descriptor allowance
func makeDatabaseHandles() int {
	limit, err := fdlimit.Current()
	if err != nil {
		common.Info("Failed to retrieve file descriptor allowance: " + err.Error())
		return 0
	}
	if limit < 2048 {
		if err := fdlimit.Raise(2048); err != nil {
			common.Info("Failed to raise file descriptor allowance: " + err.Error())
			return 0
		}
	}
	if limit > 2048 { // cap database file descriptors even if more is available
		limit = 2048
	}
	return limit / 2 // Leave half for networking and other stuff
}

//------------------------------------------------------------------------------

// GetPubKeyData get data by key from general database 
func GetPubKeyData(key []byte) (bool, interface{}) {
	if key == nil || db == nil {
		common.Error("========================GetPubKeyData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := db.Get(key)
	if da == nil || err != nil {
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Debug("========================GetPubKeyData, uncompress err=======================", "err", err, "key", string(key))
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
		if ok && pd.TSGroupID != "" {
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

// PutPubKeyData put value to general database
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

// DeletePubKeyData delete value from general database by key
func DeletePubKeyData(key []byte) error {
	if key == nil || db == nil {
		return fmt.Errorf("delete pubkey data from db fail")
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

// getSkU1FromLocalDb get Sk from local db
func getSkU1FromLocalDb(key []byte) []byte {
	if key == nil || dbsk == nil {
		return nil
	}

	da, err := dbsk.Get(key)
	if err != nil || da == nil {
		common.Error("========================getSkU1FromLocalDb,get sku1 from local db error.=========================", "err", err)
		return nil
	}

	sk, err := tsslib.DecryptMsg(string(da),KeyFile)
	if err != nil {
		common.Error("========================getSkU1FromLocalDb,decrypt sku1 data error.=========================", "err", err)
		return da
	}

	return []byte(sk)
}

//----------------------------------------------------------------------------------------------------------------

// getBip32cFromLocalDb get bip32 c value from local db
func getBip32cFromLocalDb(key []byte) []byte {
	if key == nil || dbbip32 == nil {
		return nil
	}

	da, err := dbbip32.Get(key)
	if err != nil || da == nil {
		common.Error("========================getBip32cFromLocalDb,get bip32c from local db error.=========================", "err", err)
		return nil
	}

	c, err := tsslib.DecryptMsg(string(da),KeyFile)
	if err != nil {
		common.Error("========================getBip32cFromLocalDb,decrypt bip32c data error.=========================", "err", err)
		return da
	}

	return []byte(c)
}

//--------------------------------------------------------------------------------------------------------------------

// putSkU1ToLocalDb put Sk to local db
func putSkU1ToLocalDb(key []byte, value []byte) error {
	if dbsk == nil || key == nil || value == nil {
		return fmt.Errorf("put sku1 data to db fail")
	}

	cm, err := tsslib.EncryptMsg(string(value), curEnode)
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

// putBip32cToLocalDb put bip32 c value to local db
func putBip32cToLocalDb(key []byte, value []byte) error {
	if dbbip32 == nil || key == nil || value == nil {
		return fmt.Errorf("put bip32c to db fail")
	}

	cm, err := tsslib.EncryptMsg(string(value), curEnode)
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

// deleteSkU1FromLocalDb delete Sk from local db
func deleteSkU1FromLocalDb(key []byte) error {
	if key == nil || dbsk == nil {
		return fmt.Errorf("delete sku1 from db fail,param error")
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

// deleteBip32cFromLocalDb delete bip32 c value from local db
func deleteBip32cFromLocalDb(key []byte) error {
	if key == nil || dbbip32 == nil {
		return fmt.Errorf("delete bip32c from db fail,param error")
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

// GetReqAddrInfoData get value by key from database for saving data related to generate pubkey command 
func GetReqAddrInfoData(key []byte) (bool, interface{}) {
	if key == nil || reqaddrinfodb == nil {
		common.Error("========================GetReqAddrInfoData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := reqaddrinfodb.Get(key)
	if da == nil || err != nil {
		common.Debug("========================GetReqAddrInfoData, get reqaddr info from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Debug("========================GetReqAddrInfoData, uncompress err=======================", "err", err, "key", string(key))
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

// PutReqAddrInfoData put value to database for saving data related to generate pubkey command 
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

// DeleteReqAddrInfoData delete value from database for saving data related to generate pubkey command 
func DeleteReqAddrInfoData(key []byte) error {
	if key == nil || reqaddrinfodb == nil {
		return fmt.Errorf("delete reqaddr info from db fail")
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

// GetSignInfoData get value by key from database for saving data related to sign command 
func GetSignInfoData(key []byte) (bool, interface{}) {
	if key == nil || signinfodb == nil {
		common.Error("========================GetSignInfoData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := signinfodb.Get(key)
	if da == nil || err != nil {
		common.Debug("========================GetSignInfoData, get sign info from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Debug("========================GetSignInfoData, uncompress err=======================", "err", err, "key", string(key))
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

// PutSignInfoData put value to database for saving data related to sign command 
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

// DeleteSignInfoData delete value from database for saving data related to sign command 
func DeleteSignInfoData(key []byte) error {
	if key == nil || signinfodb == nil {
		return fmt.Errorf("delete sign info from db fail")
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

// GetReShareInfoData get value by key from database for saving data related to reshare command 
func GetReShareInfoData(key []byte) (bool, interface{}) {
	if key == nil || reshareinfodb == nil {
		common.Error("========================GetReShareInfoData, param err=======================", "key", string(key))
		return false, nil
	}

	da, err := reshareinfodb.Get(key)
	if da == nil || err != nil {
		common.Debug("========================GetReShareInfoData, get reshare info from local db fail =======================", "key", string(key))
		return false, nil
	}

	ss, err := UnCompress(string(da))
	if err != nil {
		common.Debug("========================GetReShareInfoData, uncompress err=======================", "err", err, "key", string(key))
		return true, da
	}

	pubs, err := Decode2(ss, "AcceptReShareData")
	if err == nil {
		pd, ok := pubs.(*AcceptReShareData)
		if ok && pd.TSGroupID != "" {
			return true, pd
		}
	}

	return false, nil
}

//-------------------------------------------------------

// PutReShareInfoData put value to database for saving data related to reshare command 
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

// DeleteReShareInfoData delete value from database for saving data related to reshare command 
func DeleteReShareInfoData(key []byte) error {
	if key == nil || reshareinfodb == nil {
		return fmt.Errorf("delete reshare info from db fail")
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

// GetGroupDir get P2P group info database dir 
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

// GetDbDir get general database dir  
func GetDbDir() string {
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/dcrmdb" + curEnode
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/smpcdb" + curEnode
	return dir
}

// GetSmpcDb open general database
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

// GetSkU1Dir get private key database dir  
func GetSkU1Dir() string {
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/sk" + curEnode
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/sk" + curEnode
	return dir
}

// GetSmpcSkDb open private key database dir
func GetSmpcSkDb() *ethdb.LDBDatabase {
	dir := GetSkU1Dir()
	dbsk, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open dbsk fail======================", "err", err, "dir", dir)
		return nil
	}

	return dbsk
}

//--------------------------------------------------------------------

// GetBip32CDir get bip32 c value database dir 
func GetBip32CDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/bip32" + curEnode
	return dir
}

// GetSmpcBip32Db open bip32 c value database
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

// GetPreDbDir get pre-sign data database dir
func GetPreDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcpredb" + curEnode
	return dir
}

// GetSmpcPreDb open pre-sign data database 
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

// GetPreKeyDir get public key group information database dir
func GetPreKeyDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcprekey" + curEnode
	return dir
}

// GetSmpcPreKeyDb open public key group information database
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

// GetReqAddrInfoDir get dir of database for saving data related to generate pubkey command
func GetReqAddrInfoDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcreqaddrinfo" + curEnode
	return dir
}

// GetCmdReqAddrInfoDb open database for saving data related to generate pubkey command
func GetCmdReqAddrInfoDb() *ethdb.LDBDatabase {
	dir := GetReqAddrInfoDir()
	reqaddrinfodb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================smpc.Start,open reqaddrinfodb fail======================", "err", err, "dir", dir)
		return nil
	}

	return reqaddrinfodb
}

//--------------------------------------------------------------

// GetSignInfoDir get dir of database for saving data related to sign command
func GetSignInfoDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcsigninfo" + curEnode
	return dir
}

// GetSmpcSignInfoDb open database for saving data related to sign command
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

// GetReShareInfoDir get dir of database for saving data related to reshare command
func GetReShareInfoDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcreshareinfo" + curEnode
	return dir
}

// GetSmpcReShareInfoDb open database for saving data related to reshare command
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

// StartSmpcLocalDb open all database
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

	reqaddrinfodb = GetCmdReqAddrInfoDb()
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

	//giddb = GetSmpcGidDb()
	//if giddb == nil {
	//	common.Error("======================StartSmpcLocalDb,open giddb fail=====================")
	//	return errors.New("open giddb fail")
	//}

	return nil
}

//--------------------------------------------------------

// CleanUpAllReqAddrInfo Delete the data related to generating pubkey command from the corresponding sub database, and correspondingly change the status of the command data to timeout in the general database.
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

		err = DeleteReqAddrInfoData(key)
		if err != nil {
		    continue
		}
		err = PutPubKeyData(key, []byte(es))
		if err != nil {
		    continue
		}
	}
	iter.Release()
}

//----------------------------------------------------------------------------------

// CleanUpAllSignInfo Delete the data related to sign command from the corresponding sub database, and correspondingly change the status of the command data to timeout in the general database.
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

		err = DeleteSignInfoData(key)
		if err != nil {
			continue
		}
		err = PutPubKeyData(key, []byte(es))
		if err != nil {
			continue
		}
	}
	iter.Release()
}

//------------------------------------------------------------------------------------------------

// CleanUpAllReshareInfo Delete the data related to reshare command from the corresponding sub database, and correspondingly change the status of the command data to timeout in the general database.
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

		err = DeleteReShareInfoData(key)
		if err != nil {
			continue
		}
		err = PutPubKeyData(key, []byte(es))
		if err != nil {
			continue
		}
	}
	iter.Release()
}

//-----------------------------------------------------------------------------------------------------

// GetAccountsDir get dir of the database for saving all pubkeys  
func GetAccountsDir() string {
	dir := common.DefaultDataDir()
	tmp := dir + "/dcrmdata/dcrmaccounts" + curEnode
	if common.FileExist(tmp) == true {
		return tmp
	}

	dir += "/smpcdata/smpcaccounts" + curEnode
	return dir
}

//AccountLoaded Determine whether the database has been loaded  
func AccountLoaded() bool {
	dir := GetAccountsDir()
	return common.FileExist(dir)
}

// GetSmpcAccountsDirDb open database for saving all pubkeys
func GetSmpcAccountsDirDb() *ethdb.LDBDatabase {
	dir := GetAccountsDir()
	accountsdb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================GetSmpcAccountsDirDb,open accountsdb fail======================", "err", err, "dir", dir)
		return nil
	}

	return accountsdb
}

// GetSmpcGidDb open database for group db
func GetSmpcGidDb() *ethdb.LDBDatabase {
	dir := discover.GetGroupDir()
	giddb, err := ethdb.NewLDBDatabase(dir, cache, handles)
	if err != nil {
		common.Error("======================GetSmpcGidDb,open giddb fail======================", "err", err, "dir", dir)
		return nil
	}

	return giddb
}

// CopyAllAccountsFromDb Load the pubkeys generated by history,execute it only once 
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
		err = PutAccountDataToDb([]byte(key), []byte(pubkey))
		if err != nil {
			continue
		}
	}

	iter.Release()
}

// GetAccountFromDb get value from database for saving all pubkeys 
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

// PutAccountDataToDb put value to database for saving all pubkeys
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

// DeleteAccountDataFromDb delete value from database for saving all pubkeys
func DeleteAccountDataFromDb(key []byte) error {
	if key == nil || accountsdb == nil {
		return fmt.Errorf("delete account data from db fail")
	}

	err := accountsdb.Delete(key)
	if err == nil {
		common.Debug("===============DeleteAccountDataFromDb, del account data from db success.=================", "key", string(key))
		return nil
	}

	common.Error("===============DeleteAccountDataFromDb, delete account data from db fail.=================", "key", string(key), "err", err)
	return err
}

//----------------------------------------------------------

// GetTeeParamDataDir get tee param data dir  
func GetTeeParamDataDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/teeparamdata" + curEnode
	return dir
}


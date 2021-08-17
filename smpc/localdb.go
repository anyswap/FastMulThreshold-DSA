/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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
    "github.com/anyswap/Anyswap-MPCNode/internal/common"
    "github.com/anyswap/Anyswap-MPCNode/internal/common/fdlimit"
    "github.com/anyswap/Anyswap-MPCNode/ethdb"
    "fmt"
    "errors"
    "github.com/anyswap/Anyswap-MPCNode/p2p/discover"
)

var (
	cache = (75*1024)/1000 
	handles = makeDatabaseHandles()
	
	db *ethdb.LDBDatabase
	dbsk *ethdb.LDBDatabase
	dbbip32 *ethdb.LDBDatabase
	predb *ethdb.LDBDatabase
	prekey *ethdb.LDBDatabase
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

func GetPubKeyData(key []byte) (bool,interface{}) {
    if key == nil || db == nil {
	    common.Error("========================GetPubKeyData, param err=======================","key",string(key))
	return false,nil
    }
	
    da, err := db.Get(key)
    if da == nil || err != nil {
	common.Error("========================GetPubKeyData, get pubkey data from local db fail =======================","key",string(key))
	return false,nil
    }
 
    ss, err := UnCompress(string(da))
    if err != nil {
	common.Error("========================GetPubKeyData, uncompress err=======================","err",err,"key",string(key))
	return true,da
    }
 
    pubs3, err := Decode2(ss, "PubKeyData")
    if err == nil {
	pd,ok := pubs3.(*PubKeyData)
	if ok && pd.Key != "" && pd.Save != "" {  
	    return true,pd
	}
    }
    
    pubs4, err := Decode2(ss, "AcceptSignData")
    if err == nil {
	pd,ok := pubs4.(*AcceptSignData)
	if ok && pd.Keytype != "" {
	    return true,pd
 	}
    }
    
    pubs5, err := Decode2(ss, "AcceptReShareData")
    if err == nil {
	pd,ok := pubs5.(*AcceptReShareData)
	if ok && pd.TSGroupId != "" {
	    return true,pd
 	}
    }
    
    pubs, err := Decode2(ss, "AcceptReqAddrData")
    if err == nil {
	pd,ok := pubs.(*AcceptReqAddrData)
	if ok {
	    return true,pd
 	}
    }
    
    return false,nil
}

//------------------------------------------------------------------------------------------

func PutPubKeyData(key []byte,value []byte) error {
    if db == nil || key == nil || value == nil {
	return fmt.Errorf("put pubkey data to db fail")
    }
 
    err := db.Put(key,value)
    if err == nil {
	common.Debug("===============PutPubKeyData, put pubkey data into db success.=================","key",string(key))
	return nil	
    }
	
    common.Error("===============PutPubKeyData, put pubkey data into db fail.=================","key",string(key),"err",err)
    return err
}

//----------------------------------------------------------------------------------------------

func DeletePubKeyData(key []byte) error {
    if key == nil || db == nil {
	return fmt.Errorf("delete pubkey data from db fail.")
    }
 
    err := db.Delete(key)
    if err == nil {
	common.Debug("===============DeletePubKeyData, del pubkey data from db success.=================","key",string(key))
	return nil
    }
 
    common.Error("===============DeletePubKeyData, delete pubkey data from db fail.=================","key",string(key),"err",err)
    return err
}

//--------------------------------------------------------------------------------------------------------------

func getSkU1FromLocalDb(key []byte) []byte {
    if key == nil || dbsk == nil {
	return nil
     }
 
    da, err := dbsk.Get(key)
    if err != nil || da == nil {
	common.Error("========================getSkU1FromLocalDb,get sku1 from local db error.=========================","err",err)
	return nil
     }
 
    sk,err := DecryptMsg(string(da))
    if err != nil {
	common.Error("========================getSkU1FromLocalDb,decrypt sku1 data error.=========================","err",err)
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
	common.Error("========================getBip32cFromLocalDb,get bip32c from local db error.=========================","err",err)
	return nil
     }
 
    c,err := DecryptMsg(string(da))
    if err != nil {
	common.Error("========================getBip32cFromLocalDb,decrypt bip32c data error.=========================","err",err)
	return da
    }
 
    return []byte(c)
}

//--------------------------------------------------------------------------------------------------------------------

func putSkU1ToLocalDb(key []byte,value []byte)  error {
    if dbsk == nil || key == nil || value == nil {
	return fmt.Errorf("put sku1 data to db fail")
     }
 
    cm,err := EncryptMsg(string(value),cur_enode)
     if err != nil {
	common.Error("===============putSkU1ToLocalDb, encrypt sku1 data fail.=================","err",err)
	return err
     }
 
    err = dbsk.Put(key,[]byte(cm))
    if err == nil {
	common.Debug("===============putSkU1ToLocalDb, put sku1 data into db success.=================")
	return nil	
     }
	
    common.Error("===============putSkU1ToLocalDb, put sku1 data to db fail.=================","err",err)
    return err
}

//-------------------------------------------------------------------------------------------------------------

func putBip32cToLocalDb(key []byte,value []byte)  error {
    if dbbip32 == nil || key == nil || value == nil {
	return fmt.Errorf("put bip32c to db fail")
     }
 
    cm,err := EncryptMsg(string(value),cur_enode)
     if err != nil {
	common.Error("===============putBip32cToLocalDb, encrypt bip32c fail.=================","err",err)
	return err
     }
 
    err = dbbip32.Put(key,[]byte(cm))
    if err == nil {
	common.Debug("===============putBip32cToLocalDb, put bip32c into db success.=================")
	return nil	
     }
	
    common.Error("===============putBip32cToLocalDb, put bip32c to db fail.=================","err",err)
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
 
    common.Error("===============deleteSkU1FromLocalDb, delete sku1 data from db fail.=================","err",err)
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
 
    common.Error("===============deleteBip32cFromLocalDb, delete bip32c from db fail.=================","err",err)
    return err
}

//-------------------------------------------------------

func GetGroupDir() string { //TODO
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcdb" + discover.GetLocalID().String() + "group"
	return dir
}

//--------------------------------------------------------

func GetDbDir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/smpcdb" + cur_enode
	return dir
}

func GetSmpcDb() *ethdb.LDBDatabase {
    dir := GetDbDir()
    db, err := ethdb.NewLDBDatabase(dir, cache, handles)
    if err != nil {
	common.Error("======================GetSmpcDb,open db fail======================","err",err,"dir",dir)
	return nil
    }

    return db
}

//-----------------------------------------------------------

func GetSkU1Dir() string {
	dir := common.DefaultDataDir()
	dir += "/smpcdata/sk" + cur_enode
	return dir
}

func GetSmpcSkDb() *ethdb.LDBDatabase {
    dir := GetSkU1Dir()
    dbsk, err := ethdb.NewLDBDatabase(dir,cache,handles)
    if err != nil {
	common.Error("======================smpc.Start,open dbsk fail======================","err",err,"dir",dir)
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
	common.Error("======================smpc.Start,open dbbip32 fail======================","err",err,"dir",dir)
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
	common.Error("======================smpc.Start,open predb fail======================","err",err,"dir",dir)
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
	common.Error("======================smpc.Start,open prekey fail======================","err",err,"dir",dir)
	return nil
    }

    return prekey
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

    return nil
}

//--------------------------------------------------------



/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  hezhaojun@anyswap.exchange huangweijun@anyswap.exchange
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

// Package main  Gsmpc-client main program 
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"
	"time"

	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/sha3"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/ethdb"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/hexutil"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/onrik/ethrpc"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	msgsigsha3 "golang.org/x/crypto/sha3"
)

const (
    	// KEYFILE keystore file
	KEYFILE      = `{"version":3,"id":"16b5e31c-cd1a-4cdc-87a6-fc4164766698","address":"00c37841378920e2ba5151a5d1e074cf367586c4","crypto":{"ciphertext":"2070bf8491759f01b4f3f4d6d4b2e274f105be8dc01edd1ebce8d7d954eb64bd","cipherparams":{"iv":"03263465543e4631db50ecfc6b75a74f"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"9c7b6430552524f0bc1b47bed69e34b0595bc29af4d12e65ec966b16af9c2cf6","n":8192,"r":8,"p":1},"mac":"44d1b7106c28711b06cda116205ee741cba90ab3df0776d59c246b876ded0e97"}}`
	
	// SmpcToAddr smpc tx to addr
	SmpcToAddr = `0x00000000000000000000000000000000000000dc`

	// CHID smpc wallet service ID
	CHID     = 30400 //SMPC_walletService  ID
)

var (
	keyfile     *string
	datadir     *string
	logfilepath *string
	loop        *string
	n           *string
	passwd      *string
	passwdfile  *string
	url         *string
	cmd         *string
	gid         *string
	ts          *string
	mode        *string
	toAddr      *string
	value       *string
	coin        *string
	fromAddr    *string
	memo        *string
	accept      *string
	key         *string
	keyType     *string
	pubkey      *string
	inputcode   *string
	msghash     *string
	enode       *string
	tsgid       *string
	netcfg      *string
	msgsig      *string

	enodesSig         arrayFlags
	nodes             arrayFlags
	hashs             arrayFlags
	subgids           arrayFlags
	contexts          arrayFlags
	keyWrapper        *keystore.Key
	signer            types.EIP155Signer
	client            *ethrpc.EthRPC
	predb             *ethdb.LDBDatabase
	presignhashpairdb *ethdb.LDBDatabase
)

func main() {
	switch *cmd {
	case "EnodeSig":
		// get enode after sign
		enodeSig()
	case "SetGroup":
		// get GID
		setGroup()
	case "REQSMPCADDR":
		// req SMPC account
		if *msgsig == "true" {
		    reqKeyGen()
		} else {
		    reqSmpcAddr()
		}
	case "ACCEPTREQADDR":
		// req condominium account
		if *msgsig == "true" {
		    acceptKeyGen()
		} else {
		    acceptReqAddr()
		}
	case "LOCKOUT":
		lockOut()
	case "ACCEPTLOCKOUT":
		// approve condominium account lockout
		acceptLockOut()
	case "SIGN":
		PrintSignResultToLocalFile()
		// test sign
		innerloop, err := strconv.ParseUint(*n, 0, 64)
		if err != nil {
			fmt.Printf("==========================test sign fail, --n param error, n = %v,err = %v=======================\n", *n, err)
			return
		}
		outerloop, err := strconv.ParseUint(*loop, 0, 64)
		if err != nil {
			fmt.Printf("==========================test sign fail, --loop param error, n = %v,err = %v=======================\n", *loop, err)
			return
		}

		var outwg sync.WaitGroup
		for j := 0; j < int(outerloop); j++ {
			outwg.Add(1)
			go func() {
				defer outwg.Done()
				var wg sync.WaitGroup
				for i := 0; i < int(innerloop); i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if *msgsig == "true" {
						    signing()
						} else {
						    sign()
						}
					}()
				}
				wg.Wait()
			}()

			time.Sleep(time.Duration(3) * time.Second)
		}
		outwg.Wait()
	case "PRESIGNDATA":
		// test pre sign data
		if *msgsig == "true" {
		    preSigning()
		} else {
		    preGenSignData()
		}
	case "DELPRESIGNDATA":
		// test pre sign data
		delPreSignData()
	case "GETPRESIGNDATA":
		// test pre sign data
		getPreSignData()
	case "ACCEPTSIGN":
		// approve condominium account sign
		if *msgsig == "true" {
		    acceptSigning()
		} else {
		    acceptSign()
		}
	case "RESHARE":
		// test reshare
		if *msgsig == "true" {
		    resharing()
		} else {
		    reshare()
		}
	case "ACCEPTRESHARE":
		// approve condominium account reshare
		if *msgsig == "true" {
		    acceptResharing()
		} else {
		    acceptReshare()
		}
	case "CREATECONTRACT":
		err := createContract()
		if err != nil {
			fmt.Printf("createContract failed. %v\n", err)
			return
		}
	case "GETSMPCADDR":
		err := getSmpcAddr()
		if err != nil {
			fmt.Printf("pubkey = %v, get smpc addr failed. %v\n", pubkey, err)
			return
		}
	default:
		fmt.Printf("\nCMD('%v') not support\nSupport cmd: EnodeSig|SetGroup|REQSMPCADDR|ACCEPTREQADDR|ACCEPTLOCKOUT|SIGN|PRESIGNDATA|DELPRESIGNDATA|GETPRESIGNDATA|ACCEPTSIGN|RESHARE|ACCEPTRESHARE|CREATECONTRACT|GETSMPCADDR\n", *cmd)
	}
}

func init() {
	keyfile = flag.String("keystore", "", "Keystore file")
	datadir = flag.String("datadir", "", "data path")
	logfilepath = flag.String("logfilepath", "", "the path of log file")
	loop = flag.String("loop", "10", "sign outer loop count")
	n = flag.String("n", "100", "sign loop count")
	passwd = flag.String("passwd", "111111", "Password")
	passwdfile = flag.String("passwdfile", "", "Password file")
	url = flag.String("url", "http://127.0.0.1:9011", "Set node RPC URL")
	cmd = flag.String("cmd", "", "EnodeSig|SetGroup|REQSMPCADDR|ACCEPTREQADDR|ACCEPTLOCKOUT|SIGN|PRESIGNDATA|DELPRESIGNDATA|GETPRESIGNDATA|ACCEPTSIGN|RESHARE|ACCEPTRESHARE|CREATECONTRACT|GETSMPCADDR")
	gid = flag.String("gid", "", "groupID")
	ts = flag.String("ts", "2/3", "Threshold")
	mode = flag.String("mode", "2", "Mode:private=1/managed=0")
	toAddr = flag.String("to", "0x0520e8e5E08169c4dbc1580Dc9bF56638532773A", "To address")
	value = flag.String("value", "10000000000000000", "lockout value")
	coin = flag.String("coin", "FSN", "Coin type")
	netcfg = flag.String("netcfg", "mainnet", "chain config") //mainnet or testnet
	msgsig = flag.String("msgsig", "true", "msg sign flag") //false or true
	fromAddr = flag.String("from", "", "From address")
	memo = flag.String("memo", "smpcwallet.com", "Memo")
	accept = flag.String("accept", "AGREE", "AGREE|DISAGREE")
	key = flag.String("key", "", "Accept key")
	keyType = flag.String("keytype", smpclib.EC256K1, "EC256K1|ED25519|EC256STARK|SR25519")
	pubkey = flag.String("pubkey", "", "Smpc pubkey")
	inputcode = flag.String("inputcode", "", "bip32 input code")
	//msghash = flag.String("msghash", "", "msghash=Keccak256(unsignTX)")
	pkey := flag.String("pkey", "", "Private key")
	enode = flag.String("enode", "", "enode")
	tsgid = flag.String("tsgid", "", "Threshold group ID")
	// array
	flag.Var(&enodesSig, "sig", "Enodes Sig list")
	flag.Var(&nodes, "node", "Node rpc url")
	flag.Var(&hashs, "msghash", "unsigned tx hash array")
	flag.Var(&contexts, "msgcontext", "unsigned tx context array")
	flag.Var(&subgids, "subgid", "sub group id array")

	// create contract flags
	flag.StringVar(&nodeChainIDStr, "chainID", nodeChainIDStr, "chain ID of full node")
	flag.StringVar(&gatewayURL, "gateway", gatewayURL, "gateway of full node RPC address")
	flag.Uint64Var(&gasLimit, "gas", gasLimit, "gas limit")
	flag.StringVar(&gasPriceStr, "gasPrice", gasPriceStr, "gas price")
	flag.StringVar(&bytecodeFile, "bytecode", bytecodeFile, "path of bytecode file")
	flag.BoolVar(&dryrun, "dryrun", dryrun, "dry run")

	flag.Parse()

	// To account
	toAccDef := accounts.Account{
		Address: common.HexToAddress(SmpcToAddr),
	}
	fmt.Println("To address: = ", toAccDef.Address.String())
	var err error
	// decrypt private key
	var keyjson []byte
	if *keyfile != "" {
		keyjson, err = ioutil.ReadFile(*keyfile)
		if err != nil {
			fmt.Println("Read keystore fail", err)
			panic(err)
		}
	} else {
		keyjson = []byte(KEYFILE)
	}
	keyWrapper, err = keystore.DecryptKey(keyjson, strings.TrimSpace(*passwd))
	if err != nil {
		if *passwdfile != "" {
			pass, err := ioutil.ReadFile(*passwdfile)
			if err != nil {
				fmt.Println("Read passwd file fail", err)
				fmt.Println("Key decrypt error:")
				panic(err)
			} else {
				keyWrapper, err = keystore.DecryptKey(keyjson, strings.TrimSpace(string(pass)))
				if err != nil {
					fmt.Println("Key decrypt error:")
					panic(err)
				}
			}
		} else {
			fmt.Println("Key decrypt error:")
			panic(err)
		}
	}
	if *pkey != "" {
		priKey, err := crypto.HexToECDSA(*pkey)
		if err != nil {
			panic(err)
		}
		keyWrapper.PrivateKey = priKey
	}

	fmt.Printf("Recover from address = %s\n", keyWrapper.Address.String())
	// set signer and chain id
	chainID := big.NewInt(CHID)
	signer = types.NewEIP155Signer(chainID)
	// init RPC client
	client = ethrpc.New(*url)
}

// enodeSig get enode sign data, Format is "pubkey@IP:PORT" + hex.EncodeToString(crypto.Sign(crypto.Keccak256(pubkey), privateKey))
// pubkey is the enodeId
func enodeSig() {
	enodeRep, err := client.Call("smpc_getEnode")
	if err != nil {
		panic(err)
	}
	fmt.Printf("getEnode = %s\n\n", enodeRep)
	var enodeJSON dataEnode
	enodeData, _ := getJSONData(enodeRep)
	if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
		panic(err)
	}
	fmt.Printf("enode = %s\n", enodeJSON.Enode)
	// get pubkey from enode
	if *enode != "" {
		enodeJSON.Enode = *enode
	}
	s := strings.Split(enodeJSON.Enode, "@")
	enodePubkey := strings.Split(s[0], "//")
	fmt.Printf("enodePubkey = %s\n", enodePubkey[1])
	
	if  *mode == "2" {
	    fmt.Printf("\nenodeSig self = \n%s\n\n", enodePubkey[1]+":"+keyWrapper.Address.String())
	    return
	}

	hash := GetMsgSigHash([]byte(enodePubkey[1]))
	//sig, err := crypto.Sign(crypto.Keccak256([]byte(enodePubkey[1])), keyWrapper.PrivateKey)
	sig, err := crypto.Sign(hash, keyWrapper.PrivateKey)
	if err != nil {
	    panic(err)
	}
	fmt.Printf("\nenodeSig self = \n%s\n\n", enodeJSON.Enode+common.ToHex(sig))
}

// setGroup set group info
func setGroup() {
	var enodeList []string
	// get enodes from enodesSig by arg -sig
	if len(enodesSig) > 0 {
		enodeList = make([]string, len(enodesSig))
		for i := 0; i < len(enodesSig); i++ {
			s := strings.Split(enodesSig[i], "0x")
			enodeList[i] = s[0]
			fmt.Printf("enode[%d] = %s\n", i, enodeList[i])
		}
		// get enodes from rpc by arg -node
	} else if len(nodes) > 0 {
		enodeList = make([]string, len(nodes))
		for i := 0; i < len(nodes); i++ {
			client := ethrpc.New(nodes[i])
			enodeRep, err := client.Call("smpc_getEnode")
			if err != nil {
				panic(err)
			}
			var enodeJSON dataEnode
			enodeData, _ := getJSONData(enodeRep)
			if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
				panic(err)
			}
			enodeList[i] = enodeJSON.Enode
			fmt.Printf("enode[%d] = %s\n", i, enodeList[i])
		}
	}
	// get gid by send createGroup
	groupRep, err := client.Call("smpc_createGroup", *ts, enodeList)
	if err != nil {
		panic(err)
	}
	fmt.Printf("smpc_createGroup = %s\n", groupRep)
	var groupJSON groupInfo
	groupData, _ := getJSONData(groupRep)
	if err := json.Unmarshal(groupData, &groupJSON); err != nil {
		panic(err)
	}
	fmt.Printf("\nGid = %s\n\n", groupJSON.Gid)
}

// reqKeyGen  Execute generate pubkey 
func reqKeyGen() {
	// get nonce
	reqAddrNonce, err := client.Call("smpc_getReqAddrNonce", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	nonceStr, _ := getJSONResult(reqAddrNonce)
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("smpc_getReqAddrNonce = %s\nNonce = %d\n", reqAddrNonce, nonce)
	// build Sigs list parameter
	sigs := ""
	//if *mode == "0" || *mode == "2" {
	if *mode == "0" {
		for i := 0; i < len(enodesSig)-1; i++ {
			sigs = sigs + enodesSig[i] + "|"
		}
		sigs = sigs + enodesSig[len(enodesSig)-1]
	}

	if *mode == "2" {
	    sigs = strconv.Itoa(len(enodesSig)) + ":"
	    for i := 0; i < len(enodesSig)-1; i++ {
		sigs = sigs + enodesSig[i] + ":"
	    }
	    sigs = sigs + enodesSig[len(enodesSig)-1]
	}
	fmt.Printf("sigs = \n%s\n",sigs)

	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := reqAddrData{
		TxType:    *cmd,
		Account:    keyWrapper.Address.String(),
              Nonce:strconv.Itoa(int(nonce)),
		Keytype:   *keyType,
		GroupID:   *gid,
		ThresHold: *ts,
		Mode:      *mode,
		AcceptTimeOut: "600",
		TimeStamp: timestamp,
		Sigs:      sigs,
	}
	 playload, err := json.Marshal(txdata)
       if err != nil {
           fmt.Printf("reqaddr fail,err",err)
           panic(err)
       }

	// sign tx
	rsv,err := signMsg(keyWrapper.PrivateKey,playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("smpc_reqKeyGen", rsv,string(playload))
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nsmpc_reqKeyGen keyID = %s\n\n", keyID)

	fmt.Printf("\nWaiting for stats result...\n")
	// get accounts
	time.Sleep(time.Duration(20) * time.Second)
	accounts, err := client.Call("smpc_getAccounts", keyWrapper.Address.String(), *mode)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\naddress = %s\naccounts = %s\n\n", keyWrapper.Address.String(), accounts)

	// traverse key from reqAddr failed by keyID
	time.Sleep(time.Duration(2) * time.Second)
	fmt.Printf("\nreqSMPCAddr:User=%s", keyWrapper.Address.String())
	var statusJSON reqAddrStatus
	reqStatus, err := client.Call("smpc_getReqAddrStatus", keyID)
	if err != nil {
		fmt.Println("\tsmpc_getReqAddrStatus rpc error:", err)
		return
	}
	statusJSONStr, err := getJSONResult(reqStatus)
	if err != nil {
		fmt.Printf("\tsmpc_getReqAddrStatus=NotStart\tkeyID=%s ", keyID)
		fmt.Println("\tRequest not complete:", err)
		return
	}
	if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
		fmt.Println("\treqSMPCAddr:User=%s\tUnmarshal statusJSONStr fail:", err)
		return
	}
	if statusJSON.Status != "Success" {
		fmt.Printf("\tsmpc_getReqAddrStatus=%s\tkeyID=%s", statusJSON.Status, keyID)
	} else {
		fmt.Printf("\tSuccess\tPubkey=%s\n", statusJSON.PubKey)
	}
}

// reqSmpcAddr  Execute generate pubkey 
func reqSmpcAddr() {
	// get nonce
	reqAddrNonce, err := client.Call("smpc_getReqAddrNonce", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	nonceStr, _ := getJSONResult(reqAddrNonce)
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("smpc_getReqAddrNonce = %s\nNonce = %d\n", reqAddrNonce, nonce)
	// build Sigs list parameter
	sigs := ""
	//if *mode == "0" || *mode == "2" {
	if *mode == "0" {
		for i := 0; i < len(enodesSig)-1; i++ {
			sigs = sigs + enodesSig[i] + "|"
		}
		sigs = sigs + enodesSig[len(enodesSig)-1]
	}
	
	if *mode == "2" {
	    sigs = strconv.Itoa(len(enodesSig)) + ":"
	    for i := 0; i < len(enodesSig)-1; i++ {
		sigs = sigs + enodesSig[i] + ":"
	    }
	    sigs = sigs + enodesSig[len(enodesSig)-1]
	}
	fmt.Printf("sigs = \n%s\n",sigs)

	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := reqAddrData{
		TxType:    *cmd,
		Keytype:   *keyType,
		GroupID:   *gid,
		ThresHold: *ts,
		Mode:      *mode,
		AcceptTimeOut: "600",
		TimeStamp: timestamp,
		Sigs:      sigs,
	}
	playload, _ := json.Marshal(txdata)

	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, nonce, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("smpc_reqSmpcAddr", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nsmpc_reqSmpcAddr keyID = %s\n\n", keyID)

	fmt.Printf("\nWaiting for stats result...\n")
	// get accounts
	time.Sleep(time.Duration(20) * time.Second)
	accounts, err := client.Call("smpc_getAccounts", keyWrapper.Address.String(), *mode)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\naddress = %s\naccounts = %s\n\n", keyWrapper.Address.String(), accounts)

	// traverse key from reqAddr failed by keyID
	time.Sleep(time.Duration(2) * time.Second)
	fmt.Printf("\nreqSMPCAddr:User=%s", keyWrapper.Address.String())
	var statusJSON reqAddrStatus
	reqStatus, err := client.Call("smpc_getReqAddrStatus", keyID)
	if err != nil {
		fmt.Println("\tsmpc_getReqAddrStatus rpc error:", err)
		return
	}
	statusJSONStr, err := getJSONResult(reqStatus)
	if err != nil {
		fmt.Printf("\tsmpc_getReqAddrStatus=NotStart\tkeyID=%s ", keyID)
		fmt.Println("\tRequest not complete:", err)
		return
	}
	if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
		fmt.Println("\treqSMPCAddr:User=%s\tUnmarshal statusJSONStr fail:", err)
		return
	}
	if statusJSON.Status != "Success" {
		fmt.Printf("\tsmpc_getReqAddrStatus=%s\tkeyID=%s", statusJSON.Status, keyID)
	} else {
		fmt.Printf("\tSuccess\tPubkey=%s\n", statusJSON.PubKey)
	}
}

// acceptKeyGen  Agree to generate pubkey 
func acceptKeyGen() {
	// get reqAddr account list
	reqListRep, err := client.Call("smpc_getCurNodeReqAddrInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeReqAddrInfo = %s\n", reqListJSON)

	var keyList []reqAddrCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal reqAddrCurNodeInfo fail:", err)
		return
	}

	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}

		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			 Account:keyWrapper.Address.String(),
                       Nonce:"0",
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rsv, err := signMsg(keyWrapper.PrivateKey, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptReqAddrRep, err := client.Call("smpc_acceptKeyGen", rsv,string(playload))
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptReqAddrRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptReq result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

// acceptReqAddr  Agree to generate pubkey 
func acceptReqAddr() {
	// get reqAddr account list
	reqListRep, err := client.Call("smpc_getCurNodeReqAddrInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeReqAddrInfo = %s\n", reqListJSON)

	var keyList []reqAddrCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal reqAddrCurNodeInfo fail:", err)
		return
	}

	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}

		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptReqAddrRep, err := client.Call("smpc_acceptReqAddr", rawTX)
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptReqAddrRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptReq result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

func lockOut() {
	// get lockout nonce
	lockoutNonce, err := client.Call("smpc_getLockOutNonce", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	nonceStr, err := getJSONResult(lockoutNonce)
	if err != nil {
		panic(err)
	}
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("smpc_getLockOutNonce = %s\nNonce = %d\n", lockoutNonce, nonce)
	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := lockoutData{
		TxType:    *cmd,
		SmpcAddr:  *fromAddr,
		SmpcTo:    *toAddr,
		Value:     *value,
		Cointype:  *coin,
		GroupID:   *gid,
		ThresHold: *ts,
		Mode:      *mode,
		TimeStamp: timestamp,
		Memo:      *memo,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, nonce, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("smpc_lockOut", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID from result
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nsmpc_lockOut keyID = %s\n\n", keyID)
	fmt.Printf("\nWaiting for stats result...\n")
	// traverse key from reqAddr failed by keyID
	time.Sleep(time.Duration(30) * time.Second)
	fmt.Printf("\n\nUser=%s\n", keyWrapper.Address.String())
	var statusJSON lockoutStatus
	reqStatus, err := client.Call("smpc_getLockOutStatus", keyID)
	if err != nil {
		fmt.Println("\nsmpc_getLockOutStatus rpc error:", err)
		return
	}
	statusJSONStr, err := getJSONResult(reqStatus)
	if err != nil {
		fmt.Printf("\tsmpc_getLockOutStatus=NotStart\tkeyID=%s ", keyID)
		fmt.Println("\tRequest not complete:", err)
		return
	}
	if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
		fmt.Println("\tUnmarshal statusJSONStr fail:", err)
		return
	}
	if statusJSON.Status != "Success" {
		fmt.Printf("\tsmpc_getLockOutStatus=%s\tkeyID=%s  ", statusJSON.Status, keyID)
	} else {
		fmt.Printf("\tSuccess\tOutTXhash=%s", statusJSON.OutTxHash)
	}
}
func acceptLockOut() {
	// get approve list of condominium account
	reqListRep, err := client.Call("smpc_getCurNodeLockOutInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeLockOutInfo = %s\n", reqListJSON)

	var keyList []lockoutCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal lockoutCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptLockOutRep, err := client.Call("smpc_acceptLockOut", rawTX)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptLockOut = %s\n\n", acceptLockOutRep)
		// get result
		acceptRet, err := getJSONResult(acceptLockOutRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptLockOut result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

// signing Execute MPC sign 
func signing() {
	//if *msghash == "" {
	//	*msghash = common.ToHex(crypto.Keccak256([]byte(*memo)))
	//}
	if len(hashs) == 0 {
		hashs = append(hashs, common.ToHex(crypto.Keccak256([]byte(*memo))))
	}

	if len(contexts) == 0 {
		contexts = append(contexts, *memo)
	}

	signingMsgHash(hashs, contexts, 10)
}

// sign Execute MPC sign 
func sign() {
	//if *msghash == "" {
	//	*msghash = common.ToHex(crypto.Keccak256([]byte(*memo)))
	//}
	if len(hashs) == 0 {
		hashs = append(hashs, common.ToHex(crypto.Keccak256([]byte(*memo))))
	}

	if len(contexts) == 0 {
		contexts = append(contexts, *memo)
	}

	signMsgHash(hashs, contexts, 10)
}

//  preSigning Generate relevant data required for distributed sign in advance 
func preSigning() {
	if len(subgids) == 0 {
		panic(fmt.Errorf("error:sub group id array is empty"))
	}

	txdata := preSignData{
		TxType: "PRESIGNDATA",
		Account:keyWrapper.Address.String(),
               Nonce:"0",
		PubKey: *pubkey,
		SubGid: subgids,
		KeyType: *keyType,
	}
	playload, err := json.Marshal(txdata)
       if err != nil {
           panic(err)
       }
	// sign tx
	rsv, err := signMsg(keyWrapper.PrivateKey,playload)
	if err != nil {
		panic(err)
	}
	// get rawTx
	_, err = client.Call("smpc_preSigning", rsv,string(playload))
	if err != nil {
		panic(err)
	}
}

//  preGenSignData Generate relevant data required for distributed sign in advance 
func preGenSignData() {
	if len(subgids) == 0 {
		panic(fmt.Errorf("error:sub group id array is empty"))
	}

	txdata := preSignData{
		TxType: "PRESIGNDATA",
		PubKey: *pubkey,
		SubGid: subgids,
		KeyType: *keyType,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
	if err != nil {
		panic(err)
	}
	// get rawTx
	_, err = client.Call("smpc_preGenSignData", rawTX)
	if err != nil {
		panic(err)
	}
}

//------------------------------------------------------------------

// DefaultDataDir default data dir
func DefaultDataDir(datadir string) string {
	if datadir != "" {
		return datadir
	}
	// Try to place the data folder in the user's home dir
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "smpc-walletservice")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "smpc-walletservice")
		} else {
			return filepath.Join(home, ".smpc-walletservice")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

// homeDir get home path
func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

// GetPreDbDir Obtain the database path to store the relevant data required by the distributed sign 
func GetPreDbDir(eid string, datadir string) string {
	dir := DefaultDataDir(datadir)
	dir += "/smpcdata/smpcpredb" + eid

	return dir
}

// PrePubData pre-sign data
type PrePubData struct {
	Key    string
	K1     *big.Int
	R      *big.Int
	Ry     *big.Int
	Sigma1 *big.Int
	Gid    string
	Used   bool //useless? TODO
}

// PreSignDataValue pre-sign data set
type PreSignDataValue struct {
	Data []*PrePubData
}

// Decode decode string by data type
func Decode(s string, datatype string) (interface{}, error) {

	if datatype == "PreSignDataValue" {
		var m PreSignDataValue
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
			return nil, err
		}

		return &m, nil
	}

	return nil, fmt.Errorf("decode obj fail")
}

// DecodePreSignDataValue decode PreSignDataValue
func DecodePreSignDataValue(s string) (*PreSignDataValue, error) {
	if s == "" {
		return nil, fmt.Errorf("presign data error")
	}

	ret, err := Decode(s, "PreSignDataValue")
	if err != nil {
		return nil, err
	}

	return ret.(*PreSignDataValue), nil
}

// MPCHash type define
type MPCHash [32]byte

// Hex hash to hex string
func (h MPCHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h MPCHash) {
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

// delPreSignData Delete the relevant data required by the distributed sign through pubkey and group ID  
func delPreSignData() {
	enodeRep, err := client.Call("smpc_getEnode")
	if err != nil {
		panic(err)
	}
	fmt.Printf("getEnode = %s\n\n", enodeRep)
	var enodeJSON dataEnode
	enodeData, _ := getJSONData(enodeRep)
	if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
		panic(err)
	}
	fmt.Printf("enode = %s\n", enodeJSON.Enode)
	// get pubkey from enode
	if *enode != "" {
		enodeJSON.Enode = *enode
	}
	s := strings.Split(enodeJSON.Enode, "@")
	enodePubkey := strings.Split(s[0], "//")
	fmt.Printf("enodePubkey = %s\n", enodePubkey[1])

	if *pubkey == "" || *gid == "" {
		log.Fatal("Please provide pubkey,group id")
	}

	dir := GetPreDbDir(enodePubkey[1], *datadir)
	fmt.Printf("==========================delPreSignData,dir = %v ================================\n", dir)
	predbtmp, err := ethdb.NewLDBDatabase(dir, 76, 512)
	if err != nil {
		predb = nil
		if predb == nil {
			fmt.Printf("==========================delPreSignData,open db fail,dir = %v,pubkey = %v,gid = %v,cur_enode = %v ================================\n", dir, *pubkey, *gid, enodePubkey[1])
			os.Exit(1)
			return
		}
	} else {
		predb = predbtmp
	}

	if predb == nil {
		fmt.Printf("==========================delPreSignData,open db fail,dir = %v,pubkey = %v,gid = %v,cur_enode = %v ================================\n", dir, *pubkey, *gid, enodePubkey[1])
		os.Exit(1)
		return
	}

	fmt.Printf("================================delPreSignData,pubkey = %v,gid = %v ======================\n", *pubkey, *gid)

	pub := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(*pubkey + ":" + *gid))).Hex())
	iter := predb.NewIterator()
	for iter.Next() {
		key := string(iter.Key())

		fmt.Printf("================================delPreSignData, key = %v,pub = %v ======================\n", key, pub)
		if strings.EqualFold(pub, key) {
			err = predb.Delete([]byte(key))
			if err != nil {
				fmt.Printf("==========================delPreSignData, delete presign data fail,dir = %v,pubkey = %v,gid = %v,cur_enode = %v,err = %v======================\n", dir, *pubkey, *gid, enodePubkey[1], err)
			} else {
				fmt.Printf("============================delPreSignData, delete presign data success,dir = %v,pubkey = %v,gid = %v,cur_enode = %v===================\n", dir, *pubkey, *gid, enodePubkey[1])
			}

			break
		}
	}

	iter.Release()
}

// getPreSignData get the relevant data required by the distributed sign through pubkey and group ID  
func getPreSignData() {
	enodeRep, err := client.Call("smpc_getEnode")
	if err != nil {
		panic(err)
	}
	fmt.Printf("getEnode = %s\n\n", enodeRep)
	var enodeJSON dataEnode
	enodeData, _ := getJSONData(enodeRep)
	if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
		panic(err)
	}
	fmt.Printf("enode = %s\n", enodeJSON.Enode)
	// get pubkey from enode
	if *enode != "" {
		enodeJSON.Enode = *enode
	}
	s := strings.Split(enodeJSON.Enode, "@")
	enodePubkey := strings.Split(s[0], "//")
	fmt.Printf("enodePubkey = %s\n", enodePubkey[1])

	if *pubkey == "" || *gid == "" {
		log.Fatal("Please provide pubkey,group id")
	}

	dir := GetPreDbDir(enodePubkey[1], *datadir)
	fmt.Printf("==========================getPreSignData,dir = %v ================================\n", dir)
	predbtmp, err := ethdb.NewLDBDatabase(dir, 76, 512)
	if err != nil {
		predb = nil
		if predb == nil {
			fmt.Printf("==========================getPreSignData,open db fail,dir = %v,pubkey = %v,gid = %v,cur_enode = %v ================================\n", dir, *pubkey, *gid, enodePubkey[1])
			os.Exit(1)
			return
		}
	} else {
		predb = predbtmp
	}

	fmt.Printf("================================getPreSignData,pubkey = %v,gid = %v ======================\n", *pubkey, *gid)

	pub := strings.ToLower(Keccak256Hash([]byte(strings.ToLower(*pubkey + ":" + *gid))).Hex())
	iter := predb.NewIterator()
	for iter.Next() {
		key := string(iter.Key())
		value := string(iter.Value())

		fmt.Printf("================================getPreSignData, key = %v,pub = %v ======================\n", key, pub)
		if strings.EqualFold(pub, key) {
			ps, err := DecodePreSignDataValue(value)
			if err != nil {
				fmt.Printf("============================getPreSignData,decode pre-sign data value error,err = %v===========================\n")
				break
			}

			fmt.Printf("==================================getPreSignData,decode pre-sign data value success, data count = %v==========================\n", len(ps.Data))

			for _, v := range ps.Data {
				fmt.Printf("===================================getPreSignData,pub = %v, pre-sign data key = %v==========================\n", key, v.Key)
			}

			break
		}
	}

	iter.Release()
}

//----------------------------------------------------------------------------

// PrintSignResultToLocalFile print sign result to log file
func PrintSignResultToLocalFile() {
	var file string
	if logfilepath == nil {
		file = "./" + "SignResult" + ".txt" //  ./SignResult.txt
	} else {
		file = *logfilepath
	}

	logFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0766)
	if err != nil {
		return
	}
	log.SetOutput(logFile) // 将文件设置为log输出的文件
	//log.SetPrefix("[Sign]")
	//log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	return
}

// PrintTime print time
func PrintTime(t time.Time, key string, status string, loopcount int) {
	d := time.Since(t)
	str := "-------------------------------------------------------\n"
	str += "key = "
	str += key
	str += ",  "
	str += "status = "
	str += status
	str += ",  "
	str += "retry count(get every 5 seconds) = "
	str += strconv.Itoa(loopcount)
	str += ",  "
	str += "time spent = "
	s := common.PrettyDuration(d).String()
	//str += strconv.FormatFloat(d.Seconds(), 'E', -1, 64)
	str += s
	str += "\n"
	log.Println(str)
}

// signingMsgHash sign
func signingMsgHash(hashs []string, contexts []string, loopCount int) (rsv []string) {
	timevalue := time.Now()

	// get sign nonce
	signNonce, err := client.Call("smpc_getSignNonce", keyWrapper.Address.String())
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	nonceStr, err := getJSONResult(signNonce)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("smpc_getSignNonce = %s\nNonce = %d\n", signNonce, nonce)
	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := signData{
		TxType:     "SIGN",
		Account:keyWrapper.Address.String(),
               Nonce:strconv.Itoa(int(nonce)),
		PubKey:     *pubkey,
		InputCode:  *inputcode,
		MsgContext: contexts,
		MsgHash:    hashs,
		Keytype:    *keyType,
		GroupID:    *gid,
		ThresHold:  *ts,
		Mode:       *mode,
		AcceptTimeOut: "600",
		TimeStamp:  timestamp,
	}
	playload, err := json.Marshal(txdata)
       if err != nil {
           panic(err)
       }
       rsv2, err := signMsg(keyWrapper.PrivateKey,playload)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	// get rawTx
	reqKeyID, err := client.Call("smpc_signing", rsv2,string(playload))
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		//panic(err)
		return
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	fmt.Printf("\nsmpc_sign keyID = %s\n\n", keyID)
	for i, j := loopCount, 1; i != 0; j++ {
		fmt.Printf("\nWaiting for stats result (loop %v)...\n", j)
		if i > 0 {
			i--
		}
		// traverse key from reqAddr failed by keyID
		time.Sleep(time.Duration(20) * time.Second)
		fmt.Printf("\n\nUser=%s", keyWrapper.Address.String())
		var statusJSON signStatus
		reqStatus, err := client.Call("smpc_getSignStatus", keyID)
		if err != nil {
			fmt.Println("\nsmpc_getSignStatus rpc error:", err)
			continue
		}
		statusJSONStr, err := getJSONResult(reqStatus)
		if err != nil {
			fmt.Printf("\tsmpc_getSignStatus=NotStart\tkeyID=%s ", keyID)
			fmt.Println("\tRequest not complete:", err)
			continue
		}
		if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
			fmt.Println("\tUnmarshal statusJSONStr fail:", err)
			continue
		}
		switch statusJSON.Status {
		case "Timeout", "Failure":
			PrintTime(timevalue, keyID, statusJSON.Status, j)
			fmt.Printf("\tsmpc_getSignStatus=%s\tkeyID=%s\n", statusJSON.Status, keyID)
			return
		case "Success":
			PrintTime(timevalue, keyID, "Success", j)
			fmt.Printf("\tSuccess\tRSV=%s\n", statusJSON.Rsv)
			return statusJSON.Rsv
		default:
			fmt.Printf("\tsmpc_getSignStatus=%s\tkeyID=%s\n", statusJSON.Status, keyID)
			continue
		}
	}
	return
}

// signMsgHash sign
func signMsgHash(hashs []string, contexts []string, loopCount int) (rsv []string) {
	timevalue := time.Now()

	// get sign nonce
	signNonce, err := client.Call("smpc_getSignNonce", keyWrapper.Address.String())
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	nonceStr, err := getJSONResult(signNonce)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	nonce, _ := strconv.ParseUint(nonceStr, 0, 64)
	fmt.Printf("smpc_getSignNonce = %s\nNonce = %d\n", signNonce, nonce)
	// build tx data
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := signData{
		TxType:     "SIGN",
		PubKey:     *pubkey,
		InputCode:  *inputcode,
		MsgContext: contexts,
		MsgHash:    hashs,
		Keytype:    *keyType,
		GroupID:    *gid,
		ThresHold:  *ts,
		Mode:       *mode,
		AcceptTimeOut: "600",
		TimeStamp:  timestamp,
	}
	playload, _ := json.Marshal(txdata)
	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, nonce, playload)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	// get rawTx
	reqKeyID, err := client.Call("smpc_sign", rawTX)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		//panic(err)
		return
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		PrintTime(timevalue, "", "Error", 0)
		panic(err)
	}
	fmt.Printf("\nsmpc_signing keyID = %s\n\n", keyID)
	for i, j := loopCount, 1; i != 0; j++ {
		fmt.Printf("\nWaiting for stats result (loop %v)...\n", j)
		if i > 0 {
			i--
		}
		// traverse key from reqAddr failed by keyID
		time.Sleep(time.Duration(20) * time.Second)
		fmt.Printf("\n\nUser=%s", keyWrapper.Address.String())
		var statusJSON signStatus
		reqStatus, err := client.Call("smpc_getSignStatus", keyID)
		if err != nil {
			fmt.Println("\nsmpc_getSignStatus rpc error:", err)
			continue
		}
		statusJSONStr, err := getJSONResult(reqStatus)
		if err != nil {
			fmt.Printf("\tsmpc_getSignStatus=NotStart\tkeyID=%s ", keyID)
			fmt.Println("\tRequest not complete:", err)
			continue
		}
		if err := json.Unmarshal([]byte(statusJSONStr), &statusJSON); err != nil {
			fmt.Println("\tUnmarshal statusJSONStr fail:", err)
			continue
		}
		switch statusJSON.Status {
		case "Timeout", "Failure":
			PrintTime(timevalue, keyID, statusJSON.Status, j)
			fmt.Printf("\tsmpc_getSignStatus=%s\tkeyID=%s\n", statusJSON.Status, keyID)
			return
		case "Success":
			PrintTime(timevalue, keyID, "Success", j)
			fmt.Printf("\tSuccess\tRSV=%s\n", statusJSON.Rsv)
			return statusJSON.Rsv
		default:
			fmt.Printf("\tsmpc_getSignStatus=%s\tkeyID=%s\n", statusJSON.Status, keyID)
			continue
		}
	}
	return
}

// acceptSigning accept sign
func acceptSigning() {
	// get approve list of condominium account
	reqListRep, err := client.Call("smpc_getCurNodeSignInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeSignInfo = %s\n", reqListJSON)

	var keyList []signCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal signCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		var msgHash []string
		var msgContext []string

		if len(hashs) == 0 {
			hashs = append(hashs, common.ToHex(crypto.Keccak256([]byte(*memo))))
		}

		if len(contexts) == 0 {
			contexts = append(contexts, *memo)
		}

		if *key != "" {
			i = len(keyList)
			keyStr = *key
			msgHash = hashs
			msgContext = contexts
		} else {
			keyStr = keyList[i].Key
			msgHash = keyList[i].MsgHash
			msgContext = keyList[i].MsgContext
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptSignData{
			TxType:     *cmd,
			Account:keyWrapper.Address.String(),
                       Nonce:"0",
			Key:        keyStr,
			Accept:     *accept,
			MsgHash:    msgHash,
			MsgContext: msgContext,
			TimeStamp:  timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rsv, err := signMsg(keyWrapper.PrivateKey, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptSignRep, err := client.Call("smpc_acceptSigning", rsv,string(playload))
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptSignRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptSign result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

// acceptSign accept sign
func acceptSign() {
	// get approve list of condominium account
	reqListRep, err := client.Call("smpc_getCurNodeSignInfo", keyWrapper.Address.String())
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeSignInfo = %s\n", reqListJSON)

	var keyList []signCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal signCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		var msgHash []string
		var msgContext []string

		if len(hashs) == 0 {
			hashs = append(hashs, common.ToHex(crypto.Keccak256([]byte(*memo))))
		}

		if len(contexts) == 0 {
			contexts = append(contexts, *memo)
		}

		if *key != "" {
			i = len(keyList)
			keyStr = *key
			msgHash = hashs
			msgContext = contexts
		} else {
			keyStr = keyList[i].Key
			msgHash = keyList[i].MsgHash
			msgContext = keyList[i].MsgContext
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptSignData{
			TxType:     *cmd,
			Key:        keyStr,
			Accept:     *accept,
			MsgHash:    msgHash,
			MsgContext: msgContext,
			TimeStamp:  timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptSignRep, err := client.Call("smpc_acceptSign", rawTX)
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptSignRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptSign result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

// resharing  Execute Resharing
func resharing() {
	// build tx data
	sigs := ""
	for i := 0; i < len(enodesSig)-1; i++ {
		sigs = sigs + enodesSig[i] + "|"
	}

	sigs = sigs + enodesSig[len(enodesSig)-1]
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := reshareData{
		TxType:    *cmd,
		Nonce:"0",
		PubKey:    *pubkey,
		GroupID:   *gid,
		TSGroupID: *tsgid,
		ThresHold: *ts,
		Account:   keyWrapper.Address.String(),
		Mode:      *mode,
		AcceptTimeOut: "600",
		Sigs:      sigs,
		TimeStamp: timestamp,
		KeyType:    *keyType,
	}
	playload, err := json.Marshal(txdata)
	if err != nil {
		panic(err)
	}

	// sign tx
	rsv, err := signMsg(keyWrapper.PrivateKey, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("smpc_reSharing", rsv,string(playload))
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nsmpc_reShare keyID = %s\n\n", keyID)
}

// reshare  Execute Reshare 
func reshare() {
	// build tx data
	sigs := ""
	for i := 0; i < len(enodesSig)-1; i++ {
		sigs = sigs + enodesSig[i] + "|"
	}

	sigs = sigs + enodesSig[len(enodesSig)-1]
	timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
	txdata := reshareData{
		TxType:    *cmd,
		PubKey:    *pubkey,
		GroupID:   *gid,
		TSGroupID: *tsgid,
		ThresHold: *ts,
		Account:   keyWrapper.Address.String(),
		Mode:      *mode,
		AcceptTimeOut: "600",
		Sigs:      sigs,
		TimeStamp: timestamp,
		KeyType:    *keyType,
	}
	playload, err := json.Marshal(txdata)
	if err != nil {
		panic(err)
	}

	// sign tx
	rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
	if err != nil {
		panic(err)
	}
	// send rawTx
	reqKeyID, err := client.Call("smpc_reShare", rawTX)
	if err != nil {
		panic(err)
	}
	// get keyID
	keyID, err := getJSONResult(reqKeyID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nsmpc_reShare keyID = %s\n\n", keyID)
}

// acceptResharing accept reshare
func acceptResharing() {
	// get account reshare approve list
	reqListRep, err := client.Call("smpc_getCurNodeReShareInfo")
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeReShareInfo = %s\n", reqListJSON)

	var keyList []reshareCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal reshareCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Account:keyWrapper.Address.String(),
                       Nonce:"0",
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rsv, err := signMsg(keyWrapper.PrivateKey, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptSignRep, err := client.Call("smpc_acceptReSharing", rsv,string(playload))
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptSignRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptReShare result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
}

// acceptReshare accept reshare
func acceptReshare() {
	// get account reshare approve list
	reqListRep, err := client.Call("smpc_getCurNodeReShareInfo")
	if err != nil {
		panic(err)
	}
	reqListJSON, _ := getJSONData(reqListRep)
	fmt.Printf("smpc_getCurNodeReShareInfo = %s\n", reqListJSON)

	var keyList []reshareCurNodeInfo
	if err := json.Unmarshal(reqListJSON, &keyList); err != nil {
		fmt.Println("Unmarshal reshareCurNodeInfo fail:", err)
		return
	}
	// gen key list which not approve, auto accept replace input by arg -key
	for i := 0; i < len(keyList); i++ {
		// build tx data
		var keyStr string
		if *key != "" {
			i = len(keyList)
			keyStr = *key
		} else {
			keyStr = keyList[i].Key
		}
		timestamp := strconv.FormatInt((time.Now().UnixNano() / 1e6), 10)
		data := acceptData{
			TxType:    *cmd,
			Key:       keyStr,
			Accept:    *accept,
			TimeStamp: timestamp,
		}
		playload, err := json.Marshal(data)
		if err != nil {
			fmt.Println("error:", err)
			panic(err)
		}
		// sign tx
		rawTX, err := signTX(signer, keyWrapper.PrivateKey, 0, playload)
		if err != nil {
			panic(err)
		}
		// send rawTx
		acceptSignRep, err := client.Call("smpc_acceptReShare", rawTX)
		if err != nil {
			panic(err)
		}
		// get result
		acceptRet, err := getJSONResult(acceptSignRep)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nsmpc_acceptReShare result: key[%d]\t%s = %s\n\n", i+1, keyStr, acceptRet)
	}
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

// signMsg sign msg
func signMsg(privatekey *ecdsa.PrivateKey,playload []byte) (string, error) {
       // sign tx by privatekey
       hash := GetMsgSigHash(playload)
       //hash := crypto.Keccak256([]byte(header),playload)
       signature, signatureErr := crypto.Sign(hash, privatekey)
      if signatureErr != nil {
               fmt.Println("signature create error")
               panic(signatureErr)
       }
       rsv := common.ToHex(signature)
       return rsv, nil
}

// getSmpcAddr get smpc addr by pubkey
func getSmpcAddr() error {
	if pubkey == nil {
		return fmt.Errorf("pubkey error")
	}

	pub := (*pubkey)

	if pub == "" || (*coin) == "" {
		return fmt.Errorf("pubkey error")
	}

	if (*coin) != "FSN" && (*coin) != "BTC" { //only btc/fsn tmp
		return fmt.Errorf("coin type unsupported")
	}

	if len(pub) != 132 && len(pub) != 130 {
		return fmt.Errorf("invalid public key length")
	}
	if pub[:2] == "0x" || pub[:2] == "0X" {
		pub = pub[2:]
	}

	if (*coin) == "FSN" {
		pubKeyHex := strings.TrimPrefix(pub, "0x")
		data := hexEncPubkey(pubKeyHex[2:])

		pub2, err := decodePubkey(data)
		if err != nil {
			return err
		}

		address := crypto.PubkeyToAddress(*pub2).Hex()
		fmt.Printf("\ngetSmpcAddr result: %s\n\n", address)
		return nil
	}

	bb, err := hex.DecodeString(pub)
	if err != nil {
		return err
	}
	pub2, err := btcec.ParsePubKey(bb, btcec.S256())
	if err != nil {
		return err
	}

	ChainConfig := chaincfg.MainNetParams
	if (*netcfg) == "testnet" {
		ChainConfig = chaincfg.TestNet3Params
	}

	b := pub2.SerializeCompressed()
	pkHash := btcutil.Hash160(b)
	addressPubKeyHash, err := btcutil.NewAddressPubKeyHash(pkHash, &ChainConfig)
	if err != nil {
		return err
	}
	address := addressPubKeyHash.EncodeAddress()
	fmt.Printf("\ngetSmpcAddr result: %s\n\n", address)
	return nil
}

func hexEncPubkey(h string) (ret [64]byte) {
	b, err := hex.DecodeString(h)
	if err != nil {
		//panic(err)
		fmt.Printf("=============== parse pubkey error = %v ==============\n", err)
		return ret
	}
	if len(b) != len(ret) {
		//panic("invalid length")
		fmt.Printf("invalid length\n")
		return ret
	}
	copy(ret[:], b)
	return ret
}

func decodePubkey(e [64]byte) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return p, nil
}

// getJSONResult parse result from rpc return data
func getJSONResult(successResponse json.RawMessage) (string, error) {
	var data dataResult
	repData, err := getJSONData(successResponse)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(repData, &data); err != nil {
		fmt.Println("getJSONResult Unmarshal json fail:", err)
		return "", err
	}
	return data.Result, nil
}

func getJSONData(successResponse json.RawMessage) ([]byte, error) {
	var rep response
	if err := json.Unmarshal(successResponse, &rep); err != nil {
		fmt.Println("getJSONData Unmarshal json fail:", err)
		return nil, err
	}
	if rep.Status != "Success" {
		return nil, errors.New(rep.Error)
	}
	repData, err := json.Marshal(rep.Data)
	if err != nil {
		fmt.Println("getJSONData Marshal json fail:", err)
		return nil, err
	}
	return repData, nil
}

// signTX build tx with sign
func signTX(signer types.EIP155Signer, privatekey *ecdsa.PrivateKey, nonce uint64, playload []byte) (string, error) {
	toAccDef := accounts.Account{
		Address: common.HexToAddress(SmpcToAddr),
	}
	// build tx
	tx := types.NewTransaction(
		uint64(nonce),     // nonce
		toAccDef.Address,  // to address
		big.NewInt(0),     // value
		100000,            // gasLimit
		big.NewInt(80000), // gasPrice
		playload)          // data
	// sign tx by privatekey
	signature, signatureErr := crypto.Sign(signer.Hash(tx).Bytes(), privatekey)
	if signatureErr != nil {
		fmt.Println("signature create error")
		panic(signatureErr)
	}
	// build tx with sign
	sigTx, signErr := tx.WithSignature(signer, signature)
	if signErr != nil {
		fmt.Println("signer with signature error")
		panic(signErr)
	}
	// get raw TX
	txdata, txerr := rlp.EncodeToBytes(sigTx)
	if txerr != nil {
		panic(txerr)
	}
	rawTX := common.ToHex(txdata)
	fmt.Printf("\nSignTx:\nChainId\t\t=%s\nGas\t\t=%d\nGasPrice\t=%s\nNonce\t\t=%d\nToAddr\t\t=%s\nHash\t\t=%s\nData\t\t=%s\n",
		sigTx.ChainId(), sigTx.Gas(), sigTx.GasPrice(), sigTx.Nonce(), sigTx.To().String(), sigTx.Hash().Hex(), sigTx.Data())
	fmt.Printf("RawTransaction = %+v\n", rawTX)
	return rawTX, nil
}

type response struct {
	Status string      `json:"Status"`
	Tip    string      `json:"Tip"`
	Error  string      `json:"Error"`
	Data   interface{} `json:"Data"`
}
type dataResult struct {
	Result string `json:"result"`
}
type dataEnode struct {
	Enode string `json:"Enode"`
}
type groupInfo struct {
	Gid    string      `json:"Gid"`
	Mode   string      `json:"Mode"`
	Count  int         `json:"Count"`
	Enodes interface{} `json:"Enodes"`
}
type reqAddrData struct {
	TxType    string `json:"TxType"`
	Account string `json:"Account"`
       Nonce string `json:"Nonce"`
	Keytype   string `json:"Keytype"`
	GroupID   string `json:"GroupId"`
	ThresHold string `json:"ThresHold"`
	Mode      string `json:"Mode"`
	AcceptTimeOut  string `json:"AcceptTimeOut"` //unit: second
	TimeStamp string `json:"TimeStamp"`
	Sigs      string `json:"Sigs"`
}
type acceptData struct {
	TxType    string `json:"TxType"`
	Account string `json:"Account"`
       Nonce string `json:"Nonce"`
	Key       string `json:"Key"`
	Accept    string `json:"Accept"`
	TimeStamp string `json:"TimeStamp"`
}
type acceptSignData struct {
	TxType     string   `json:"TxType"`
	Account string `json:"Account"`
       Nonce string `json:"Nonce"`
	Key        string   `json:"Key"`
	Accept     string   `json:"Accept"`
	MsgHash    []string `json:"MsgHash"`
	MsgContext []string `json:"MsgContext"`
	TimeStamp  string   `json:"TimeStamp"`
}
type lockoutData struct {
	TxType    string `json:"TxType"`
	SmpcAddr  string `json:"SmpcAddr"`
	SmpcTo    string `json:"SmpcTo"`
	Value     string `json:"Value"`
	Cointype  string `json:"Cointype"`
	GroupID   string `json:"GroupId"`
	ThresHold string `json:"ThresHold"`
	Mode      string `json:"Mode"`
	TimeStamp string `json:"TimeStamp"`
	Memo      string `json:"Memo"`
}
type signData struct {
	TxType     string   `json:"TxType"`
	Account string `json:"Account"`
       Nonce string `json:"Nonce"`
	PubKey     string   `json:"PubKey"`
	InputCode  string   `json:"InputCode"`
	MsgContext []string `json:"MsgContext"`
	MsgHash    []string `json:"MsgHash"`
	Keytype    string   `json:"Keytype"`
	GroupID    string   `json:"GroupId"`
	ThresHold  string   `json:"ThresHold"`
	Mode       string   `json:"Mode"`
	AcceptTimeOut  string `json:"AcceptTimeOut"` //unit: second
	TimeStamp  string   `json:"TimeStamp"`
}
type preSignData struct {
	TxType string   `json:"TxType"`
	Account string `json:"Account"`
       Nonce string `json:"Nonce"`
	PubKey string   `json:"PubKey"`
	SubGid []string `json:"SubGid"`
	KeyType string   `json:"KeyType"`
}
type reshareData struct {
	TxType    string `json:"TxType"`
       Nonce string `json:"Nonce"`
	PubKey    string `json:"PubKey"`
	GroupID   string `json:"GroupId"`
	TSGroupID string `json:"TSGroupId"`
	ThresHold string `json:"ThresHold"`
	Account   string `json:"Account"`
	Mode      string `json:"Mode"`
	AcceptTimeOut  string `json:"AcceptTimeOut"` //unit: second
	Sigs      string `json:"Sigs"`
	TimeStamp string `json:"TimeStamp"`
	KeyType    string `json:"KeyType"`
}
type reqAddrStatus struct {
	Status    string      `json:"Status"`
	PubKey    string      `json:"PubKey"`
	Tip       string      `json:"Tip"`
	Error     string      `json:"Error"`
	AllReply  interface{} `json:"AllReply"`
	TimeStamp string      `json:"TimeStamp"`
}
type lockoutStatus struct {
	Status    string      `json:"Status"`
	OutTxHash string      `json:"OutTxHash"`
	Tip       string      `json:"Tip"`
	Error     string      `json:"Error"`
	AllReply  interface{} `json:"AllReply"`
	TimeStamp string      `json:"TimeStamp"`
}
type signStatus struct {
	Status    string      `json:"Status"`
	Rsv       []string    `json:"Rsv"`
	Tip       string      `json:"Tip"`
	Error     string      `json:"Error"`
	AllReply  interface{} `json:"AllReply"`
	TimeStamp string      `json:"TimeStamp"`
}
type reqAddrCurNodeInfo struct {
	Account   string `json:"Account"`
	Cointype  string `json:"Cointype"`
	GroupID   string `json:"GroupId"`
	Key       string `json:"Key"`
	Mode      string `json:"Mode"`
	Nonce     string `json:"Nonce"`
	ThresHold string `json:"ThresHold"`
	TimeStamp string `json:"TimeStamp"`
}
type lockoutCurNodeInfo struct {
	Account   string `json:"Account"`
	GroupID   string `json:"GroupId"`
	Key       string `json:"Key"`
	Nonce     string `json:"Nonce"`
	Mode      string `json:"Mode"`
	SmpcFrom  string `json:"SmpcFrom"`
	SmpcTo    string `json:"SmpcTo"`
	Value     string `json:"Value"`
	CoinType  string `json:"CoinType"`
	ThresHold string `json:"ThresHold"`
	TimeStamp string `json:"TimeStamp"`
}
type signCurNodeInfo struct {
	Account    string   `json:"Account"`
	GroupID    string   `json:"GroupId"`
	Key        string   `json:"Key"`
	KeyType    string   `json:"KeyType"`
	Mode       string   `json:"Mode"`
	MsgContext []string `json:"MsgContext"`
	MsgHash    []string `json:"MsgHash"`
	Nonce      string   `json:"Nonce"`
	PubKey     string   `json:"PubKey"`
	ThresHold  string   `json:"ThresHold"`
	TimeStamp  string   `json:"TimeStamp"`
}
type reshareCurNodeInfo struct {
	Key       string `json:"Key"`
	PubKey    string `json:"PubKey"`
	GroupID   string `json:"GroupId"`
	TSGroupID string `json:"TSGroupId"`
	ThresHold string `json:"ThresHold"`
	Account   string `json:"Account"`
	Mode      string `json:"Mode"`
	TimeStamp string `json:"TimeStamp"`
}

// Value set args to start
type Value interface {
	String() string
	Set(string) error
}
type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprint(*i)
}
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

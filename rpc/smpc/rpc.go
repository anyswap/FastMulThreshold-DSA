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

// Package smpc Gsmpc rpc interface
package smpc

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/rpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
)

func listenSignal(exit chan int) {
	sig := make(chan os.Signal)
	signal.Notify(sig)

	for {
		<-sig
		exit <- 1
	}
}

// Service RPC service,include interface
type Service struct{}

// CallPeer  
func (service *Service) CallPeer(msg string,enode string) map[string]interface{} {

	common.Debug("===============CallPeer================", "msg", msg,"enode",enode)
	data := make(map[string]interface{})
	smpc.Call(msg,enode)
	data["result"] = "Done" 
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// ReqSmpcAddr this will be called by smpc_reqSmpcAddr
// raw: tx raw data
//return pubkey and coins addr
func (service *Service) ReqSmpcAddr(raw string) map[string]interface{} { //函数名首字母必须大写
	common.Debug("===============ReqSmpcAddr================", "raw", raw)

	data := make(map[string]interface{})
	if raw == "" {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    "parameter error",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := smpc.ReqKeyGen(raw)
	common.Debug("=================ReqSmpcAddr,get result.==================", "ret", ret, "tip", tip, "err", err, "raw", raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// AcceptReqAddr  Agree to generate pubkey 
//  Raw is a special signed transaction that agrees to reqaddr. The data format is:
// {
// "TxType":"ACCEPTREQADDR",
// "Key":"XXX",
// "Accept":"XXX",
// "TimeStamp":"XXX"
// }
func (service *Service) AcceptReqAddr(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc AcceptReqAddr from web,raw = %v==========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	ret, tip, err := smpc.RPCAcceptReqAddr(raw)
	//common.Info("========================AcceptReqAddr,get result======================","ret",ret,"tip",tip,"err",err,"raw",raw)
	//fmt.Printf("%v ==========call rpc AcceptReqAddr from web,ret = %v,tip = %v,err = %v,raw = %v==========\n", common.CurrentTime(), ret, tip, err, raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetReqAddrNonce  Get the nonce value of the special transaction generating pubkey 
func (service *Service) GetReqAddrNonce(account string) map[string]interface{} {
	//fmt.Println("%v =========call rpc.GetReqAddrNonce from web,account = %v =================", common.CurrentTime(), account)

	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := smpc.GetReqAddrNonce(account)
	//fmt.Println("%v =========call rpc.GetReqAddrNonce finish,account = %v,ret = %v,tip = %v,err = %v =================", common.CurrentTime(), account, ret, tip, err)

	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetCurNodeReqAddrInfo  Get the list of generating pubkey command data currently to be approved 
func (service *Service) GetCurNodeReqAddrInfo(account string) map[string]interface{} {
	common.Debug("==================GetCurNodeReqAddrInfo====================", "account", account)

	s, tip, err := smpc.GetCurNodeReqAddrInfo(account)
	common.Debug("==================GetCurNodeReqAddrInfo====================", "account", account, "ret", s, "err", err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

// GetReqAddrStatus  Get the result of generating pubkey
// key:  This generates the unique identification value of the pubkey command 
func (service *Service) GetReqAddrStatus(key string) map[string]interface{} {
	common.Debug("==================GetReqAddrStatus====================", "key", key)

	data := make(map[string]interface{})
	ret, tip, err := smpc.GetReqAddrStatus(key)
	common.Debug("==================GetReqAddrStatus====================", "key", key, "ret", ret, "err", err)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// AcceptSign  Agree to sign
// Raw is a special transaction agreed to sign after signing. The data format is:
// {
// "TxType":"ACCEPTSIGN",
// "Key":"XXX",
// "Accept":"XXX",
// "TimeStamp":"XXX"
// }
func (service *Service) AcceptSign(raw string) map[string]interface{} {

	data := make(map[string]interface{})
	ret, tip, err := smpc.RPCAcceptSign(raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// Sign  Execute the sign command 
// Raw is a special signed transaction. The nonce of the transaction is through DCRM_ Getsignnonce function. The data format is:
// {
// "TxType":"SIGN",
// "PubKey":"XXX",
// "MsgHash":"XXX",
// "MsgContext":"XXX",
// "Keytype":"XXX",
// "GroupId":"XXX",
// "ThresHold":"XXX",
// "Mode":"XXX",
// "TimeStamp":"XXX"
// }
func (service *Service) Sign(raw string) map[string]interface{} {
	common.Info("===================Sign=====================", "raw", raw)

	data := make(map[string]interface{})
	key, tip, err := smpc.Sign(raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = key
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetSignNonce  Get the nonce value of the special transaction of the sign command 
func (service *Service) GetSignNonce(account string) map[string]interface{} {
	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := smpc.GetSignNonce(account)
	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetCurNodeSignInfo Get the list of sign command data currently to be approved
func (service *Service) GetCurNodeSignInfo(account string) map[string]interface{} {
	common.Debug("==================GetCurNodeSignInfo====================", "account", account)

	s, tip, err := smpc.GetCurNodeSignInfo(account)
	common.Debug("==================GetCurNodeSignInfo====================", "account", account, "ret", s, "err", err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

// GetSignStatus  Get the result of sign command
// key:  This generates the unique identification value of the sign command
func (service *Service) GetSignStatus(key string) map[string]interface{} {
	common.Debug("==================GetSignStatus====================", "key", key)
	data := make(map[string]interface{})
	ret, tip, err := smpc.GetSignStatus(key)
	common.Debug("==================GetSignStatus====================", "key", key, "ret", ret, "err", err)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// ReShare do reshare
func (service *Service) ReShare(raw string) map[string]interface{} {
	common.Debug("===================ReShare=====================", "raw", raw)

	data := make(map[string]interface{})
	key, tip, err := smpc.ReShare(raw)
	common.Debug("===================reshare=====================", "key", key, "err", err, "raw", raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = key
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetReShareNonce  Get the nonce value of this resare command special transaction 
func (service *Service) GetReShareNonce(account string) map[string]interface{} {
	data := make(map[string]interface{})
	if account == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := smpc.GetReShareNonce(account)
	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// AcceptReShare Agree to reshare
func (service *Service) AcceptReShare(raw string) map[string]interface{} {
	//fmt.Printf("%v ==========call rpc AcceptReShare from web,raw = %v==========\n", common.CurrentTime(), raw)

	data := make(map[string]interface{})
	ret, tip, err := smpc.RPCAcceptReShare(raw)
	//fmt.Printf("%v ==========call rpc AcceptReShare from web,ret = %v,tip = %v,err = %v,raw = %v==========\n", common.CurrentTime(), ret, tip, err, raw)
	if err != nil {
		data["result"] = "Failure"
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetCurNodeReShareInfo  Get the Reshare command approval list 
func (service *Service) GetCurNodeReShareInfo() map[string]interface{} {
	s, tip, err := smpc.GetCurNodeReShareInfo()
	//fmt.Printf("%v ==============finish call rpc GetCurNodeReShareInfo ,ret = %v,err = %v ================\n", common.CurrentTime(), s, err)
	if err != nil {
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   "",
		}
	}

	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   s,
	}
}

// GetReShareStatus  Get the result of the Reshare command  
func (service *Service) GetReShareStatus(key string) map[string]interface{} {
	data := make(map[string]interface{})
	ret, tip, err := smpc.GetReShareStatus(key)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// PreGenSignData  Generate the relevant data required by the sign command in advance 
// raw tx:
// data = pubkey + subgids
func (service *Service) PreGenSignData(raw string) map[string]interface{} {
	common.Info("===================PreGenSignData=====================", "raw", raw)

	data := make(map[string]interface{})
	tip, err := smpc.PreGenSignData(raw)
	//common.Info("===================Sign,get result=====================","key",key,"err",err,"raw",raw)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = "generating pre-sign data ..."
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetBip32ChildKey  The return value is the sub public key of the X1 / x2 /... / xn sub node of the root node's total public key pubkey.
// Rootpubkey is the total public key pubkey of the root node
// The inputcode format is "m / X1 / x2 /... / xn", where x1,..., xn is the index number of the child node of each level, which is in decimal format, for example: "m / 1234567890123456789012345678901234567890123456789012323455678901234"
// inputcode = "m/x1/x2/..../xn"
func (service *Service) GetBip32ChildKey(rootpubkey string, inputcode string) map[string]interface{} {
	data := make(map[string]interface{})
	pub, tip, err := smpc.GetBip32ChildKey(rootpubkey, inputcode)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = pub
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetAccounts get all pubkey by accout and mode
// gid = "",get all pubkey of all gid
// gid != "",get all pubkey by gid
func (service *Service) GetAccounts(account, mode string) map[string]interface{} {
	data := make(map[string]interface{})
	ret, tip, err := smpc.GetAccounts(account, mode)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetAccountsBalance get all accout balances by pubkey
func (service *Service) GetAccountsBalance(pubkey string, account string) map[string]interface{} {
	fmt.Printf("%v ==========call rpc GetAccountsBalance from web, account = %v, pubkey = %v,=============\n", common.CurrentTime(), account, pubkey)
	data := make(map[string]interface{})
	if pubkey == "" {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    "param is empty",
			"Error":  "param is empty",
			"Data":   data,
		}
	}

	ret, tip, err := smpc.GetAccountsBalance(pubkey, account)
	fmt.Printf("%v ==========finish call rpc GetAccountsBalance from web, ret = %v,err = %v,account = %v, pubkey = %v,=============\n", common.CurrentTime(), ret, err, account, pubkey)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetBalance get account balance
func (service *Service) GetBalance(account string, cointype string, smpcaddr string) map[string]interface{} {

	data := make(map[string]interface{})
	if account == "" || cointype == "" || smpcaddr == "" {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    "parameter error,but return 0",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	ret, tip, err := smpc.GetBalance(account, cointype, smpcaddr)

	if err != nil {
		data["result"] = "0"
		return map[string]interface{}{
			"Status": "Success",
			"Tip":    tip + ",but return 0",
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

// GetSmpcAddr get smpc addrs by pubkey
func (service *Service) GetSmpcAddr(pubkey string) map[string]interface{} {
	data := make(map[string]interface{})
	ret, tip, err := smpc.GetSmpcAddr(pubkey)
	if err != nil {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    tip,
			"Error":  err.Error(),
			"Data":   data,
		}
	}

	data["result"] = ret
	return map[string]interface{}{
		"Status": "Success",
		"Tip":    "",
		"Error":  "",
		"Data":   data,
	}
}

var (
	rpcport  int
	endpoint string = "0.0.0.0"
	server   *rpc.Server
	err      error
)

// RPCInit rpc start init
func RPCInit(port int) {
	rpcport = port
	go func() {
	    err := startRPCServer()
	    if err != nil {
		return
	    }
	}()
}

// splitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func splitAndTrim(input string) []string {
	result := strings.Split(input, ",")
	for i, r := range result {
		result[i] = strings.TrimSpace(r)
	}
	return result
}

func startRPCServer() error {
	go func() {
		server = rpc.NewServer()
		service := new(Service)
		if err := server.RegisterName("smpc", service); err != nil {
			panic(err)
		}

		// All APIs registered, start the HTTP listener
		var (
			listener net.Listener
			err      error
		)

		endpoint = endpoint + ":" + strconv.Itoa(rpcport)
		if listener, err = net.Listen("tcp", endpoint); err != nil {
			panic(err)
		}

		/////////
		/*
			    var (
				    extapiURL = "n/a"
				    ipcapiURL = "n/a"
			    )
			    rpcAPI := []rpc.API{
				    {
					    Namespace: "account",
					    Public:    true,
					    Service:   api,
					    Version:   "1.0"},
			    }
			    if c.Bool(utils.RPCEnabledFlag.Name) {

				    vhosts := splitAndTrim(c.GlobalString(utils.RPCVirtualHostsFlag.Name))
				    cors := splitAndTrim(c.GlobalString(utils.RPCCORSDomainFlag.Name))

				    // start http server
				    httpEndpoint := fmt.Sprintf("%s:%d", c.String(utils.RPCListenAddrFlag.Name), c.Int(rpcPortFlag.Name))
				    listener, _, err := rpc.StartHTTPEndpoint(httpEndpoint, rpcAPI, []string{"account"}, cors, vhosts, rpc.DefaultHTTPTimeouts)
				    if err != nil {
					    utils.Fatalf("Could not start RPC api: %v", err)
				    }
				    extapiURL = fmt.Sprintf("http://%s", httpEndpoint)
				    log.Info("HTTP endpoint opened", "url", extapiURL)

				    defer func() {
					    listener.Close()
					    log.Info("HTTP endpoint closed", "url", httpEndpoint)
				    }()

			    }
			    if !c.Bool(utils.IPCDisabledFlag.Name) {
				    if c.IsSet(utils.IPCPathFlag.Name) {
					    ipcapiURL = c.String(utils.IPCPathFlag.Name)
				    } else {
					    ipcapiURL = filepath.Join(configDir, "clef.ipc")
				    }

				    listener, _, err := rpc.StartIPCEndpoint(ipcapiURL, rpcAPI)
				    if err != nil {
					    utils.Fatalf("Could not start IPC api: %v", err)
				    }
				    log.Info("IPC endpoint opened", "url", ipcapiURL)
				    defer func() {
					    listener.Close()
					    log.Info("IPC endpoint closed", "url", ipcapiURL)
				    }()

			    }
		*/
		/////////

		vhosts := make([]string, 0)
		cors := splitAndTrim("*")
		go func() {
		    err2 := rpc.NewHTTPServer(cors, vhosts, rpc.DefaultHTTPTimeouts, server).Serve(listener)
		    if err2 != nil {
			log.Error("============== new http server fail ==============","err",err2)
			return
		    }
		}()
		rpcstring := "==================== RPC Service Start! url = " + fmt.Sprintf("http://%s", endpoint) + " ====================="
		log.Info(rpcstring)

		exit := make(chan int)
		<-exit

		server.Stop()
	}()

	return nil
}

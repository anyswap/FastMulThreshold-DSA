/*
 *  Copyright (C) 2021-2022  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2021-2022  haijun.cai@anyswap.exchange
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
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/smpc"
	"encoding/json"
)

// ReqKeyGen this will be called by smpc_reqKeyGen
// msg: a json string,such as :
//{
//"Account":xxx,
//"Nonce":xxx,
//}
//return pubkey and coins addr
func (service *Service) ReqKeyGen(rsv string,msg string) map[string]interface{} {
	common.Debug("===============ReqKeyGen================", "msg",msg)
	
	data := make(map[string]interface{})
	if msg == "" || rsv == "" {
		data["result"] = ""
		return map[string]interface{}{
			"Status": "Error",
			"Tip":    "parameter error",
			"Error":  "parameter error",
			"Data":   data,
		}
	}

	m := &smpc.MsgSig{Rsv: rsv, MsgType: "REQSMPCADDR", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	ret, tip, err := smpc.ReqKeyGen(string(raw))
	common.Debug("=================ReqKeyGen,get result.==================", "ret", ret, "tip", tip, "err", err, "raw", raw)
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

// AcceptKeyGen  Agree to generate pubkey 
// Raw is a special signed transaction that agrees to reqaddr. The data format is:
// {
// "TxType":"ACCEPTREQADDR",
// "Account":"xxx",
// "Nonce":"xxx",
// "Key":"XXX",
// "Accept":"XXX",
// "TimeStamp":"XXX"
// }
func (service *Service) AcceptKeyGen(rsv string,msg string) map[string]interface{} {

	data := make(map[string]interface{})
	m := &smpc.MsgSig{Rsv: rsv, MsgType: "ACCEPTREQADDR", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	ret, tip, err := smpc.RPCAcceptReqAddr(string(raw))
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

// AcceptSigning  Agree to sign
// Raw is a special transaction agreed to sign after signing. The data format is:
// {
// "TxType":"ACCEPTSIGN",
// "Account":"xxx",
// "Nonce":"xxx",
// "Key":"XXX",
// "Accept":"XXX",
// "TimeStamp":"XXX"
// }
func (service *Service) AcceptSigning(rsv string,msg string) map[string]interface{} {

	data := make(map[string]interface{})
	m := &smpc.MsgSig{Rsv: rsv, MsgType: "ACCEPTSIGN", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	ret, tip, err := smpc.RPCAcceptSign(string(raw))
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

// Signing  Execute the sign command 
// Raw is a special signed transaction. The nonce of the transaction is through SMPC_ Getsignnonce function. The data format is:
// {
// "TxType":"SIGN",
// "Account":"xxx",
// "Nonce":"xxx",
// "PubKey":"XXX",
// "MsgHash":"XXX",
// "MsgContext":"XXX",
// "Keytype":"XXX",
// "GroupId":"XXX",
// "ThresHold":"XXX",
// "Mode":"XXX",
// "TimeStamp":"XXX"
// }
func (service *Service) Signing(rsv string,msg string) map[string]interface{} {
	common.Debug("===================Signing=====================", "rsv", rsv,"msg",msg)

	data := make(map[string]interface{})
	m := &smpc.MsgSig{Rsv: rsv, MsgType: "SIGN", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	key, tip, err := smpc.Sign(string(raw))
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

// ReSharing do reshare
func (service *Service) ReSharing(rsv string,msg string) map[string]interface{} {
	common.Debug("===================ReSharing=====================", "rsv", rsv,"msg",msg)

	data := make(map[string]interface{})
	m := &smpc.MsgSig{Rsv: rsv, MsgType: "RESHARE", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	key, tip, err := smpc.ReShare(string(raw))
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

// AcceptReSharing Agree to reshare
func (service *Service) AcceptReSharing(rsv string,msg string) map[string]interface{} {

	data := make(map[string]interface{})
	m := &smpc.MsgSig{Rsv: rsv, MsgType: "ACCEPTRESHARE", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	ret, tip, err := smpc.RPCAcceptReShare(string(raw))
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

// PreSigning  Generate the relevant data required by the sign command in advance 
// data = pubkey + subgids
func (service *Service) PreSigning(rsv string,msg string) map[string]interface{} {
	common.Debug("===================PreSigning=====================", "rsv", rsv,"msg",msg)

	data := make(map[string]interface{})
	m := &smpc.MsgSig{Rsv: rsv, MsgType: "PRESIGNDATA", Msg: msg}
       raw,err := json.Marshal(m)
       if err != nil {
               data["result"] = ""
               return map[string]interface{}{
                       "Status": "Error",
                       "Tip":    "",
                       "Error":  err.Error(),
                       "Data":   data,
               }
       }

	tip, err := smpc.PreGenSignData(string(raw))
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


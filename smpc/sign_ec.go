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
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/signing"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"encoding/hex"
)

//--------------------------------------------ECDSA start----------------------------------------------------------

// SignProcessInboundMessages Analyze the obtained P2P messages and enter next round
func SignProcessInboundMessages(msgprex string, finishChan chan struct{}, wg *sync.WaitGroup, ch chan interface{}) {
	defer wg.Done()
	if msgprex == "" {
	    return
	}

	//log.Info("start sign processing inbound messages")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to sign process inbound messages")}
		ch <- res
		return
	}

	defer log.Info("stop sign processing inbound messages","key",msgprex)
	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)
			if err != nil {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}

			mm := SignGetRealMessage(msgmap)
			if mm == nil {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to sign process inbound messages")}
				ch <- res
				return
			}

			//check sig
			if msgmap["Sig"] == "" {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail")}
				ch <- res
				return
			}

			if msgmap["ENode"] == "" {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail")}
				ch <- res
				return
			}

			sig, err := hex.DecodeString(msgmap["Sig"])
			if err != nil {
			    common.Error("[SIGN] decode msg sig data error","err",err,"key",msgprex)
			    res := RPCSmpcRes{Ret: "", Err: err}
			    ch <- res
			    return
			}
			
			common.Debug("===============sign,check p2p msg===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			if !checkP2pSig(sig,mm,msgmap["ENode"]) {
			    common.Error("===============sign,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
			    ch <- res
			    return
			}
			
			// check fromID
			// w.SmpcFrom is the MPC PubKey
			smpcpks, err := hex.DecodeString(w.SmpcFrom)
			if err != nil {
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return
			}

			exsit, da := GetPubKeyData(smpcpks[:])
			if !exsit || da == nil {
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign get local save data fail")}
			    ch <- res
			    return
			}
			
			pubs, ok := da.(*PubKeyData)
			if !ok || pubs.GroupID == "" {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign get local save data fail")}
				ch <- res
				return
			}

			_,ID := GetNodeUID(msgmap["ENode"], "EC256K1",pubs.GroupID)
			id := fmt.Sprintf("%v", ID)
			uid := hex.EncodeToString([]byte(id))
			if !strings.EqualFold(uid,mm.GetFromID()) {
			    common.Error("===============sign,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"],"err","check from ID fail")
			    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check from ID fail")}
			    ch <- res
			    return
			}
			
			// check whether 'from' is in the group
			succ := false
			_, nodes := GetGroup(w.groupid)
			others := strings.Split(nodes, common.Sep2)
			for _, v := range others {
			    node2 := ParseNode(v) //bug??
			    if strings.EqualFold(node2,msgmap["ENode"]) {
				succ = true
				break
			    }
			}

			if !succ {
				common.Error("===============sign,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
				return
			}
			////

			_, err = w.DNode.Update(mm)
			if err != nil {
				log.Error("========== SignProcessInboundMessages, dnode update fail===========","receiv smpc msg",m,"err",err)
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}
		}
	}
}

// SignGetRealMessage get the message data struct by map. (p2p msg ---> map)
func SignGetRealMessage(msg map[string]string) smpclib.Message {
    	if msg == nil {
	    return nil
	}

	from := msg["FromID"]
	if from == "" {
	    return nil
	}

	var to []string
	v, ok := msg["ToID"]
	if ok && v != "" {
		to = strings.Split(v, ":")
	}

	index, indexerr := strconv.Atoi(msg["FromIndex"])
	if indexerr != nil {
		return nil
	}

	//1 message
	if msg["Type"] == "SignRound1Message" {
	    if msg["C11"] == "" {
		return nil
	    }

		c11, _ := new(big.Int).SetString(msg["C11"], 10)
		if c11 == nil {
		    return nil
		}

		if msg["ComWiC"] == "" {
		    return nil
		}

		wic, _ := new(big.Int).SetString(msg["ComWiC"], 10)
		if wic == nil {
		    return nil
		}

		srm := &signing.SignRound1Message{
			SignRoundMessage: new(signing.SignRoundMessage),
			C11:              c11,
			ComWiC:           wic,
		}
		
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	//2 message
	if msg["Type"] == "SignRound2Message" {
	    if msg["U1u1MtAZK1Proof"] == "" {
		return nil
	    }

		proof := &ec2.MtARangeProof{}
		if err := proof.UnmarshalJSON([]byte(msg["U1u1MtAZK1Proof"])); err == nil {

			srm := &signing.SignRound2Message{
				SignRoundMessage: new(signing.SignRoundMessage),
				U1u1MtAZK1Proof:  proof,
			}
			srm.SetFromID(from)
			srm.SetFromIndex(index)
			srm.ToID = to

			return srm
		}

		return nil
	}

	//3 message
	if msg["Type"] == "SignRound3Message" {
	    if msg["Kc"] == "" {
		return nil
	    }

	    kc, _ := new(big.Int).SetString(msg["Kc"], 10)
	    if kc == nil {
		return nil
	    }

	    if msg["ComWiD"] == "" {
		return nil
	    }

		tmp := strings.Split(msg["ComWiD"], ":")
		dtmp := make([]*big.Int, len(tmp))
		for k, v := range tmp {
			dtmp[k], _ = new(big.Int).SetString(v, 10)
			if dtmp[k] == nil {
			    return nil
			}
		}

	    srm := &signing.SignRound3Message{
		    SignRoundMessage: new(signing.SignRoundMessage),
		    Kc:               kc,
		    ComWiD:dtmp,
	    }
	    srm.SetFromID(from)
	    srm.SetFromIndex(index)
	    srm.ToID = to
	    return srm
	}

	//4 message
	if msg["Type"] == "SignRound4Message" {
	    if msg["U1u1MtAZK2Proof"] == "" {
		return nil
	    }

		proof := &ec2.MtARespZKProof{}
		if err := proof.UnmarshalJSON([]byte(msg["U1u1MtAZK2Proof"])); err == nil {
		    if msg["U1KGamma1Cipher"] == "" {
			return nil
		    }

			cipher, _ := new(big.Int).SetString(msg["U1KGamma1Cipher"], 10)
			if cipher == nil {
			    return nil
			}

			srm := &signing.SignRound4Message{
				SignRoundMessage: new(signing.SignRoundMessage),
				U1KGamma1Cipher:  cipher,
				U1u1MtAZK2Proof:  proof,
			}
			srm.SetFromID(from)
			srm.SetFromIndex(index)
			srm.ToID = to
			return srm
		}

		return nil
	}

	//4-1 message
	if msg["Type"] == "SignRound4Message1" {
	    if msg["U1u1MtAZK3Proof"] == "" {
		return nil
	    }

		proof := &ec2.MtAwcRespZKProof{}
		if err := proof.UnmarshalJSON([]byte(msg["U1u1MtAZK3Proof"])); err == nil {
		    if msg["U1Kw1Cipher"] == "" {
			return nil
		    }

			cipher, _ := new(big.Int).SetString(msg["U1Kw1Cipher"], 10)
			if cipher == nil {
			    return nil
			}

			srm := &signing.SignRound4Message1{
				SignRoundMessage: new(signing.SignRoundMessage),
				U1Kw1Cipher:      cipher,
				U1u1MtAZK3Proof:  proof,
			}
			srm.SetFromID(from)
			srm.SetFromIndex(index)
			srm.ToID = to
			return srm
		}

		return nil
	}

	//5 message
	if msg["Type"] == "SignRound5Message" {
	    if msg["Tpf"] == "" {
		return nil
	    }

		proof := &ec2.TProof{}
		if err := proof.UnmarshalJSON([]byte(msg["Tpf"])); err == nil {
		    if msg["Delta1"] == "" || msg["T1X"] == "" || msg["T1Y"] == "" {
			return nil
		    }

		    delta, _ := new(big.Int).SetString(msg["Delta1"], 10)
		    t1x, _ := new(big.Int).SetString(msg["T1X"], 10)
		    t1y, _ := new(big.Int).SetString(msg["T1Y"], 10)

		    if delta == nil || t1x == nil || t1y == nil {
			return nil
		    }

		    srm := &signing.SignRound5Message{
			    SignRoundMessage: new(signing.SignRoundMessage),
			    Delta1:           delta,
			    T1X:           t1x,
			    T1Y:           t1y,
			    Tpf:	proof,
		    }
		    srm.SetFromID(from)
		    srm.SetFromIndex(index)
		    srm.ToID = to
		    return srm
		}

		return nil
	}

	//6 message
	if msg["Type"] == "SignRound6Message" {
	    if msg["U1GammaZKProof"] == "" {
		return nil
	    }

		proof := &ec2.ZkUProof{}
		if err := proof.UnmarshalJSON([]byte(msg["U1GammaZKProof"])); err == nil {
		    if msg["CommU1D"] == "" {
			return nil
		    }

			tmp := strings.Split(msg["CommU1D"], ":")
			dtmp := make([]*big.Int, len(tmp))
			for k, v := range tmp {
				dtmp[k], _ = new(big.Int).SetString(v, 10)
				if dtmp[k] == nil {
				    return nil
				}
			}

			srm := &signing.SignRound6Message{
				SignRoundMessage: new(signing.SignRoundMessage),
				CommU1D:          dtmp,
				U1GammaZKProof:   proof,
			}
			srm.SetFromID(from)
			srm.SetFromIndex(index)
			srm.ToID = to
			return srm
		}

		return nil
	}

	//7 message
	if msg["Type"] == "SignRound7Message" {
	    if msg["PdlwSlackPf"] == "" {
		return nil
	    }

		proof := &ec2.PDLwSlackProof{}
		if err := proof.UnmarshalJSON([]byte(msg["PdlwSlackPf"])); err == nil {
		    if msg["K1RX"] == "" || msg["K1RY"] == "" {
			return nil
		    }

			k1rx, _ := new(big.Int).SetString(msg["K1RX"], 10)
			k1ry, _ := new(big.Int).SetString(msg["K1RY"], 10)
			if k1rx == nil || k1ry == nil {
			    return nil
			}

			srm := &signing.SignRound7Message{
				SignRoundMessage: new(signing.SignRoundMessage),
				K1RX:          k1rx,
				K1RY:          k1ry,
				PdlwSlackPf:   proof,
			}
			srm.SetFromID(from)
			srm.SetFromIndex(index)
			srm.ToID = to
			return srm
		}

		return nil
	}

	// 8 message
	if msg["Type"] == "SignRound8Message" {
	    if msg["STpf"] == "" {
		return nil
	    }

		proof := &ec2.STProof{}
		if err := proof.UnmarshalJSON([]byte(msg["STpf"])); err == nil {
		    if msg["S1X"] == "" || msg["S1Y"] == "" {
			return nil
		    }

			s1x, _ := new(big.Int).SetString(msg["S1X"], 10)
			s1y, _ := new(big.Int).SetString(msg["S1Y"], 10)
			if s1x == nil || s1y == nil {
			    return nil
			}

			srm := &signing.SignRound8Message{
				SignRoundMessage: new(signing.SignRoundMessage),
				S1X:          s1x,
				S1Y:          s1y,
				STpf:   proof,
			}
			srm.SetFromID(from)
			srm.SetFromIndex(index)
			srm.ToID = to
			return srm
		}

		return nil
	}
	
	// 9 message
	if msg["Type"] == "SignRound9Message" {
	    if msg["Us1"] == "" {
		return nil
	    }

		us1, _ := new(big.Int).SetString(msg["Us1"], 10)
		if us1 == nil {
		    return nil
		}

		srm := &signing.SignRound9Message{
			SignRoundMessage: new(signing.SignRoundMessage),
			Us1:               us1,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	return nil
}

// processSign  Obtain the data to be sent in each round and send it to other nodes until the end of the sign command 
func processSign(msgprex string, msgtoenode map[string]string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan signing.PrePubData) (*signing.PrePubData, error) {
	for {
		select {
		case <-errChan:
			log.Error("=========== processSign,error channel closed fail to start local smpc node=========","key", msgprex)
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * time.Duration(EcSignTimeout)):
			log.Error("========================== processSign,sign timeout=======================","key",msgprex)
			return nil, errors.New("sign timeout")
		case msg := <-outCh:
			err := SignProcessOutCh(msgprex, msgtoenode, msg, "")
			if err != nil {
				log.Error("============================= processSign, sign process outch fail =======================","err",err,"key",msgprex)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			//fmt.Printf("\n=========================sign finished successfully,sig data = %v, key = %v ===========================\n", msg, msgprex)
			return &msg, nil
		}
	}
}

// processSignFinalize  Obtain the data to be sent in each round and send it to other nodes until the end of the sign command 
func processSignFinalize(msgprex string, msgtoenode map[string]string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan *big.Int, gid string) (*big.Int, error) {
	for {
		select {
		case <-errChan:
			log.Error("=========== processSign,error channel closed fail to start local smpc node ============","key", msgprex)
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * time.Duration(EcSignTimeout)):
			log.Error("========================== processSignFinalize,sign timeout =====================","key", msgprex)
			return nil, errors.New("sign timeout")
		case msg := <-outCh:
			err := SignProcessOutCh(msgprex, msgtoenode, msg, gid)
			if err != nil {
				log.Error("================================= processSignFinalize, sign process outch fail ==============================","err",err,"key",msgprex)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			//fmt.Printf("\n=======================sign finished successfully, s = %v, key = %v =======================\n", msg, msgprex)
			return msg, nil
		}
	}
}

//--------------------------------------------------------ECDSA end-------------------------------------------------------

// SignProcessOutCh send message to other node
func SignProcessOutCh(msgprex string, msgtoenode map[string]string, msg smpclib.Message, gid string) error {
	if msg == nil || msgprex == "" || msgtoenode == nil {
		return fmt.Errorf("smpc info error")
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		return fmt.Errorf("get worker fail")
	}

	sig,err := sigP2pMsg(msg,curEnode)
	if err != nil {
	    return err
	}

	msgmap := msg.OutMap()
	msgmap["Key"] = msgprex
	msgmap["ENode"] = curEnode
	msgmap["Sig"] = hex.EncodeToString(sig)
	s, err := json.Marshal(msgmap)
	if err != nil {
		return err
	}

	if gid == "" {
		gid = w.groupid
	}

	if msg.IsBroadcast() {
		SendMsgToSmpcGroup(string(s), gid)
	} else {
		for _, v := range msg.GetToID() {
			enode := msgtoenode[v]
			_, enodes := GetGroup(gid)
			nodes := strings.Split(enodes, common.Sep2)
			for _, node := range nodes {
				node2 := ParseNode(node)
				if strings.EqualFold(enode, node2) {
					SendMsgToPeer(node, string(s))
					break
				}
			}
		}
	}

	return nil
}

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
	"encoding/json"
	"errors"
	"fmt"
	edsigning "github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/signing"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"strconv"
	"strings"
	"sync"
	"time"
)

//--------------------------------------------------------EDDSA start-------------------------------------------------------

// EdSignProcessInboundMessages Analyze the obtained P2P messages and enter next round
func EdSignProcessInboundMessages(msgprex string, finishChan chan struct{}, wg *sync.WaitGroup, ch chan interface{}) {
	defer wg.Done()
	fmt.Printf("start ed sign processing inbound messages\n")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("fail to ed sign process inbound messages")}
		ch <- res
		return
	}

	defer fmt.Printf("stop ed sign processing inbound messages\n")
	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)

			fmt.Printf("=================== EdSignProcessInboundMessages, msg = %v, err = %v, key = %v ====================\n", m, err, msgprex)
			if err != nil {
				res := RpcSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}

			mm := EdSignGetRealMessage(msgmap)
			if mm == nil {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("fail to ed sign process inbound messages")}
				ch <- res
				return
			}

			_, err = w.DNode.Update(mm)
			if err != nil {
				fmt.Printf("========== EdSignProcessInboundMessages, dnode update fail, receiv smpc msg = %v, err = %v, key = %v ============\n", m, err, msgprex)
				res := RpcSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}
		}
	}
}

// EdSignGetRealMessage get the message data struct by map. (p2p msg ---> map)
func EdSignGetRealMessage(msg map[string]string) smpclib.Message {
	from := msg["FromID"]
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
		cr, _ := hex.DecodeString(msg["CR"])
		var CR [32]byte
		copy(CR[:], cr[:])

		srm := &edsigning.SignRound1Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			CR:               CR,
		}

		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	//2 message
	if msg["Type"] == "SignRound2Message" {
		zkr, _ := hex.DecodeString(msg["ZkR"])
		var ZkR [64]byte
		copy(ZkR[:], zkr[:])

		srm := &edsigning.SignRound2Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			ZkR:              ZkR,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//3 message
	if msg["Type"] == "SignRound3Message" {
		dr, _ := hex.DecodeString(msg["DR"])
		var DR [64]byte
		copy(DR[:], dr[:])

		srm := &edsigning.SignRound3Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			DR:               DR,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//4 message
	if msg["Type"] == "SignRound4Message" {
		csb, _ := hex.DecodeString(msg["CSB"])
		var CSB [32]byte
		copy(CSB[:], csb[:])

		srm := &edsigning.SignRound4Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			CSB:              CSB,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//5 message
	if msg["Type"] == "SignRound5Message" {
		dsb, _ := hex.DecodeString(msg["DSB"])
		var DSB [64]byte
		copy(DSB[:], dsb[:])

		srm := &edsigning.SignRound5Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			DSB:              DSB,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//6 message
	if msg["Type"] == "SignRound6Message" {
		s, _ := hex.DecodeString(msg["S"])
		var S [32]byte
		copy(S[:], s[:])

		srm := &edsigning.SignRound6Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			S:                S,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	return nil
}

// processSign_ed  Obtain the data to be sent in each round and send it to other nodes until the end of the sign command 
func processSign_ed(msgprex string, msgtoenode map[string]string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan edsigning.EdSignData) (*edsigning.EdSignData, error) {
	for {
		select {
		case <-errChan:
			fmt.Printf("=========================== processSign_ed,error channel closed fail to start local smpc node, key = %v =====================\n", msgprex)
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * 300):
			fmt.Printf("========================== processSign_ed,sign timeout, key = %v ==========================\n", msgprex)
			return nil, errors.New("ed sign timeout")
		case msg := <-outCh:
			err := SignProcessOutCh(msgprex, msgtoenode, msg, "")
			if err != nil {
				fmt.Printf("======================= processSign_ed, sign process outch err = %v, key = %v ====================\n", err, msgprex)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			//fmt.Printf("\n=======================ed sign finished successfully,sig data = %v, key = %v ======================\n", msg, msgprex)
			return &msg, nil
		}
	}
}

//-------------------------------------------------------EDDSA end---------------------------------------------------

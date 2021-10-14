package smpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/signing"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

//--------------------------------------------ECDSA start----------------------------------------------------------

// SignProcessInboundMessages Analyze the obtained P2P messages and enter next round
func SignProcessInboundMessages(msgprex string, finishChan chan struct{}, wg *sync.WaitGroup, ch chan interface{}) {
	defer wg.Done()
	fmt.Printf("start sign processing inbound messages\n")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("fail to sign process inbound messages")}
		ch <- res
		return
	}

	defer fmt.Printf("stop sign processing inbound messages\n")
	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)
			if err != nil {
				res := RpcSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}

			mm := SignGetRealMessage(msgmap)
			if mm == nil {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("fail to sign process inbound messages")}
				ch <- res
				return
			}

			_, err = w.DNode.Update(mm)
			if err != nil {
				fmt.Printf("========== SignProcessInboundMessages, dnode update fail, receiv smpc msg = %v, err = %v ============\n", m, err)
				res := RpcSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}
		}
	}
}

// SignGetRealMessage get the message data struct by map. (p2p msg ---> map)
func SignGetRealMessage(msg map[string]string) smpclib.Message {
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
		c11, _ := new(big.Int).SetString(msg["C11"], 10)
		srm := &signing.SignRound1Message{
			SignRoundMessage: new(signing.SignRoundMessage),
			C11:              c11,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	//2 message
	if msg["Type"] == "SignRound2Message" {
		proof := &ec2.MtAZK1Proof_nhh{}
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

		kc, _ := new(big.Int).SetString(msg["Kc"], 10)
		srm := &signing.SignRound3Message{
			SignRoundMessage: new(signing.SignRoundMessage),
			Kc:               kc,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	//4 message
	if msg["Type"] == "SignRound4Message" {
		proof := &ec2.MtAZK2Proof_nhh{}
		if err := proof.UnmarshalJSON([]byte(msg["U1u1MtAZK2Proof"])); err == nil {
			cipher, _ := new(big.Int).SetString(msg["U1KGamma1Cipher"], 10)
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
		proof := &ec2.MtAZK3Proof_nhh{}
		if err := proof.UnmarshalJSON([]byte(msg["U1u1MtAZK3Proof"])); err == nil {
			cipher, _ := new(big.Int).SetString(msg["U1Kw1Cipher"], 10)
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
		delta, _ := new(big.Int).SetString(msg["Delta1"], 10)
		srm := &signing.SignRound5Message{
			SignRoundMessage: new(signing.SignRoundMessage),
			Delta1:           delta,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	//6 message
	if msg["Type"] == "SignRound6Message" {
		proof := &ec2.ZkUProof{}
		if err := proof.UnmarshalJSON([]byte(msg["U1GammaZKProof"])); err == nil {
			tmp := strings.Split(msg["CommU1D"], ":")
			dtmp := make([]*big.Int, len(tmp))
			for k, v := range tmp {
				dtmp[k], _ = new(big.Int).SetString(v, 10)
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
		us1, _ := new(big.Int).SetString(msg["Us1"], 10)
		srm := &signing.SignRound7Message{
			SignRoundMessage: new(signing.SignRoundMessage),
			Us1:              us1,
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
			fmt.Printf("=========== processSign,error channel closed fail to start local smpc node, key = %v ===========\n", msgprex)
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * 300):
			fmt.Printf("========================== processSign,sign timeout, key = %v ========================\n", msgprex)
			return nil, errors.New("sign timeout")
		case msg := <-outCh:
			err := SignProcessOutCh(msgprex, msgtoenode, msg, "")
			if err != nil {
				fmt.Printf("============================= processSign, sign process outch err = %v, key = %v =======================\n", err, msgprex)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			fmt.Printf("\n=========================sign finished successfully,sig data = %v, key = %v ===========================\n", msg, msgprex)
			return &msg, nil
		}
	}
}

// processSignFinalize  Obtain the data to be sent in each round and send it to other nodes until the end of the sign command 
func processSignFinalize(msgprex string, msgtoenode map[string]string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan *big.Int, gid string) (*big.Int, error) {
	for {
		select {
		case <-errChan:
			fmt.Printf("=========== processSign,error channel closed fail to start local smpc node, key = %v ===========\n", msgprex)
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * 300):
			fmt.Printf("========================== processSign,sign timeout, key = %v =========================\n", msgprex)
			return nil, errors.New("sign timeout")
		case msg := <-outCh:
			err := SignProcessOutCh(msgprex, msgtoenode, msg, gid)
			if err != nil {
				fmt.Printf("================================= processSign, sign process outch err = %v, key = %v ==========================\n", err, msgprex)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			fmt.Printf("\n=======================sign finished successfully, s = %v, key = %v =======================\n", msg, msgprex)
			return msg, nil
		}
	}
}

//--------------------------------------------------------ECDSA end-------------------------------------------------------

// SignProcessOutCh send message to other node
func SignProcessOutCh(msgprex string, msgtoenode map[string]string, msg smpclib.Message, gid string) error {
	if msg == nil {
		return fmt.Errorf("smpc info error")
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		return fmt.Errorf("get worker fail")
	}

	msgmap := msg.OutMap()
	msgmap["Key"] = msgprex
	msgmap["ENode"] = cur_enode
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

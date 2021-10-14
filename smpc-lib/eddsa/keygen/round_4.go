package keygen

import (
	"errors"
	"encoding/hex"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"crypto/sha512"
)

// Start verify cPk dPk zkPk,calc vss 
func (round *round4) Start() error {
	if round.started {
		return errors.New("ed,round already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIds()
	if err != nil {
		return errors.New("round.Start get ids fail.")
	}

	var PkSet []byte

	for k, id := range ids {
		msg1, ok := round.temp.kgRound1Messages[k].(*KGRound1Message)
		if !ok {
			return errors.New("round.Start get round1 msg fail")
		}

		msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
			return errors.New("round.Start get round3 msg fail")
		}

		CPkFlag := ed.Verify(msg1.CPk, msg3.DPk)
		if !CPkFlag {
			fmt.Printf("Error: Commitment(PK) Not Pass at User: %v, k = %v \n", id, k)
			return errors.New("smpc back-end internal error:commitment check fail in req ed pubkey")
		}

		msg2, ok := round.temp.kgRound2Messages[k].(*KGRound2Message)
		if !ok {
			return errors.New("round.Start get round2 msg fail")
		}

		var t [32]byte
		copy(t[:], msg3.DPk[32:])
		zkPkFlag := ed.Verify_zk(msg2.ZkPk, t)
		if !zkPkFlag {
			fmt.Printf("Error: ZeroKnowledge Proof (Pk) Not Pass at User: %v \n", id)
			return errors.New("smpc back-end internal error:zeroknowledge check fail")
		}

		PkSet = append(PkSet[:], (msg3.DPk[32:])...)
	}

	// 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
	var a [32]byte
	var aDigest [64]byte

	msg3, ok := round.temp.kgRound3Messages[cur_index].(*KGRound3Message)
	if !ok {
		return errors.New("round get msg3 fail")
	}

	h := sha512.New()
	_, err = h.Write(msg3.DPk[32:])
	if err != nil {
		return errors.New("smpc back-end internal error:write dpk fail in calcing SHA256(PkU1, {PkU2, PkU3}")
	}

	_, err = h.Write(PkSet)
	if err != nil {
		return errors.New("smpc back-end internal error:write pkset fail in calcing SHA256(PkU1, {PkU2, PkU3}")
	}

	h.Sum(aDigest[:0])
	ed.ScReduce(&a, &aDigest)

	// 2.6 calculate ask
	var ask [32]byte
	var temSk2 [32]byte
	copy(temSk2[:], round.temp.sk[:32])
	ed.ScMul(&ask, &a, &temSk2)

	// 2.7 calculate vss

	var uids [][32]byte
	for _, v := range ids {
		var tem [32]byte
		tmp := v.Bytes()
		copy(tem[:], tmp[:])
		if len(v.Bytes()) < 32 {
			l := len(v.Bytes())
			for j := l; j < 32; j++ {
				tem[j] = byte(0x00)
			}
		}
		uids = append(uids, tem)
	}
	round.temp.uids = uids

	_, cfsBBytes, shares := ed.Vss(ask, uids, round.threshold, round.dnodecount)
	round.temp.cfsBBytes = cfsBBytes

	for k, id := range ids {
		kg := &KGRound4Message{
			KGRoundMessage: new(KGRoundMessage),
			Share:          shares[k],
		}
		kg.SetFromID(round.dnodeid)
		kg.SetFromIndex(cur_index)

		if k == cur_index {
			round.temp.kgRound4Messages[k] = kg
		} else {

			var tmp [32]byte
			copy(tmp[:], id.Bytes())
			idtmp := hex.EncodeToString(tmp[:])
			kg.AppendToID(idtmp) //id-->dnodeid
			round.out <- kg
		}
	}

	fmt.Printf("========= round4 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round4) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound4Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.kgRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

// NextRound enter next round
func (round *round4) NextRound() smpc.Round {
	round.started = false
	return &round5{round}
}

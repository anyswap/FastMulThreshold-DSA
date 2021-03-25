package signing 

import (
	"errors"
	"fmt"
	//"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"crypto/sha512"
	"encoding/hex"
)

func (round *round4) Start() error {
	if round.started {
	    fmt.Printf("============= ed sign,round4.start fail =======\n")
	    return errors.New("ed sign,round4 already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	cur_index,err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
	    return err
	}

	var FinalR, temR2 ed.ExtendedGroupElement
	var FinalRBytes [32]byte

	for k,_ := range round.idsign {
	    msg1,ok := round.temp.signRound1Messages[k].(*SignRound1Message)
	    if !ok {
		return errors.New("get CR fail.")
	    }
	    
	    msg3,ok := round.temp.signRound3Messages[k].(*SignRound3Message)
	    if !ok {
		return errors.New("get DR fail.")
	    }
	    
	    CRFlag := ed.Verify(msg1.CR,msg3.DR)
	    if !CRFlag {
		    fmt.Printf("Error: Commitment(R) Not Pass at User: %v\n",round.save.CurDNodeID)
		    return errors.New("dcrm back-end internal error:commitment verification fail in ed sign") 
	    }
	    
	    msg2,ok := round.temp.signRound2Messages[k].(*SignRound2Message)
	    if !ok {
		return errors.New("get ZkR fail.")
	    }
	    
	    var temR [32]byte
	    copy(temR[:], msg3.DR[32:])
	    
	    zkRFlag := ed.Verify_zk(msg2.ZkR, temR)
	    if !zkRFlag {
		    fmt.Printf("Error: ZeroKnowledge Proof (R) Not Pass at User: %v\n",round.save.CurDNodeID)
		    return errors.New("dcrm back-end internal error:zeroknowledge verification fail in ed sign")
	    }
	    
	    var temRBytes [32]byte
	    copy(temRBytes[:], msg3.DR[32:])
	    temR2.FromBytes(&temRBytes)
	    if k == 0 {
		    FinalR = temR2
	    } else {
		    ed.GeAdd(&FinalR, &FinalR, &temR2)
	    }
	}
	FinalR.ToBytes(&FinalRBytes)
	round.temp.FinalRBytes = FinalRBytes

	// 2.6 calculate k=H(FinalRBytes||pk||M)
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	_,err = h.Write(FinalRBytes[:])
	if err != nil {
	    return errors.New("dcrm back-end internal error:write final r fail in caling k")
	}

	_,err = h.Write(round.temp.pkfinal[:])
	if err != nil {
	    return errors.New("dcrm back-end internal error:write pk fail in caling k")
	}

	_,err = h.Write(([]byte(round.temp.message))[:])
	if err != nil {
	    return errors.New("dcrm back-end internal error:write message fail in caling k")
	}

	h.Sum(kDigest[:0])
	ed.ScReduce(&k, &kDigest)

	// 2.7 calculate lambda1
	var lambda [32]byte
	lambda[0] = 1
	order := ed.GetBytesOrder()

	var cur_byte [32]byte
	copy(cur_byte[:],round.save.CurDNodeID.Bytes())
	
	for kk, vv := range round.idsign {
		if kk == cur_index {
			continue
		}

		var index_byte [32]byte
		copy(index_byte[:],vv.Bytes())
		
		var time [32]byte
		t := index_byte//round.temp.uids[oldindex]
		tt := cur_byte//round.temp.uids[cur_oldindex]
		ed.ScSub(&time, &t, &tt)
		time = ed.ScModInverse(time, order)
		ed.ScMul(&time, &time, &t)
		ed.ScMul(&lambda, &lambda, &time)
	}

	var s [32]byte
	ed.ScMul(&s, &lambda, &round.temp.tsk)

	stmp := hex.EncodeToString(s[:])
	fmt.Printf("============================== round4.start, stmp = %v ============================\n",stmp)

	ed.ScMul(&s, &s, &k)
	ed.ScAdd(&s, &s, &round.temp.r)

	// 2.9 calculate sBBytes
	var sBBytes [32]byte
	var sB ed.ExtendedGroupElement
	ed.GeScalarMultBase(&sB, &s)
	sB.ToBytes(&sBBytes)

	// 2.10 commit(sBBytes)
	CSB, DSB := ed.Commit(sBBytes)
	round.temp.DSB = DSB
	round.temp.sBBytes = sBBytes
	round.temp.s = s

	srm := &SignRound4Message{
	    SignRoundMessage: new(SignRoundMessage),
	    CSB:CSB,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound4Messages[cur_index] = srm
	round.out <- srm

	return nil
}

func (round *round4) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.signRound4Messages {
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

func (round *round4) NextRound() dcrm.Round {
    //fmt.Printf("========= round.next round ========\n")
    round.started = false
    return &round5{round}
}


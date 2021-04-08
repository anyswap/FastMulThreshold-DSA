package keygen

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"crypto/sha512"
	"bytes"
)

func (round *round6) Start() error {
	if round.started {
		return errors.New("ed,round already started")
	}
	round.number = 6
	round.started = true
	round.resetOK()

	cur_index,err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
	    return err
	}

	ids,err := round.GetIds()
	if err != nil {
	    return errors.New("round.Start get ids fail.")
	}

	//get cur id
	/*var cur_id [32]byte
	for k,id := range ids {
	    fmt.Printf("==================round6.start, id = %v,id len = %v, k = %v,cur_index = %v ==================\n",id,len(id.Bytes()),k,cur_index)
	    if k == cur_index {
		copy(cur_id[:],id.Bytes())
		break
	    }
	}*/
	//

	var PkSet2 []byte
	for k,id := range ids {
	    msg4,ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	    if !ok {
		return errors.New("ed,round.Start get round4 msg fail")
	    }
	   
	    msg5,ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
	    if !ok {
		return errors.New("ed,round.Start get round5 msg fail")
	    }
	   
	    msg3,ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
	    if !ok {
		return errors.New("ed,round.Start get round3 msg fail")
	    }
	  
	    //fmt.Printf("=====================round6.start,check vss, share = %v, id = %v,index = %v,uids[] = %v, cfsbtyes = %v,k = %v ============\n",msg4.Share,id,cur_index,round.temp.uids[cur_index],msg5.CfsBBytes,k)

	    shareUFlag := ed.Verify_vss(msg4.Share,round.temp.uids[cur_index],msg5.CfsBBytes)
	    if !shareUFlag {
		    fmt.Printf("Error: VSS Share Verification Not Pass at User: %v, k  = %v \n", id,k)
		    return errors.New("smpc back-end internal error:VSS Share verification fail")
	    }
	    
	    var temPk [32]byte
	    t := msg3.DPk[:] 
	    copy(temPk[:], t[32:])
	    PkSet2 = append(PkSet2[:], (temPk[:])...)
	}

	//fmt.Printf("===============================round6.start,check vss share success ===============================\n")
	   
	// 3.2 verify share2
	var a2 [32]byte
	var aDigest2 [64]byte

	// 3.3 calculate tSk
	var tSk [32]byte
	
	h := sha512.New()
	for k, id := range ids {
		msg3,ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
		    return errors.New("ed,round.Start get round3 msg fail")
		}
	   
		var temPk [32]byte
		t := msg3.DPk[:] 
		copy(temPk[:], t[32:])

		h.Reset()
		_,err = h.Write(temPk[:])
		if err != nil {
		    return err
		}
		_,err = h.Write(PkSet2)
		if err != nil {
		    return err
		}
		h.Sum(aDigest2[:0])
		ed.ScReduce(&a2, &aDigest2)

		var askB, A ed.ExtendedGroupElement
		A.FromBytes(&temPk)
		ed.GeScalarMult(&askB, &a2, &A)

		var askBBytes [32]byte
		askB.ToBytes(&askBBytes)

		msg5,ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
		if !ok {
		    return errors.New("ed,round.Start get round5 msg fail")
		}
	       
		t2 := msg5.CfsBBytes
		tt := t2[0]
		if !bytes.Equal(askBBytes[:], tt[:]) {
			fmt.Printf("Error: VSS Coefficient Verification Not Pass at User: %v \n", id)
			return errors.New("smpc back-end internal error:VSS Coefficient verification fail")
		}
		
		msg4,ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
		if !ok {
		    return errors.New("ed,round.Start get round4 msg fail")
		}
	       
		t3 := msg4.Share 
		ed.ScAdd(&tSk, &tSk, &t3)
	}

	// 3.4 calculate pk
	var finalPk ed.ExtendedGroupElement
	var finalPkBytes [32]byte

	i := 0
	for k, _ := range ids {
		msg3,ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
		    return errors.New("ed,round.Start get round3 msg fail")
		}
	   
		var temPk [32]byte
		t := msg3.DPk[:] 
		copy(temPk[:], t[32:])

		h.Reset()
		_,err = h.Write(temPk[:])
		if err != nil {
		    return err 
		}
		
		_,err = h.Write(PkSet2)
		if err != nil {
		    return err 
		}

		h.Sum(aDigest2[:0])
		ed.ScReduce(&a2, &aDigest2)

		var askB, A ed.ExtendedGroupElement
		A.FromBytes(&temPk)
		ed.GeScalarMult(&askB, &a2, &A)

		if i == 0 {
			finalPk = askB
		} else {
			ed.GeAdd(&finalPk, &finalPk, &askB)
		}

		i++
	}

	finalPk.ToBytes(&finalPkBytes)
	
	round.Save.TSk = tSk
	round.Save.FinalPkBytes = finalPkBytes

	//fmt.Printf("===============round6.start, save.Sk = %v,save.Pk = %v,save.TSk = %v,save.FinalPkBytes = %v, save.Ids = %v, save.CurDNodeID = %v =================\n",hex.EncodeToString(round.Save.Sk[:]),hex.EncodeToString(round.Save.Pk[:]),hex.EncodeToString(round.Save.TSk[:]),hex.EncodeToString(round.Save.FinalPkBytes[:]),round.Save.Ids,round.Save.CurDNodeID)

	round.end <- *round.Save
	
	pub := hex.EncodeToString(finalPkBytes[:])
	fmt.Printf("========= round6 start success, pubkey = %v ==========\n",pub)
	return nil
}

func (round *round6) CanAccept(msg smpc.Message) bool {
	return false
}

func (round *round6) Update() (bool, error) {
	return false, nil
}

func (round *round6) NextRound() smpc.Round {
	return nil
}


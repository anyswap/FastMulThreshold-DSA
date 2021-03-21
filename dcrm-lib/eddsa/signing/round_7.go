package signing 

import (
	"errors"
	"fmt"
	//"math/big"
	"encoding/hex"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
	"github.com/agl/ed25519"
)

func (round *round7) Start() error {
	if round.started {
	    fmt.Printf("============= ed sign,round7.start fail =======\n")
	    return errors.New("ed sign,round already started")
	}
	round.number = 7
	round.started = true
	round.resetOK()

	var FinalS [32]byte
	for k, _ := range round.idsign {
	    msg6,ok := round.temp.signRound6Messages[k].(*SignRound6Message)
	    if !ok {
		return errors.New("get S fail.")
	    }
	   
	    var t [32]byte
	    copy(t[:],msg6.S[:])
	    ed.ScAdd(&FinalS, &FinalS, &t)
	}

	inputVerify := InputVerify{FinalR: round.temp.FinalRBytes, FinalS: FinalS, Message: []byte(round.temp.message), FinalPk: round.temp.pkfinal}

	var pass = EdVerify(inputVerify)
	fmt.Printf("===========ed verify, pass = %v============\n",pass)

	//r
	rx := hex.EncodeToString(round.temp.FinalRBytes[:])
	sx := hex.EncodeToString(FinalS[:])
	fmt.Printf("===========ed sign, round7.start, rx = %v, sx = %v============\n",rx,sx)

	//////test
	signature := new([64]byte)
	copy(signature[:], round.temp.FinalRBytes[:])
	copy(signature[32:], FinalS[:])
	suss := ed25519.Verify(&round.temp.pkfinal, []byte(round.temp.message), signature)
	fmt.Printf("===========ed verify, success = %v============\n",suss)

	round.end <- EdSignData{Rx:rx,Sx:sx}

	fmt.Printf("============= round7.start success, current node id = %v =============\n",round.kgid)

	return nil
}

func (round *round7) CanAccept(msg dcrm.Message) bool {
	return false
}

func (round *round7) Update() (bool, error) {
	return false, nil
}

func (round *round7) NextRound() dcrm.Round {
    return nil 
}


package signing 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
)

func (round *round7) Start() error {
	if round.started {
	    fmt.Printf("============= round7.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 7
	round.started = true
	round.resetOK()

	var GammaGSumx *big.Int
	var GammaGSumy *big.Int
	for k,_ := range round.idsign {
	    msg1,_ := round.temp.signRound1Messages[k].(*dcrm.SignRound1Message)
	    msg6,_ := round.temp.signRound6Messages[k].(*dcrm.SignRound6Message)
	    deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
	    if !deCommit.Verify() {
		return errors.New("verify commit fail.")
	    }

	    _, u1GammaG := deCommit.DeCommit()
	    if !ec2.ZkUVerify(u1GammaG,msg6.U1GammaZKProof) {
		return errors.New("verify zkuproof fail.")
	    }

	    if k == 0 {
		GammaGSumx = u1GammaG[0]
		GammaGSumy = u1GammaG[1]
	    }
	}

	for k,_ := range round.idsign {
	    if k == 0 {
		continue
	    }

	    msg1,_ := round.temp.signRound1Messages[k].(*dcrm.SignRound1Message)
	    msg6,_ := round.temp.signRound6Messages[k].(*dcrm.SignRound6Message)
	    deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
	    _, u1GammaG := deCommit.DeCommit()
	    GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, u1GammaG[0], u1GammaG[1])
	}
	deltaSumInverse := new(big.Int).ModInverse(round.temp.deltaSum, secp256k1.S256().N)
	deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

	// 4. get r = deltaGammaGx
	r := deltaGammaGx
	zero, _ := new(big.Int).SetString("0", 10)
	if r.Cmp(zero) == 0 {
	    return errors.New("r == 0.")
	}

	if r == nil || deltaGammaGy == nil {
	    return errors.New("calc r fail.")
	}

	round.end <- dcrm.PrePubData{K1:round.temp.u1K,R:r,Ry:deltaGammaGy,Sigma1:round.temp.sigma1}

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


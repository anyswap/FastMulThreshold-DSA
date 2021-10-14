package signing

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

// Start verify commitment,zkuproof,calc R
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
	for k := range round.idsign {
		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
		deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
		if !deCommit.Verify() {
			return errors.New("verify commit fail.")
		}

		_, u1GammaG := deCommit.DeCommit()
		if !ec2.ZkUVerify(u1GammaG, msg6.U1GammaZKProof) {
			return errors.New("verify zkuproof fail.")
		}

		if k == 0 {
			GammaGSumx = u1GammaG[0]
			GammaGSumy = u1GammaG[1]
		}
	}

	for k := range round.idsign {
		if k == 0 {
			continue
		}

		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
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

	round.end <- PrePubData{K1: round.temp.u1K, R: r, Ry: deltaGammaGy, Sigma1: round.temp.sigma1}

	fmt.Printf("============= round7.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept end pre-sign 
func (round *round7) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end pre-sign
func (round *round7) Update() (bool, error) {
	return false, nil
}

// NextRound end pre-sign
func (round *round7) NextRound() smpc.Round {
	return nil
}

package signing

import (
	"errors"
	"fmt"
	"encoding/hex"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/agl/ed25519"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
)

// Start calc S and check (R,S)
func (round *round7) Start() error {
	if round.started {
		fmt.Printf("============= ed sign,round7.start fail =======\n")
		return errors.New("ed sign,round already started")
	}
	round.number = 7
	round.started = true
	round.resetOK()

	var FinalS [32]byte
	for k := range round.idsign {
		msg6, ok := round.temp.signRound6Messages[k].(*SignRound6Message)
		if !ok {
			return errors.New("get S fail.")
		}

		var t [32]byte
		copy(t[:], msg6.S[:])
		ed.ScAdd(&FinalS, &FinalS, &t)
	}

	inputVerify := InputVerify{FinalR: round.temp.FinalRBytes, FinalS: FinalS, Message: []byte(round.temp.message), FinalPk: round.temp.pkfinal}

	var pass = EdVerify(inputVerify)
	fmt.Printf("===========ed verify, pass = %v============\n", pass)

	//r
	rx := hex.EncodeToString(round.temp.FinalRBytes[:])
	sx := hex.EncodeToString(FinalS[:])
	fmt.Printf("===========ed sign, round7.start, rx = %v, sx = %v============\n", rx, sx)

	//////test
	signature := new([64]byte)
	copy(signature[:], round.temp.FinalRBytes[:])
	copy(signature[32:], FinalS[:])

	fmt.Printf("================= ed sign 25519,sig = %v, pk = %v, msg = %v, sig str = %v, pk str = %v, msg str = %v =======================\n", signature, round.temp.pkfinal, round.temp.message, hex.EncodeToString(signature[:]), hex.EncodeToString(round.temp.pkfinal[:]), hex.EncodeToString(round.temp.message[:]))
	suss := ed25519.Verify(&round.temp.pkfinal, []byte(round.temp.message), signature)
	fmt.Printf("===========ed verify, success = %v============\n", suss)

	/////////solana
	/*suss = edlib.Verify(round.temp.pkfinal[:],round.temp.message,signature[:])
	fmt.Printf("===========ed lib verify, success = %v============\n",suss)

	suss = Verify(round.temp.pkfinal[:],round.temp.message,signature[:])
	fmt.Printf("===========ed lib at local verify, success = %v============\n",suss)*/
	/////////solana

	round.end <- EdSignData{Rx: round.temp.FinalRBytes, Sx: FinalS}

	fmt.Printf("============= round7.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept end signing 
func (round *round7) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end signing
func (round *round7) Update() (bool, error) {
	return false, nil
}

// NextRound end signing
func (round *round7) NextRound() smpc.Round {
	return nil
}

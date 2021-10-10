package keygen

import (
	"errors"
	"fmt"
	//"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"io"
	//"crypto/ed25519/internal/edwards25519"
)

func (round *round1) Start() error {
	if round.started {
		fmt.Printf("============ round1 start error,already started============\n")
		return errors.New("round already started")
	}
	round.number = 1
	round.started = true
	round.resetOK()

	rand := cryptorand.Reader
	var seed [32]byte

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, seed)")
		return err
	}

	// 1.2 privateKey' = SHA512(seed)

	var sk [64]byte
	var pk [32]byte

	seedDigest := sha512.Sum512(seed[:])

	seedDigest[0] &= 248
	seedDigest[31] &= 127
	//seedDigest[31] &= 63
	seedDigest[31] |= 64

	copy(sk[:], seedDigest[:])

	// 1.3 publicKey
	var temSk [32]byte
	copy(temSk[:], sk[:32])

	var A ed.ExtendedGroupElement
	ed.GeScalarMultBase(&A, &temSk)

	A.ToBytes(&pk)
	///////////////////solana
	/*var sk [64]byte
	var pk [32]byte

	seedDigest := sha512.Sum512(seed[:])

	seedDigest[0] &= 248
	seedDigest[31] &= 127
	seedDigest[31] |= 64

	var A ed.ExtendedGroupElement
	var temSk [32]byte
	copy(temSk[:], seedDigest[:])
	ed.GeScalarMultBase(&A, &temSk)
	A.ToBytes(&pk)

	copy(sk[:], seed[:])
	copy(sk[32:], pk[:])*/
	/////////////////solana

	CPk, DPk := ed.Commit(pk)
	zkPk := ed.Prove(temSk)

	round.temp.sk = sk
	round.temp.pk = pk
	round.temp.DPk = DPk
	round.temp.zkPk = zkPk

	index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		fmt.Printf("============round1 start,get dnode id index fail,err = %v ===========\n", err)
		return err
	}

	kg := &KGRound1Message{
		KGRoundMessage: new(KGRoundMessage),
		CPk:            CPk,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(index)

	round.Save.Sk = sk
	round.Save.Pk = pk
	round.temp.kgRound1Messages[index] = kg
	round.out <- kg

	fmt.Printf("============ round1 start success,cpk = %v,index = %v ============\n", CPk, index)
	return nil
}

func (round *round1) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, error) {
	for j, msg := range round.temp.kgRound1Messages {
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

func (round *round1) NextRound() smpc.Round {
	round.started = false
	return &round2{round}
}

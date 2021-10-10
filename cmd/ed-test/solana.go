/*
This file provides Solana dev tools like generate key pair, build address, sign and verify tx, call rpc etc.
*/
package main

import (
	"bytes"
	"context"
	"fmt"
	//"log"
	"math/big"

	"encoding/hex"
	"errors"
	bin "github.com/dfuse-io/binary"
	"github.com/dfuse-io/solana-go"
	"github.com/dfuse-io/solana-go/programs/system"
	"github.com/dfuse-io/solana-go/rpc"
	//"github.com/agl/ed25519"
)

func main() {
	tx_test()
}

func checkError(err error) {
	if err != nil {
		//log.Fatal(err)
		fmt.Printf("=======================checkError, err = %v ========================\n", err)
	}
}

func buildUnsignedTx(fromAddress, toAddress string, amount *big.Int) *solana.Transaction {
	from, err := solana.PublicKeyFromBase58(fromAddress)
	checkError(err)
	to, err := solana.PublicKeyFromBase58(toAddress)
	checkError(err)
	lamports := amount.Uint64()

	transfer := &system.Instruction{
		BaseVariant: bin.BaseVariant{
			TypeID: 2, // 0 表示 create account，1 空缺，2 表示 transfer
			Impl: &system.Transfer{
				Lamports: bin.Uint64(lamports),
				Accounts: &system.TransferAccounts{
					From: &solana.AccountMeta{PublicKey: from, IsSigner: true, IsWritable: true},
					To:   &solana.AccountMeta{PublicKey: to, IsSigner: false, IsWritable: true},
				},
			},
		},
	}

	ctx := context.Background()
	cli := GetClient()

	resRbt, err := cli.GetRecentBlockhash(ctx, "finalized")
	checkError(err)
	blockHash := resRbt.Value.Blockhash
	fmt.Printf("\nRecent block hash: %v\n", blockHash)

	opt := &solana.Options{
		Payer: from,
	}

	tx, err := solana.TransactionWithInstructions([]solana.TransactionInstruction{transfer}, blockHash, opt)
	checkError(err)
	fmt.Printf("\nTransaction: %+v\n", tx)
	return tx
}

func signTx(tx *solana.Transaction, priv solana.PrivateKey) []byte {
	m := tx.Message
	fmt.Printf("\nMessage: %+v\n", m)

	buf := new(bytes.Buffer)
	err := bin.NewEncoder(buf).Encode(m)
	checkError(err)

	messageCnt := buf.Bytes()
	fmt.Printf("\nMessage bytes: %+v\n", messageCnt)
	signature, err := priv.Sign(messageCnt)
	checkError(err)
	fmt.Printf("\nSignature: %+v\n", signature)
	fmt.Printf("\nSignature bytes: %+v\n", signature[:])
	return signature[:]
}

func makeSignedTx(tx *solana.Transaction, sig []byte) *solana.Transaction {
	var signature [64]byte
	copy(signature[:], sig)
	tx.Signatures = append(tx.Signatures, signature)
	fmt.Printf("\nSigned tx: %+v\n", tx)
	return tx
}

func simulateTx(tx *solana.Transaction) {
	ctx := context.Background()
	cli := GetClient()
	resSmt, err := cli.SimulateTransaction(ctx, tx)
	checkError(err)
	fmt.Printf("\nSimulate transaction result: %+v\n", resSmt)
}

func sendTx(tx *solana.Transaction) {
	ctx := context.Background()
	cli := GetClient()
	txid, err := cli.SendTransaction(ctx, tx)
	checkError(err)
	fmt.Printf("\nSend transaction success: %v\n", txid) // 2Rt9koHr14HL3MKKoq1iqSE1z8vC6a7MCsNih7R4v2XyGSVDzstDJqagicJUfwTmZFD9WHTFtuY3r6qgwd6haWrH*/
}

func tx_test() {
	tx := buildUnsignedTx("7R9zUfmcXPUFGEtWtjuFUjhW5WD2i4G6ZL4TFbDJSozu", "2z55nksdCojo3jDW5reezbZMEvBQmdgPvMa7djMn3vR4", big.NewInt(2333))
	//tx := buildUnsignedTx("DLnwyzASiNxwAz4wUfaHWnrZNi27YWCQf6JMSbH1b2pP", "2z55nksdCojo3jDW5reezbZMEvBQmdgPvMa7djMn3vR4", big.NewInt(333))

	priv, _ := solana.PrivateKeyFromBase58("3tFWtC14qLFNCZjGZHhBjE9Ff78SUtvVrcV13QPz2nRiQV6JpycbYp7oRibUn39jYYm65nHNVA6CSv6rHvEXY3vm")
	sig := signTx(tx, priv)

	/*sig,_ := hex.DecodeString("bc319a15be87b5737c8ff951353c4e1ed59c7113d1bc3279d5e47e4a1c81d98b9c18b68d36db0516409ff6f0034744d3f92a283a7a9cacbde85af335ff48f00e")
	pk,_ := hex.DecodeString("b75e3b663dd8af70dbbf87aa39b4c3f824300cfc175ca2a366d4ab5a6d184830")
	m := tx.Message
	buf := new(bytes.Buffer)
	bin.NewEncoder(buf).Encode(m)
	messageCnt := buf.Bytes()
	var pk1 [32]byte
	var sig1 [64]byte
	copy(pk1[:],pk[:])
	copy(sig1[:],sig[:])

	fmt.Printf("=================== ed sign,sig = %v,pk = %v,msg = %v, msg str = %v ==================\n",sig1,pk1,messageCnt,hex.EncodeToString(messageCnt[:]))
	suss := ed25519.Verify(&pk1,messageCnt,&sig1)
	fmt.Printf("=================== ed sign,suss = %v ==================\n",suss)*/

	signedTx := makeSignedTx(tx, sig)

	// 仿真
	//simulateTx(signedTx)

	// 真实发送
	sendTx(signedTx)
}

func GetClient() *rpc.Client {
	var endpoint = "https://testnet.solana.com"
	cli := rpc.NewClient(endpoint)
	return cli
}

func PubkeyHexToAddress(pubkeyHex string) (string, error) {
	bz, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return "", errors.New("Decode pubkey hex error")
	}
	pub := PublicKeyFromBytes(bz)
	return fmt.Sprintf("%s", pub), nil
}

func PublicKeyFromBytes(in []byte) (out solana.PublicKey) {
	byteCount := len(in)
	if byteCount == 0 {
		return
	}

	max := 32
	if byteCount < max {
		max = byteCount
	}

	copy(out[:], in[0:max])
	return
}

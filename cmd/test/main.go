package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	golog "github.com/ipfs/go-log"
	libp2p "github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	net "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	ma "github.com/multiformats/go-multiaddr"
	gologging "github.com/whyrusleeping/go-logging"
	
	"bytes"
	"math/big"

	"encoding/hex"
	"errors"
	bin "github.com/dfuse-io/binary"
	"github.com/dfuse-io/solana-go"
	"github.com/dfuse-io/solana-go/programs/system"
	"github.com/dfuse-io/solana-go/rpc"
)

// makeBasicHost creates a LibP2P host with a random peer ID listening on the
// given multiaddress. It will use secio if secio is true.
func makeBasicHost(listenPort int, secio bool, randseed int64) (host.Host, error) {

	// If the seed is zero, use real cryptographic randomness. Otherwise, use a
	// deterministic randomness source to make generated keys stay the same
	// across multiple runs
	var r io.Reader
	if randseed == 0 {
		r = rand.Reader
	} else {
		r = mrand.New(mrand.NewSource(randseed))
	}

	// Generate a key pair for this host. We will use it
	// to obtain a valid host ID.
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", listenPort)),
		libp2p.Identity(priv),
	}

	if !secio {
		opts = append(opts, libp2p.NoEncryption())
	}

	basicHost, err := libp2p.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	// Build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", basicHost.ID().Pretty()))

	// Now we can build a full multiaddress to reach this host
	// by encapsulating both addresses:
	addr := basicHost.Addrs()[0]
	fullAddr := addr.Encapsulate(hostAddr)
	log.Printf("I am %s\n", fullAddr)
	if secio {
		log.Printf("Now run \"go run main.go -l %d -d %s -secio\" on a different terminal\n", listenPort+1, fullAddr)
	} else {
		log.Printf("Now run \"go run main.go -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	}

	return basicHost, nil
}

func handleStream(s net.Stream) {

	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readData(rw)
	go writeData(rw)

	// stream 's' will stay open until you close it (or the other side closes it).
}

func readData(rw *bufio.ReadWriter) {

	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		if str == "" {
			return
		}
		if str != "\n" {

			chain := make([]Block, 0)
			if err := json.Unmarshal([]byte(str), &chain); err != nil {
				log.Fatal(err)
			}

			mutex.Lock()
			if len(chain) > len(Blockchain) {
				Blockchain = chain
				bytes, err := json.MarshalIndent(Blockchain, "", "  ")
				if err != nil {

					log.Fatal(err)
				}
				// Green console color:     \x1b[32m
				// Reset console color:     \x1b[0m
				fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
			}
			mutex.Unlock()
		}
	}
}

func writeData(rw *bufio.ReadWriter) {

	go func() {
		for {
			time.Sleep(5 * time.Second)
			mutex.Lock()
			bytes, err := json.Marshal(Blockchain)
			if err != nil {
				log.Println(err)
			}
			mutex.Unlock()

			mutex.Lock()
			rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
			rw.Flush()
			mutex.Unlock()

		}
	}()

	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		sendData = strings.Replace(sendData, "\n", "", -1)
		bpm, err := strconv.Atoi(sendData)
		if err != nil {
			log.Fatal(err)
		}
		newBlock := generateBlock(Blockchain[len(Blockchain)-1], bpm)

		if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
			mutex.Lock()
			Blockchain = append(Blockchain, newBlock)
			mutex.Unlock()
		}

		bytes, err := json.Marshal(Blockchain)
		if err != nil {
			log.Println(err)
		}

		spew.Dump(Blockchain)

		mutex.Lock()
		rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
		rw.Flush()
		mutex.Unlock()
	}

}

// ---------------------------------------------- solana tx test -----------------------------------------------------------

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

//--------------------------------------------------------------------------------------------------------------------------

func main() {
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{0, t.String(), 0, calculateHash(genesisBlock), ""}

	Blockchain = append(Blockchain, genesisBlock)

	// LibP2P code uses golog to log messages. They log with different
	// string IDs (i.e. "swarm"). We can control the verbosity level for
	// all loggers with:
	golog.SetAllLoggers(gologging.INFO) // Change to DEBUG for extra info

	// Parse options from the command line
	sol := flag.Bool("sol", false, "enable test solana tx")
	listenF := flag.Int("l", 0, "wait for incoming connections")
	target := flag.String("d", "", "target peer to dial")
	secio := flag.Bool("secio", false, "enable secio")
	seed := flag.Int64("seed", 0, "set random seed for id generation")
	flag.Parse()

	if *sol == true {
	    tx_test()
	    return
	}

	if *listenF == 0 {
		log.Fatal("Please provide a port to bind on with -l")
	}

	// Make a host that listens on the given multiaddress
	ha, err := makeBasicHost(*listenF, *secio, *seed)
	if err != nil {
		log.Fatal(err)
	}

	if *target == "" {
		log.Println("listening for connections")
		// Set a stream handler on host A. /p2p/1.0.0 is
		// a user-defined protocol name.
		ha.SetStreamHandler("/p2p/1.0.0", handleStream)

		select {} // hang forever
		/**** This is where the listener code ends ****/
	} else {
		ha.SetStreamHandler("/p2p/1.0.0", handleStream)

		// The following code extracts target's peer ID from the
		// given multiaddress
		ipfsaddr, err := ma.NewMultiaddr(*target)
		if err != nil {
			log.Fatalln(err)
		}

		pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
		if err != nil {
			log.Fatalln(err)
		}

		peerid, err := peer.IDB58Decode(pid)
		if err != nil {
			log.Fatalln(err)
		}

		// Decapsulate the /ipfs/<peerID> part from the target
		// /ip4/<a.b.c.d>/ipfs/<peer> becomes /ip4/<a.b.c.d>
		targetPeerAddr, _ := ma.NewMultiaddr(
			fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
		targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

		// We have a peer ID and a targetAddr so we add it to the peerstore
		// so LibP2P knows how to contact it
		ha.Peerstore().AddAddr(peerid, targetAddr, pstore.PermanentAddrTTL)

		log.Println("opening stream")
		// make a new stream from host B to host A
		// it should be handled on host A by the handler we set above because
		// we use the same /p2p/1.0.0 protocol
		s, err := ha.NewStream(context.Background(), peerid, "/p2p/1.0.0")
		if err != nil {
			log.Fatalln(err)
		}
		// Create a buffered stream so that read and writes are non blocking.
		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

		// Create a thread to read and write data.
		go writeData(rw)
		go readData(rw)

		select {} // hang forever

	}
}




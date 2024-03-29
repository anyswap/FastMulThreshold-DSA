/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange huangweijun@anyswap.exchange
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Package main  Gsmpc main program 
package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/anyswap/FastMulThreshold-DSA/crypto"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/internal/flags"
	"github.com/anyswap/FastMulThreshold-DSA/internal/params"
	"github.com/anyswap/FastMulThreshold-DSA/p2p"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/layer2"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/nat"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/netutil"
	rpcsmpc "github.com/anyswap/FastMulThreshold-DSA/rpc/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc"
	comlog "github.com/anyswap/FastMulThreshold-DSA/log"
	"gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "gsmpc" // Client identifier to advertise over the network
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit  = ""
	gitDate    = ""
	gitVersion = ""
	// The app that holds all commands and flags.
	app = flags.NewApp(gitCommit, gitDate, "the Smpc Wallet Service command line interface")
)

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// StartSmpc Start the gsmpc program, including:
// 1. Initialization: RPC, P2P service, local database (including general database, private key database, bip32 c value database,bip32 pre-sign data database, pre-sign data database, public key group information database, database for saving data related to generate pubkey command, database for saving data related to signature command, database for saving data related to resare command, pubkey), P2P callback function, Crypto coins configuration, startup parameters (including the number of pre generated packets, the timeout waiting for P2P information, the number of automatic retries after failed address application or signature, the timeout agreed by the nodes, whether to synchronize pre generated packets between nodes, etc.), and the enodeid of the local node.
// 2. Load the pubkeys generated by history and execute it only once.
// 3. Generate 4 large prime numbers
// 4. Execute automatic pre generation of data packets.
// 5. Listen for the arrival of the sign command.
// 6. Delete the data related to generating pubkey command, the signature command and the restore command from the corresponding sub database, and correspondingly change the status of the command data to timeout in the general database.
func StartSmpc(c *cli.Context) {

	//smpc.Tx_Test()
	SetLogger()
	go func() {
		<-signalChan
		stopLock.Lock()
		common.Info("=============================Cleaning before stop...======================================")
		stopLock.Unlock()
		os.Exit(0)
	}()
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	err := startP2pNode()
	if err != nil {
	    comlog.Error("start p2p node fail","err",err)
	    return
	}

	time.Sleep(time.Duration(30) * time.Second)

	rpcsmpc.RPCInit(rpcport)

	common.Info("=============================Start Gsmpc=================================","datadir",datadir,"waitmsg",waitmsg,"rotate",rotate,"maxage",maxage,"trytimes",trytimes,"presignnum",presignnum,"nonetrestrict",nonetrestrict,"relay",relayInPeers,"jobs",jobs,"autopre",autopre,"testnet",testnet,"neighbor relay",neigh)
	params := &smpc.LunchParams{WaitMsg: waitmsg, TryTimes: trytimes, PreSignNum: presignnum, Jobs: jobs, MaxAcceptTime: maxaccepttime, Bip32Pre: bip32pre, SyncPreSign: syncpresign,RelayInPeers: relayInPeers,AutoPreSign:autopre,TestNet:testnet,NeighRelay:neigh}
	smpc.Start(params)
	select {} // note for server, or for client
}

// SetLogger config log print
func SetLogger() {
	common.SetLogger(uint32(verbosity), json, color)
	if log != "" {
		common.SetLogFile(log, rotate, maxage)
	}
}

var (
	//args
	rpcport      int
	port         int
	config       string
	bootnodes    string
	keyfile      string
	keyfilehex   string
	pubkey       string
	genKey       string
	datadir      string
	log          string
	rotate       uint64
	maxage       uint64
	verbosity    uint64
	nonetrestrict bool
	json         bool
	color        bool
	waitmsg      uint64
	trytimes     uint64
	presignnum   uint64
	jobs   uint64
	maxaccepttime    uint64
	bip32pre     uint64
	syncpresign string
	relayInPeers        bool
	neigh       bool
	autopre        bool
	testnet   bool

	statDir = "stat"

	stopLock   sync.Mutex
	signalChan = make(chan os.Signal, 1)
)

const privateNet bool = false

type conf struct {
	Gsmpc *gsmpcConf
}

type gsmpcConf struct {
	Nodekey   string
	Bootnodes string
	Port      int
	Rpcport   int
}

func init() {
	app.Action = StartSmpc
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2018-2019 The anyswap Authors"
	app.Commands = []cli.Command{
		versionCommand,
		licenseCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))
	app.Flags = []cli.Flag{
		cli.IntFlag{Name: "rpcport", Value: 0, Usage: "listen port", Destination: &rpcport},
		cli.IntFlag{Name: "port", Value: 0, Usage: "listen port", Destination: &port},
		cli.StringFlag{Name: "config", Value: "./conf.toml", Usage: "config file", Destination: &config},
		cli.StringFlag{Name: "bootnodes", Value: "", Usage: "boot node", Destination: &bootnodes},
		cli.StringFlag{Name: "nodekey", Value: "", Usage: "private key filename", Destination: &keyfile},
		cli.StringFlag{Name: "nodekeyhex", Value: "", Usage: "private key as hex", Destination: &keyfilehex},
		cli.StringFlag{Name: "pubkey", Value: "", Usage: "public key from web user", Destination: &pubkey},
		cli.StringFlag{Name: "genkey", Value: "", Usage: "generate a node key", Destination: &genKey},
		cli.StringFlag{Name: "datadir", Value: "", Usage: "data dir", Destination: &datadir},
		cli.StringFlag{Name: "log", Value: "", Usage: "Specify log file, support rotate", Destination: &log},
		cli.Uint64Flag{Name: "rotate", Value: 24, Usage: "log rotation time (unit hour)", Destination: &rotate},
		cli.Uint64Flag{Name: "maxage", Value: 7200, Usage: "log max age (unit hour)", Destination: &maxage},
		cli.Uint64Flag{Name: "verbosity", Value: 4, Usage: "log verbosity (0:panic, 1:fatal, 2:error, 3:warn, 4:info, 5:debug, 6:trace)", Destination: &verbosity},
		cli.BoolTFlag{Name: "nonetrestrict", Usage: "Not connectivity can be restricted to certain IP networks(without whitelist of static nodes)", Destination: &nonetrestrict},
		cli.BoolFlag{Name: "json", Usage: "output log in json format", Destination: &json},
		cli.BoolFlag{Name: "color", Usage: "output log in color text format", Destination: &color},
		cli.Uint64Flag{Name: "waitmsg", Value: 180, Usage: "the time to wait p2p msg", Destination: &waitmsg},
		cli.Uint64Flag{Name: "trytimes", Value: 1, Usage: "the times to try key-gen/sign", Destination: &trytimes},
		cli.Uint64Flag{Name: "presignnum", Value: 10, Usage: "the total of pre-sign data", Destination: &presignnum},
		cli.Uint64Flag{Name: "jobs", Value: 10000, Usage: "the max worker numbers", Destination: &jobs},
		cli.BoolFlag{Name: "autopresign", Usage: "auto pre-sign when start gsmpc", Destination: &autopre},
		cli.BoolTFlag{Name: "relay", Usage: "relay msg in peers", Destination: &relayInPeers},
		cli.BoolFlag{Name: "neighbor-relay", Usage: "relay msg in neighbor nodes", Destination: &neigh},
		cli.BoolTFlag{Name: "testnet", Usage: "testnet or mainnet", Destination: &testnet},
		cli.Uint64Flag{Name: "maxaccepttime", Value: 604800, Usage: "the max time to wait for accept from all nodes", Destination: &maxaccepttime},
		cli.Uint64Flag{Name: "bip32pre", Value: 4, Usage: "the total counts of pre-sign data for bip32 child pubkey", Destination: &bip32pre},
		cli.StringFlag{Name: "sync-presign", Value: "true", Usage: "synchronize presign data between group nodes", Destination: &syncpresign},
	}
	gitVersion = params.VersionWithMeta
}

func getConfig() error {
	var cf conf
	var path string = config
	if keyfile != "" && keyfilehex != "" {
		fmt.Printf("Options -nodekey and -nodekeyhex are mutually exclusive\n")
		keyfilehex = ""
	}
	nkey := ""
	bnodes := ""
	pt := 0
	rport := 0
	if common.FileExist(path) {
		if _, err := toml.DecodeFile(path, &cf); err != nil {
			fmt.Printf("DecodeFile %v: %v\n", path, err)
			return err
		}
		comlog.Info("config file","path", path)

		nkey = cf.Gsmpc.Nodekey
		bnodes = cf.Gsmpc.Bootnodes
		pt = cf.Gsmpc.Port
		rport = cf.Gsmpc.Rpcport
	}
	if nkey != "" && keyfile == "" {
		keyfile = nkey
	}
	if bnodes != "" && bootnodes == "" {
		bootnodes = bnodes
	}
	if pt != 0 && port == 0 {
		port = pt
	}
	if rport != 0 && rpcport == 0 {
		rpcport = rport
	}
	return nil
}

// startP2pNode  Start P2P service 
func startP2pNode() error {
	common.InitDir(datadir)
	params.SetVersion(gitVersion, gitCommit, gitDate)
	layer2.InitP2pDir()
	err := getConfig()
	if err != nil {
	    return err
	}

	if port == 0 {
		port = 4441
	}
	if rpcport == 0 {
		rpcport = 4449
	}
	if !privateNet && bootnodes == "" {
	    if testnet {
		bootnodes = "enode://c8cd604f8db9e26bea4bdde9d16778027dd1a964298349de6cc5217103cf5181be8fe41893e755c7594f8c0c73a1eaa14ff297e4c606ef39f2decd31d2ccea25@101.32.97.27:20901"
	    } else {
		bootnodes = "enode://c189b1fd3c7377ad705266017a2d6d2b649b83db31475705a97940d6e228cd92df9500f5dcc3723f81ef08a7910fcda66463827b89341c30c4c9015861e082c7@101.32.97.27:11920"
	    }
	}
	if genKey != "" {
		nodeKey, err := crypto.GenerateKey()
		if err != nil {
			comlog.Error("could not generate key","err", err)
			os.Exit(1)
		}
		if err = crypto.SaveECDSA(genKey, nodeKey); err != nil {
			fmt.Printf("could not save key: %v\n", err)
			os.Exit(1)
		}
		os.Exit(1)
	}
	var nodeKey *ecdsa.PrivateKey
	var errkey error
	pubdir := ""
	if privateNet {
		if bootnodes == "" {
			bootnodes = "enode://4dbed736b0d918eb607382e4e50cd85683c4592e32f666cac03c822b2762f2209a51b3ed513adfa28c7fa2be4ca003135a5734cfc1e82161873debb0cff732c8@127.0.0.1:36231"
		}
		keyfilehex = ""
		fmt.Printf("private network\n")
		if pubkey != "" {
			pubdir = pubkey
			if strings.HasPrefix(pubkey, "0x") {
				pubdir = pubkey[2:]
			}
			fmt.Printf("bootnodes: %v\n", bootnodes)
			keyname := fmt.Sprintf("%v.key", pubdir[:8])
			keyfile = filepath.Join(layer2.GetSelfDir(), keyname)
		}
	}
	if keyfilehex != "" {
		nodeKey, errkey = crypto.HexToECDSA(keyfilehex)
		if errkey != nil {
			comlog.Error("HexToECDSA nodekeyhex","keyfile", keyfilehex, "err",errkey)
			os.Exit(1)
		}
		comlog.Info("start p2p","keyfilehex",keyfilehex,"bootnodes",bootnodes)
	} else {
		if keyfile == "" {
			keyfile = fmt.Sprintf("node.key")
		}
		comlog.Info("start p2p","keyfilehex",keyfilehex,"bootnodes",bootnodes)
		smpc.KeyFile = keyfile
		nodeKey, errkey = crypto.LoadECDSA(keyfile)
		if errkey != nil {
			nodeKey, _ = crypto.GenerateKey()
			err = crypto.SaveECDSA(keyfile, nodeKey)
			if err != nil {
			    os.Exit(1)
			}

			var kfd *os.File
			kfd, _ = os.OpenFile(keyfile, os.O_WRONLY|os.O_APPEND, 0600)
			_,err2 := kfd.WriteString(fmt.Sprintf("\nenode://%v\n", discover.PubkeyID(&nodeKey.PublicKey)))
			if err2 != nil {
			    kfd.Close()
			    os.Exit(1)
			}
			kfd.Close()
		}
	}
	nodeidString := discover.PubkeyID(&nodeKey.PublicKey).String()
	if pubdir == "" {
		pubdir = nodeidString
	}
	if privateNet {
		port = getPort(port)
		rp := getRPCPort(pubdir)
		fmt.Printf("getRPCPort, rp: %v\n", rp)
		if rp != 0 {
			rpcport = rp
		}
		rpcport = getPort(rpcport)
		storeRPCPort(pubdir, rpcport)
	}
	comlog.Info("start gsmpc","port",port,"rpcport",rpcport)
	layer2.InitSelfNodeID(nodeidString)
	layer2.InitIPPort(port)

	smpc := layer2.SmpcNew(nil)
	nodeserv := p2p.Server{
		Config: p2p.Config{
			MaxPeers:        100,
			MaxPendingPeers: 100,
			NoDiscovery:     false,
			PrivateKey:      nodeKey,
			Name:            "p2p layer2",
			ListenAddr:      fmt.Sprintf(":%d", port),
			Protocols:       smpc.Protocols(),
			NAT:             nat.Any(),
			//Logger:     logger,
		},
	}
	if !nonetrestrict {
		var inetRestrict netutil.Netlist
		nodeserv.Config.NetRestrict = &inetRestrict
	}

	bootNodes, err := discover.ParseNode(bootnodes)
	if err != nil {
		return err
	}
	comlog.Info("=========== startP2pNode() ==========","bootnodes", bootNodes)
	nodeserv.Config.BootstrapNodes = []*discover.Node{bootNodes}

	discover.CheckNetwokConnect()
	go func() {
		if err := nodeserv.Start(); err != nil {
			comlog.Error("==== startP2pNode() ====","nodeserv.Start err", err)
			return
		}

		layer2.InitServer(nodeserv)
		//fmt.Printf("\nNodeInfo: %+v\n", nodeserv.NodeInfo())
		comlog.Info("=================== P2P Service Start! ===================")
		if privateNet {
			go func() {
				signalChan := make(chan os.Signal, 1)
				signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
				<-signalChan
				deleteRPCPort(pubdir)
				os.Exit(1)
			}()
		}
		select {}
	}()
	return nil
}

// getPort get free port
func getPort(port int) int {
	if PortInUse(port) {
		portTmp, err := GetFreePort()
		if err == nil {
			fmt.Printf("PortInUse, port: %v, newport: %v\n", port, portTmp)
			port = portTmp
		} else {
			fmt.Printf("GetFreePort, err: %v\n", err)
			os.Exit(1)
		}
	}
	//fmt.Printf("PORT: %v\n", port)
	return port
}

// GetFreePort get free port
func GetFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// PortInUse Determine whether the port is used 
func PortInUse(port int) bool {
	home := common.HomeDir()
	if home != "" {
		checkStatement := ""
		if runtime.GOOS == "darwin" {
			checkStatement = fmt.Sprintf("netstat -an|grep %v", port)
			output, _ := exec.Command("sh", "-c", checkStatement).CombinedOutput()
			if len(output) > 0 {
				return true
			}
		} else if runtime.GOOS == "windows" {
			p := fmt.Sprintf("netstat -ano|findstr %v", port)
			output := exec.Command("cmd", "/C", p)
			_, err := output.CombinedOutput()
			if err == nil {
				return true
			}
		} else {
			checkStatement = fmt.Sprintf("netstat -anutp|grep %v", port)
			output, _ := exec.Command("sh", "-c", checkStatement).CombinedOutput()
			if len(output) > 0 {
				return true
			}
		}
	}
	return false
}

// storeRPCPort save rpc port
func storeRPCPort(pubdir string, rpcport int) {
	updateRPCPort(pubdir, fmt.Sprintf("%v", rpcport))
}

// deleteRPCPort delete rpc port
func deleteRPCPort(pubdir string) {
	updateRPCPort(pubdir, "")
}

// updateRPCPort update rpc port
func updateRPCPort(pubdir, rpcport string) {
	portDir := common.DefaultDataDir()
	dir := filepath.Join(portDir, statDir, pubdir)
	if common.FileExist(dir) != true {
	    err := os.MkdirAll(dir, os.ModePerm)
	    if err != nil {
		return
	    }
	}
	rpcfile := filepath.Join(dir, "rpcport")
	fmt.Printf("==== updateRPCPort() ====, rpcfile: %v, rpcport: %v\n", rpcfile, rpcport)
	f, err := os.Create(rpcfile)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		_, err = f.Write([]byte(rpcport))
		if err != nil {
		    return
		}
	}
}

// getRPCPort get rpc port
func getRPCPort(pubdir string) int {
	fmt.Printf("==== getRPCPort() ====, pubdir: %v\n", pubdir)
	portDir := common.DefaultDataDir()
	dir := filepath.Join(portDir, statDir, pubdir)
	if common.FileExist(dir) != true {
		return 0
	}
	rpcfile := filepath.Join(dir, "rpcport")
	if common.FileExist(rpcfile) != true {
		return 0
	}

	port, err := ioutil.ReadFile(rpcfile)
	if err == nil {
		pp := strings.Split(string(port), "\n")
		p, err := strconv.Atoi(pp[0])
		fmt.Printf("==== getRPCPort() ====, p: %v, err: %v\n", p, err)
		if err == nil {
			return p
		}
	}
	return 0
}

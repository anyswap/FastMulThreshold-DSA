package main

import (
    "fmt"
    "bytes"
    "io"
    "net"
    "flag"
    "github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
    "strings"
    "math/big"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
    "encoding/json"
    "github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
    "github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
    "github.com/anyswap/FastMulThreshold-DSA/log"
    cryptorand "crypto/rand"
    "github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
    r255 "github.com/gtank/ristretto255"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
    "encoding/hex"
    "crypto/sha512"
    tsslib "github.com/anyswap/FastMulThreshold-DSA/tss-lib/common"
    "github.com/anyswap/FastMulThreshold-DSA/smpc/tss/eddsa/signing"
    "errors"
    "github.com/anyswap/FastMulThreshold-DSA/crypto"
    "github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
    "os"
    "github.com/anyswap/FastMulThreshold-DSA/crypto/sha3"
    "github.com/anyswap/FastMulThreshold-DSA/internal/common/hexutil"
)

//------------------------------------------------
var (
    KeyFile string
    MsgToEnode map[string]string = make(map[string]string)
)

func main() {
    clientip := flag.String("ip", "", "client ip to dial") // --ip
    clientport := flag.String("port", "", "client port to dial") // --port
    keyfile := flag.String("nodekey", "", "node key file path") // --port
    flag.Parse()
    if *clientip == "" || *clientport == "" || *keyfile == "" {
	log.Error("===============ip/port param error============")
	return
    }
    
   KeyFile = *keyfile
   nodeKey, errkey := crypto.LoadECDSA(*keyfile)
    if errkey != nil {
	    nodeKey, _ = crypto.GenerateKey()
	    err := crypto.SaveECDSA(*keyfile, nodeKey)
	    if err != nil {
		os.Exit(1)
	    }

	    var kfd *os.File
	    kfd, _ = os.OpenFile(*keyfile, os.O_WRONLY|os.O_APPEND, 0600)
	    _,err2 := kfd.WriteString(fmt.Sprintf("\nenode://%v\n", discover.PubkeyID(&nodeKey.PublicKey)))
	    if err2 != nil {
		kfd.Close()
		os.Exit(1)
	    }
	    kfd.Close()
    }
    
    cli := *clientip + ":" + *clientport
    socket.ServerAddress = cli

    log.Info("=============load keyfile successfully=============","KeyFile",KeyFile)
    
    listener, err := net.Listen(socket.ServerNetworkType, socket.ServerAddress)
    if err != nil {
        panic(err)
    }
    
    go ec2.GenRandomSafePrime()
    
    defer listener.Close()
    log.Info("waiting client connect...")

    for {
        conn, err := listener.Accept()
        if err != nil {
            panic(err)
        }

        go handleConnect(conn)
    }
}

//------------------------------------------------

func handleConnect(conn net.Conn) {
    log.Info("socket server, client connected", "addr",conn.RemoteAddr())

    for {
        //conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(3600))) //设置读取超时时间
        
	msg, err := socket.Read(conn)

	log.Info("=================socket server,finish reading msg================","msg",msg,"err",err)

	if err != nil {
            if err == io.EOF {
                log.Error("socket server,client closed", "addr",conn.RemoteAddr())
                break
            } else {
                log.Error("socket server read error", "err",err)
            }

	    continue
        }

	go handleMessage(conn,msg)
    }
}

//--------------------------------------------

func handleMessage(conn net.Conn,msg string) {
    if msg == "" {
	return
    }

    msgmap := make(map[string]string)
    err := json.Unmarshal([]byte(msg),&msgmap)
    if err != nil {
	log.Error("===========socket server,handle message error","err",err)
	return
    }

    msgtype := msgmap["MsgType"]
    switch msgtype {
    case "KGRound0Msg":
	    HandleKGRound0Msg(conn,msgmap["Content"])
	    break
    case "KGRound1Msg":
	    HandleKGRound1Msg(conn,msgmap["Content"])
	    break
    //case "KGRound2Msg":
//	    HandleKGRound2Msg(conn,msgmap["Content"])
//	    break
    case "KGRound2SquareFreeProve":
	    HandleKGRound2SquareFreeProve(conn,msgmap["Content"])
	    break
    case "KGRound2VssShare":
	    HandleKGRound2VssShare(conn,msgmap["Content"])
	    break
    //case "IdsVss":
//	    HandleIdsVss(conn,msgmap["Content"])
//	    break
    case "KGRound3Msg":
	    HandleKGRound3Msg(conn,msgmap["Content"])
	    break
    case "KGRound4VssCheck":
	    HandleKGRound4VssCheck(conn,msgmap["Content"])
	    break
    case "KGRound4DeCom":
	    HandleKGRound4DeCom(conn,msgmap["Content"])
	    break
    /*case "KGRound4DeCom2":
	    HandleKGRound4DeCom2(conn,msgmap["Content"])
	    break
    case "KGRound4XiCom":
	    HandleKGRound4XiCom(conn,msgmap["Content"])
	    break
    case "KGRound4Msg":
	    HandleKGRound4Msg(conn,msgmap["Content"])
	    break*/
    case "KGRound5SquareFee":
	    HandleKGRound5SquareFee(conn,msgmap["Content"])
	    break
    case "KGRound5Hv":
	    HandleKGRound5Hv(conn,msgmap["Content"])
	    break
    case "KGRound6ComCheck":
	    HandleKGRound6ComCheck(conn,msgmap["Content"])
	    break
    case "KGRound6SquareFeeCheck":
	    HandleKGRound6SquareFeeCheck(conn,msgmap["Content"])
	    break
    case "KGRound6HvCheck":
	    HandleKGRound6HvCheck(conn,msgmap["Content"])
	    break
    case "KGRound6Msg":
	    HandleKGRound6Msg(conn,msgmap["Content"])
	    break
    case "KGRound7Msg":
	    HandleKGRound7Msg(conn,msgmap["Content"])
	    break
    case "SigningRound1Msg":
	    HandleSigningRound1Msg(conn,msgmap["Content"])
	    break
    case "SigningRound2PaiEnc":
	    HandleSigningRound2PaiEnc(conn,msgmap["Content"])
	    break
    case "SigningRound2Msg":
	    HandleSigningRound2Msg(conn,msgmap["Content"])
	    break
    case "SigningRound4MtARangeProofCheck":
	    HandleSigningRound4MtARangeProofCheck(conn,msgmap["Content"])
	    break
    case "SigningRound4ComCheck":
	    HandleSigningRound4ComCheck(conn,msgmap["Content"])
	    break
    case "SigningRound4Beta":
	    HandleSigningRound4Beta(conn,msgmap["Content"])
	    break
    case "SigningRound4Msg":
	    HandleSigningRound4Msg(conn,msgmap["Content"])
	    break
    case "SigningRound4Msg1":
	    HandleSigningRound4Msg1(conn,msgmap["Content"])
	    break
    case "SigningRound5MtARespZKProofCheck":
	    HandleSigningRound5MtARespZKProofCheck(conn,msgmap["Content"])
	    break
    case "SigningRound5ComCheck":
	    HandleSigningRound5ComCheck(conn,msgmap["Content"])
	    break
    case "SigningRound5Msg":
	    HandleSigningRound5Msg(conn,msgmap["Content"])
	    break
    case "SigningRound6Msg":
	    HandleSigningRound6Msg(conn,msgmap["Content"])
	    break
    case "SigningRound7ComCheck":
	    HandleSigningRound7ComCheck(conn,msgmap["Content"])
	    break
    case "SigningRound7DeCom":
	    HandleSigningRound7DeCom(conn,msgmap["Content"])
	    break
    case "SigningRound7Msg":
	    HandleSigningRound7Msg(conn,msgmap["Content"])
	    break
    case "SigningRound8PDLwSlackCheck":
	    HandleSigningRound8PDLwSlackCheck(conn,msgmap["Content"])
	    break
    case "SigningRound8CalcK1R":
	    HandleSigningRound8CalcK1R(conn,msgmap["Content"])
	    break
    case "SigningRound8Msg":
	    HandleSigningRound8Msg(conn,msgmap["Content"])
	    break
    case "SigningRound9Msg":
	    HandleSigningRound9Msg(conn,msgmap["Content"])
	    break
    case "SigningRound10Msg":
	    HandleSigningRound10Msg(conn,msgmap["Content"])
	    break
    case "SigningRound11Msg":
	    HandleSigningRound11Msg(conn,msgmap["Content"])
	    break
    case "EDKGRound1Msg":
	    HandleEDKGRound1Msg(conn,msgmap["Content"])
	    break
    case "EDKGRound4ComCheck":
	    HandleEDKGRound4ComCheck(conn,msgmap["Content"])
	    break
    case "EDKGRound4Msg":
	    HandleEDKGRound4Msg(conn,msgmap["Content"])
	    break
    case "EDKGRound6VssCheck":
	    HandleEDKGRound6VssCheck(conn,msgmap["Content"])
	    break
    case "EDKGRound6Msg":
	    HandleEDKGRound6Msg(conn,msgmap["Content"])
	    break
    case "EDSigningRound1Msg":
	    HandleEDSigningRound1Msg(conn,msgmap["Content"])
	    break
    case "EDSigningRound4Msg":
	    HandleEDSigningRound4Msg(conn,msgmap["Content"])
	    break
    case "EDSigningRound6Msg":
	    HandleEDSigningRound6Msg(conn,msgmap["Content"])
	    break
    case "EDSigningRound7Msg":
	    HandleEDSigningRound7Msg(conn,msgmap["Content"])
	    break
    default:
	    return
    }
}

//-------------------------------------------

type PolyShare struct {
    Shares []*ec2.ShareStruct2
}

//-------------------------------------------

func HandleKGRound0Msg(conn net.Conn,content string) {
    log.Info("============socket server,handle KGRound0Msg================","content",content)
    if content == "" {
	return
    }

    s:= &socket.KGRound0Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	log.Error("============socket server,unmarshal message error================","err",err)
	return
    }

    log.Info("============socket server,HandleKGRound0Msg================","content",content,"fromid",s.FromID,"enode",s.ENode)
    MsgToEnode[s.FromID] = s.ENode
}
    
func HandleKGRound1Msg(conn net.Conn,content string) {
    log.Info("============socket server,handle KGRound1Msg================","content",content)
    if content == "" {
	return
    }

    s:= &socket.KGRound1Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	log.Error("============socket server,unmarshal message error================","err",err)
	return
    }
    
    u1 := random.GetRandomIntFromZn(secp256k1.S256(s.KeyType).N1())
    c1 := random.GetRandomIntFromZn(secp256k1.S256(s.KeyType).N1())

    if u1 == nil || c1 == nil || s.ThresHold <= 1 || s.ThresHold > s.DNodeCount {
	log.Error("==============socket server,KGRound1 param check fail====================","u1",u1,"c1",c1,"s.ThresHold",s.ThresHold,"s.DNodeCount",s.DNodeCount)
	return 
    }

    u1Poly, u1PolyG, _ := ec2.Vss2Init(s.KeyType,u1,s.ThresHold)
    _, c1PolyG, _ := ec2.Vss2Init(s.KeyType,c1,s.ThresHold)

    u1Gx, u1Gy := secp256k1.S256(s.KeyType).ScalarBaseMult(u1.Bytes())
    u1Secrets := make([]*big.Int, 0)
    u1Secrets = append(u1Secrets, u1Gx)
    u1Secrets = append(u1Secrets, u1Gy)
    for i := 1; i < len(u1PolyG.PolyG); i++ {
	    u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
	    u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
    }
    commitU1G := new(ec2.Commitment).Commit(u1Secrets...)

    //bip32
    c1Gx, c1Gy := secp256k1.S256(s.KeyType).ScalarBaseMult(c1.Bytes())
    c1Secrets := make([]*big.Int, 0)
    c1Secrets = append(c1Secrets, c1Gx)
    c1Secrets = append(c1Secrets, c1Gy)
    for i := 1; i < len(c1PolyG.PolyG); i++ {
	    c1Secrets = append(c1Secrets, c1PolyG.PolyG[i][0])
	    c1Secrets = append(c1Secrets, c1PolyG.PolyG[i][1])
    }
    commitC1G := new(ec2.Commitment).Commit(c1Secrets...)

    // 3. generate their own paillier public key and private key
    u1PaillierPk, u1PaillierSk,p,q := ec2.GenerateKeyPair(s.PaillierKeyLen)
    
    if u1PaillierPk == nil || u1PaillierSk == nil {
	log.Error("==============socket server,KGRound1 paillier pk/sk fail====================")
       return 
    }

    if commitU1G == nil || commitC1G == nil {
	log.Error("==============socket server,KGRound1 commitment u1/c1 data error====================")
	return 
    }

    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    //
    msgmap["U1"],err = EncryptU1(u1)
    if err != nil {
	return
    }

    msgmap["U1Poly"],err = EncryptU1Poly(u1Poly)
    if err != nil {
	return
    }

    tmp3 := make([][]string, len(u1PolyG.PolyG))
    for k, v := range u1PolyG.PolyG {
	    tmp4 := make([]string, len(v))
	    for kk, vv := range v {
		    tmp4[kk] = fmt.Sprintf("%v", vv)
	    }

	    tmp3[k] = tmp4
    }
    tmp5 := make([]string, len(tmp3))
    for k, v := range tmp3 {
	    vv := strings.Join(v, ":")
	    tmp5[k] = vv
    }
    msgmap["U1PolyG"] = strings.Join(tmp5, "|")
    
    msgmap["CommitU1G.C"] = fmt.Sprintf("%v", commitU1G.C)
    tmp := make([]string, len(commitU1G.D))
    for k, v := range commitU1G.D {
	    tmp[k] = fmt.Sprintf("%v", v)
    }
    msgmap["CommitU1G.D"] = strings.Join(tmp, ":")
    msgmap["C1"] = fmt.Sprintf("%v", c1)

    msgmap["CommitC1G.C"] = fmt.Sprintf("%v", commitC1G.C)
    tmp = make([]string, len(commitC1G.D))
    for k, v := range commitC1G.D {
	    tmp[k] = fmt.Sprintf("%v", v)
    }
    msgmap["CommitC1G.D"] = strings.Join(tmp, ":")

    msgmap["U1PaillierSk"],err = EncryptPaillierSk(u1PaillierSk)
    if err != nil {
	return
    }

    pk, err := u1PaillierPk.MarshalJSON()
    if err != nil {
	log.Error("==============socket server,KGRound1 paillier pk marshal error====================","err",err)
	return
    }
    msgmap["U1PaillierPk"] = string(pk)

    msgmap["P"],err = EncryptP(p)
    if err != nil {
	return
    }

    msgmap["Q"],err = EncryptQ(q)
    if err != nil {
	return
    }
    //

    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("==============socket server,KGRound1 message1 marshal error====================","err",err)
	return
    }

    log.Info("===========socket server,write msg to client===========","msg",string(str))
    socket.Write(conn,string(str))
}

//------------------------------------------------

func HandleKGRound2SquareFreeProve(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound2SquareFreeProve{}
    err := s.ToObj([]byte(content))
    if err != nil {
	log.Error("===============server.HandleKGRound2SquareFreeProve,toobj error==============","err",err)
	return
    }

    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    paisk,err := DecryptPaillierSk(s.PaiSk)
    if err != nil {
	log.Error("===============server.HandleKGRound2SquareFreeProve,dec paillier sk fail==============","err",err)
	return
    }

    num := ec2.MustGetRandomInt(paisk.N.BitLen())
    if num == nil {
	log.Error("==============socket server,get random int====================","msg",content)
	return
    }

    sfProof := ec2.SquareFreeProve(paisk.N,num,paisk.L)
    if sfProof == nil {
	log.Error("==============socket server,get square free prove====================","msg",content)
	return
    }
    
    msgmap["Num"] = fmt.Sprintf("%v",num)
    sf,err := sfProof.MarshalJSON()
    if err != nil {
	log.Error("===============server.HandleKGRound2SquareFreeProve,marshal sfproof to json error==============","err",err)
       return 
    }
    msgmap["SfPf"] = string(sf)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("==============socket server,HandleKGRound2SquareFreeProve,marshal error====================","msg",content,"err",err)
	return
    }

    log.Info("=============server.HandleKGRound2SquareFreeProve,write msg to channel===========","content",string(str))
    socket.Write(conn,string(str))
}

//-------------------------------------------------

type KGRound2VssShareRet struct {
    Shares []*ec2.ShareStruct2
}

func HandleKGRound2VssShare(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound2VssShare{}
    err := s.ToObj([]byte(content))
    if err != nil {
	log.Error("===============server.HandleKGRound2VssShare,toobj error==============","err",err)
	return
    }

    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
   
    u1Poly,err := DecryptU1Poly(s.U1Poly)
    if err != nil {
	return
    }

    u1Shares, err := u1Poly.Vss2(s.KeyType,s.IDs)
    if err != nil {
	return
    }

    tmp := make([]*ec2.ShareStruct2,len(u1Shares))
    for k,v := range u1Shares {
	shareenc,err := EncryptShare(v.Share,"")
	if err != nil {
	    return
	}

	t := &ec2.ShareStruct2{ID:v.ID,Share:new(big.Int).SetBytes([]byte(shareenc))}
	tmp[k] = t
    }
    
    ret := &KGRound2VssShareRet{Shares:tmp}
    b,err := json.Marshal(ret)
    if err != nil {
	return
    }
    msgmap["VssShares"] = string(b)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------

/*type ShareRet struct {
    Self bool
    ToID string
    ID *big.Int
    Share string
}

type KGRound2RetValue struct {
    Num *big.Int
    SfPf *ec2.SquareFreeProof
    Shares []ShareRet
}

func HandleKGRound2Msg(conn net.Conn,content string) {
    log.Info("=============server.HandleKGRound2Msg,get content===========","content",content)
    if content == "" {
	return
    }

    s:= &socket.KGRound2Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	log.Error("===============server.HandleKGRound2Msg,toobj error==============","err",err)
	return
    }

    log.Info("=============server.HandleKGRound2Msg,to obj successfully===========","s",s)
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    paisk,err := DecryptPaillierSk(s.PaiSk)
    if err != nil {
	log.Error("===============server.HandleKGRound2Msg,dec paillier sk fail==============","err",err)
	return
    }

    num := ec2.MustGetRandomInt(paisk.N.BitLen())
    if num == nil {
	log.Error("==============socket server,get random int====================","msg",content)
	return
    }

    sfProof := ec2.SquareFreeProve(paisk.N,num,paisk.L)
    if sfProof == nil {
	log.Error("==============socket server,get square free prove====================","msg",content)
	return
    }

    u1Poly,err := DecryptU1Poly(s.U1Poly)
    if err != nil {
	return
    }

    u1Shares, err := u1Poly.Vss2(s.KeyType,s.Ids)
    if err != nil {
	return
    }

    log.Info("=============server.HandleKGRound2Msg,get u1shares successfully===========","u1Shares",u1Shares)
    var Shares []ShareRet
    for k, id := range s.Ids {
	for _, v := range u1Shares {
	    a := v.ID

	    vv := ec2.GetSharesID(v)
	    if vv != nil && vv.Cmp(id) == 0 && k == s.Index {
		enode := MsgToEnode[s.NodeID]
		log.Info("=============server.HandleKGRound2Msg,get current node share===========","enode",enode,"idtmp",s.NodeID,"share",v.Share)
		sh,err := EncryptShare(v.Share,enode)
		if err != nil {
		    log.Error("=============server.HandleKGRound2Msg,encrypt curnode share error===========","err",err,"enode",enode,"idtmp",s.NodeID)
		    return
		}
		//_,err = DecryptShare(sh,KeyFile)
		//if err != nil {
		//    log.Error("=============server.HandleKGRound2Msg,dec share data fail=============","err",err)
		//    return
		//}
		
		tmp := ShareRet{Self:true,ToID:"",ID:a,Share:sh}
		Shares = append(Shares,tmp)
		break
	} else if vv != nil && vv.Cmp(id) == 0 {
		t := fmt.Sprintf("%v",id)
		idtmp := hex.EncodeToString([]byte(t))
		enode := MsgToEnode[idtmp]
		log.Info("=============server.HandleKGRound2Msg,encrypt other nodes share data===========","share",v.Share,"enode",enode,"idtmp",idtmp)
		sh,err := EncryptShare(v.Share,enode)
		if err != nil {
		    log.Error("=============server.HandleKGRound2Msg,encrypt other nodes share error===========","err",err,"enode",enode,"idtmp",idtmp)
		    return
		}
		//_,err = DecryptShare(sh,KeyFile)
		//if err != nil {
		//    log.Error("=============server.HandleKGRound2Msg,dec share data fail=============","err",err)
		//    return
		//}
		
		tmp := ShareRet{Self:false,ToID:idtmp,ID:a,Share:sh}
		Shares = append(Shares,tmp)
		break
	    }
	}
    }

    ret := &KGRound2RetValue{Num:num,SfPf:sfProof,Shares:Shares}
    b,err := json.Marshal(ret)
    if err != nil {
	log.Error("=============server.HandleKGRound2Msg,marshal return value error===========","err",err)
	return
    }
    msgmap["KGRound2RetValue"] = string(b)

    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("==============socket server,HandleKGRound2Msg,marshal error====================","msg",content,"err",err)
	return
    }

    log.Info("=============server.HandleKGRound2Msg,write msg to channel===========","content",string(str))
    socket.Write(conn,string(str))
}
*/
//---------------------------------------------------

/*func HandleIdsVss(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.IdsVss{}
    err := s.ToObj([]byte(content))
    if err != nil {
	log.Error("===============socket server,HandleIdsVss,to obj error===========","err",err)
	return
    }
    
    dul,err := ec2.ContainsDuplicate(s.Ids)
    if err != nil || dul {
	log.Error("================socket server,contain dup ids","err",err)
	return
    }

    //u1Poly := &ec2.PolyStruct2{Poly: s.U1Poly}
    u1Poly,err := DecryptU1Poly(s.U1Poly)
    if err != nil {
	log.Error("===============socket server,HandleIdsVss,dec pai sk error===========","err",err)
	return
    }

    u1Shares, err := u1Poly.Vss2(s.KeyType,s.Ids)
    if err != nil {
	log.Error("================socket server,vss error","err",err)
	return
    }

    var share PolyShare
    share.Shares = u1Shares
    data,err := json.Marshal(share)
    if err != nil {
	log.Error("================socket server,Poly Share marshal error","err",err)
	return
    }

    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    msgmap["U1Shares"] = string(data)
    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("================socket server,marshal vss data error","err",err)
	return
    }

    socket.Write(conn,string(str))
}
*/

//----------------------------------------

func HandleKGRound3Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound3Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    if !ec2.SquareFreeVerify(s.N,s.Num,s.SfPf) {
	msgmap["SquareFreeVerifyRes"] = "FALSE"
    } else {
	msgmap["SquareFreeVerifyRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("===============socket server,marshal KGRound3 error","err",err)
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------

func HandleKGRound4VssCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound4VssCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
   
    log.Info("=============server.HandleKGRound4VssCheck=============","KeyFile",KeyFile)
    cm := string(s.Share.Bytes())
    sh,err := DecryptShare(cm,KeyFile)
    if err != nil {
	log.Error("=============server.HandleKGRound4VssCheck,dec share data fail=============","err",err)
	return
    }

    log.Info("=============server.HandleKGRound4VssCheck,dec share data successfully=============","KeyFile",KeyFile,"share",sh)
    ushare := &ec2.ShareStruct2{ID: s.ID, Share: sh}
    ps := &ec2.PolyGStruct2{PolyG: s.PolyG}
    if !ushare.Verify2(s.KeyType,ps) {
	msgmap["Round4CheckRes"] = "FALSE"
    }

    //verify commitment
    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    if !deCommit.Verify(s.KeyType) {
	msgmap["Round4CheckRes"] = "FALSE"
    }

    //verify bip32 commitment
    deCommitBip32 := &ec2.Commitment{C: s.Bip32C, D: s.Bip32D}
    if !deCommitBip32.Verify(s.KeyType) {
	msgmap["Round4CheckRes"] = "FALSE"
    }

    _, c1G := deCommitBip32.DeCommit(s.KeyType)

    cGVerifyx, cGVerifyy := secp256k1.S256(s.KeyType).ScalarBaseMult(s.Msg21C.Bytes())
    if c1G[0].Cmp(cGVerifyx) == 0 && c1G[1].Cmp(cGVerifyy) == 0 {
	    //.....
    } else {
	msgmap["Round4CheckRes"] = "FALSE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    msgmap["Round4CheckRes"] = "TRUE"
    socket.Write(conn,string(str))
}

//------------------------------------------------

func HandleKGRound4DeCom(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound4DeCom{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }

    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    var pkx *big.Int
    var pky *big.Int
    var c *big.Int
    var skU1 *big.Int

    for k:= range s.Cs {
	cm := string(s.Shares[k].Bytes())
	sh,err := DecryptShare(cm,KeyFile)
	if err != nil {
	    return
	}

	ushare := &ec2.ShareStruct2{ID: s.IDs[k], Share: sh}
	deCommit := &ec2.Commitment{C: s.Cs[k], D: s.Ds[k]}
	_, u1G := deCommit.DeCommit(s.KeyType)
	pkx = u1G[0]
	pky = u1G[1]

	c = s.CC[k] 
	skU1 = ushare.Share
	break
    }

    for k := range s.Cs {
	if k == 0 {
	    continue
	}

	cm := string(s.Shares[k].Bytes())
	sh,err := DecryptShare(cm,KeyFile)
	if err != nil {
	    return
	}

	ushare := &ec2.ShareStruct2{ID: s.IDs[k], Share: sh}
	deCommit := &ec2.Commitment{C: s.Cs[k], D: s.Ds[k]}
	_, u1G := deCommit.DeCommit(s.KeyType)
	pkx, pky = secp256k1.S256(s.KeyType).Add(pkx, pky, u1G[0], u1G[1])
	c = new(big.Int).Add(c, s.CC[k])
	skU1 = new(big.Int).Add(skU1, ushare.Share)
    }

    c = new(big.Int).Mod(c, secp256k1.S256(s.KeyType).N1())
    skU1 = new(big.Int).Mod(skU1, secp256k1.S256(s.KeyType).N1())

    msgmap["PKX"] = fmt.Sprintf("%v", pkx)
    msgmap["PKY"] = fmt.Sprintf("%v", pky)
    msgmap["C"] = fmt.Sprintf("%v", c)
    msgmap["SKU1"],err = EncryptSk(skU1)
    if err != nil {
	return
    }

    // add commitment for sku1
    xiGx, xiGy := secp256k1.S256(s.KeyType).ScalarBaseMult(skU1.Bytes())
    u1Secrets := make([]*big.Int, 0)
    u1Secrets = append(u1Secrets, xiGx)
    u1Secrets = append(u1Secrets, xiGy)
    commitXiG := new(ec2.Commitment).Commit(u1Secrets...)
    if commitXiG == nil {
	return 
    }

    b,err := json.Marshal(commitXiG)
    if err != nil {
	return
    }

    msgmap["CommitXiG"] = string(b)
    //

    // zk of paillier key
    u1NtildeH1H2, alpha, beta, p, q,p1,p2 := ec2.GenerateNtildeH1H2(s.NtildeLen)
    if u1NtildeH1H2 == nil {
	return
    }
    b,err = json.Marshal(u1NtildeH1H2)
    if err != nil {
	return
    }
    msgmap["NtildeH1H2"] = string(b)

    ntildeProof1 := ec2.NewNtildeProof(u1NtildeH1H2.H1, u1NtildeH1H2.H2, alpha, p, q, u1NtildeH1H2.Ntilde)
    ntildeProof2 := ec2.NewNtildeProof(u1NtildeH1H2.H2, u1NtildeH1H2.H1, beta, p, q, u1NtildeH1H2.Ntilde)
    b,err = json.Marshal(ntildeProof1)
    if err != nil {
	return
    }
    msgmap["NtildeProof1"] = string(b)

    b,err = json.Marshal(ntildeProof2)
    if err != nil {
	return
    }
    msgmap["NtildeProof2"] = string(b)

    priv := &ec2.NtildePrivData{Alpha:alpha,Beta:beta,Q1:p,Q2:q}
    msgmap["U1NtildePrivData"],err = EncryptNtildePrivData(priv)
    if err != nil {
	return
    }

    //msgmap["Alpha"] = fmt.Sprintf("%v",alpha)
    //msgmap["Beta"] = fmt.Sprintf("%v",beta)
    msgmap["P1"],err = EncryptP1(p1)
    if err != nil {
	return
    }

    msgmap["P2"],err = EncryptP2(p2)
    if err != nil {
	return
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

/*func HandleKGRound4DeCom2(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound4DeCom2{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    sh,err := DecryptShare(s.Share,KeyFile)
    if err != nil {
	return
    }

    ushare := &ec2.ShareStruct2{ID: s.ID, Share: sh}
    deCommit := &ec2.Commitment{C: s.C, D: s.D}

    _, u1G := deCommit.DeCommit(s.KeyType)

    msgmap["G0"] = fmt.Sprintf("%v", u1G[0])
    msgmap["G1"] = fmt.Sprintf("%v", u1G[1])
    msgmap["C"] = fmt.Sprintf("%v", s.Msg21C)
    msgmap["SKU1"] = fmt.Sprintf("%v", ushare.Share)
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleKGRound4XiCom(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound4XiCom{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    c := new(big.Int).Mod(s.C, secp256k1.S256(s.KeyType).N1())
    sk := new(big.Int).Mod(s.Sk, secp256k1.S256(s.KeyType).N1())
    msgmap["C"] = fmt.Sprintf("%v", c)
    msgmap["SK"] = fmt.Sprintf("%v", sk)
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}
//---------------------------------------

func HandleKGRound4Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound4Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    // add commitment for sku1
    xiGx, xiGy := secp256k1.S256(s.KeyType).ScalarBaseMult(s.Sk.Bytes())
    u1Secrets := make([]*big.Int, 0)
    u1Secrets = append(u1Secrets, xiGx)
    u1Secrets = append(u1Secrets, xiGy)
    commitXiG := new(ec2.Commitment).Commit(u1Secrets...)
    if commitXiG == nil {
	return
    }

    b,err := json.Marshal(commitXiG)
    if err != nil {
	log.Error("==============socket server,marshal commitment msg error===============","err",err)
	return
    }

    msgmap["CommitXiG"] = string(b)

    // zk of paillier key
    u1NtildeH1H2, alpha, beta, p, q,p1,p2 := ec2.GenerateNtildeH1H2(s.NtildeLen)
    if u1NtildeH1H2 == nil {
	    return
    }
    
    ntildeProof1 := ec2.NewNtildeProof(u1NtildeH1H2.H1, u1NtildeH1H2.H2, alpha, p, q, u1NtildeH1H2.Ntilde)
    ntildeProof2 := ec2.NewNtildeProof(u1NtildeH1H2.H2, u1NtildeH1H2.H1, beta, p, q, u1NtildeH1H2.Ntilde)

    priv := &ec2.NtildePrivData{Alpha:alpha,Beta:beta,Q1:p,Q2:q}
    b,err = json.Marshal(priv)
    if err != nil {
	log.Error("==============socket server,marshal ntilde priv data error===============","err",err)
	return
    }

    msgmap["U1NtildePrivData"] = string(b)

    b,err = json.Marshal(u1NtildeH1H2)
    if err != nil {
	log.Error("==============socket server,marshal ntilde h1 h2 data error===============","err",err)
	return
    }

    msgmap["NtildeH1H2"] = string(b)
    msgmap["Alpha"] = fmt.Sprintf("%v",alpha)
    msgmap["Beta"] = fmt.Sprintf("%v",beta)
    msgmap["P"] = fmt.Sprintf("%v",p)
    msgmap["Q"] = fmt.Sprintf("%v",q)
    msgmap["P1"] = fmt.Sprintf("%v",p1)
    msgmap["P2"] = fmt.Sprintf("%v",p2)

    b,err = json.Marshal(ntildeProof1)
    if err != nil {
	log.Error("==============socket server,marshal ntilde proof1 error===============","err",err)
	return
    }
    msgmap["NtildeProof1"] = string(b)

    b,err = json.Marshal(ntildeProof2)
    if err != nil {
	log.Error("==============socket server,marshal ntilde proof2 error===============","err",err)
	return
    }
    msgmap["NtildeProof2"] = string(b)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}
*/

//--------------------------------------------

func HandleKGRound5SquareFee(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound5SquareFee{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    num := ec2.MustGetRandomInt(s.Ntilde.BitLen())
    if num == nil {
	return
    }

    p1,err := DecryptP1(s.P1)
    if err != nil {
	return
    }

    p2,err := DecryptP2(s.P2)
    if err != nil {
	return
    }

    pMinus1 := new(big.Int).Sub(p1, big.NewInt(1))
    qMinus1 := new(big.Int).Sub(p2, big.NewInt(1))
    l := new(big.Int).Mul(pMinus1, qMinus1)
    sfProof := ec2.SquareFreeProve(s.Ntilde,num,l)
    if sfProof == nil {
	return
    }

    msgmap["Num"] = fmt.Sprintf("%v",num)
    sfpf,err := json.Marshal(sfProof)
    if err != nil {
	return
    }
    msgmap["SfPf"] = string(sfpf)
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//--------------------------------------------

func HandleKGRound5Hv(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound5Hv{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    num := ec2.MustGetRandomInt(s.Ntilde.BitLen())
    if num == nil {
	return
    }

    p1,err := DecryptP1(s.P1)
    if err != nil {
	return
    }

    p2,err := DecryptP2(s.P2)
    if err != nil {
	return
    }

    hvProof := ec2.HvProve(s.Ntilde,num,p1,p2)
    if hvProof == nil {
	return
    }

    msgmap["Num"] = fmt.Sprintf("%v",num)
    hvf,err := json.Marshal(hvProof)
    if err != nil {
	return
    }
    msgmap["HvPf"] = string(hvf)
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------

func HandleKGRound6ComCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound6ComCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    if !deCommit.Verify(s.KeyType) {
	msgmap["CommitCheckRes"] = "FALSE"
    } else {
	msgmap["CommitCheckRes"] = "TRUE"
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleKGRound6SquareFeeCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound6SquareFeeCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    if !ec2.SquareFreeVerify(s.Ntilde,s.Num,s.Sfp) {
	msgmap["SquareFreeCheckRes"] = "FALSE"
    } else {
	msgmap["SquareFreeCheckRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
       return 
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------------

func HandleKGRound6HvCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound6HvCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    if !ec2.HvVerify(s.Ntilde,s.Num,s.HvPf) {
	msgmap["HvCheckRes"] = "FALSE"
    } else {
	msgmap["HvCheckRes"] = "TRUE"
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------------

func HandleKGRound6Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound6Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    sk,err := DecryptSk(s.Sk)
    if err != nil {
	return
    }

    // add prove for xi 
    u1zkXiProof := ec2.ZkXiProve(s.KeyType,sk)
    if u1zkXiProof == nil {
	return
    }

    pf,err := json.Marshal(u1zkXiProof)
    if err != nil {
	return
    }
    msgmap["ZkXiProof"] = string(pf)
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//------------------------------------------------

func HandleKGRound7Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound7Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    _, xiG := deCommit.DeCommit(s.KeyType)

    if !ec2.ZkXiVerify(s.KeyType,xiG,s.XiPf) {
	    msgmap["ZkXiCheckRes"] = "FALSE"
    } else {
	    msgmap["ZkXiCheckRes"] = "TRUE"
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------------

func HandleSigningRound1Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound1Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    var self *big.Int
    lambda1 := big.NewInt(1)
    for k, v := range s.IdSign {
	    if k == s.Index {
		    self = v
		    break
	    }
    }

    if self == nil {
	    return
    }

    for k, v := range s.IdSign {
	    if k == s.Index {
		    continue
	    }

	    sub := new(big.Int).Sub(v, self)
	    subInverse := new(big.Int).ModInverse(sub, secp256k1.S256(s.KeyType).N1())
	    if subInverse == nil {
		return
	    }

	    times := new(big.Int).Mul(subInverse, v)
	    lambda1 = new(big.Int).Mul(lambda1, times)
	    lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256(s.KeyType).N1())
    }

    tmp := string(s.SkU1.Bytes())
    sku1,err := DecryptSk(tmp)
    if err != nil {
	return
    }

    w1 := new(big.Int).Mul(lambda1, sku1)
    w1 = new(big.Int).Mod(w1, secp256k1.S256(s.KeyType).N1())
    msgmap["W1"],err = EncryptW1(w1)
    if err != nil {
	return
    }

    u1K := random.GetRandomIntFromZn(secp256k1.S256(s.KeyType).N1())
    u1Gamma := random.GetRandomIntFromZn(secp256k1.S256(s.KeyType).N1())

    u1GammaGx, u1GammaGy := secp256k1.S256(s.KeyType).ScalarBaseMult(u1Gamma.Bytes())
    commitU1GammaG := new(ec2.Commitment).Commit(u1GammaGx, u1GammaGy)
    if commitU1GammaG == nil {
	    return
    }

    // add for GG18 A.2 Respondent ZK Proof for MtAwc
    wiGx, wiGy := secp256k1.S256(s.KeyType).ScalarBaseMult(w1.Bytes())
    commitwiG := new(ec2.Commitment).Commit(wiGx, wiGy)
    if commitwiG == nil {
	return
    }

    msgmap["U1K"],err = EncryptU1K(u1K)
    if err != nil {
	return
    }

    msgmap["U1Gamma"],err = EncryptU1Gamma(u1Gamma)
    if err != nil {
	return
    }

    wicom,err := json.Marshal(commitwiG)
    if err != nil {
	return
    }
    msgmap["ComWiG"] = string(wicom)

    u1gammaG,err := json.Marshal(commitU1GammaG)
    if err != nil {
	return
    }
    msgmap["ComU1GammaG"] = string(u1gammaG)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------

func HandleSigningRound2PaiEnc(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound2PaiEnc{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    u1K,err := DecryptU1K(s.U1K)
    if err != nil {
	return
    }

    u1KCipher, u1R, _ := s.U1PaillierPk.Encrypt(u1K)

    msgmap["U1R"] = fmt.Sprintf("%v",u1R)
    msgmap["U1KCipher"] = fmt.Sprintf("%v",u1KCipher)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------------

func HandleSigningRound2Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound2Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    u1K,err := DecryptU1K(s.U1K)
    if err != nil {
	return
    }

    u1u1MtAZK1Proof := ec2.MtARangeProofProve(s.KeyType,s.UKC,u1K, s.UKC2, s.U1PaiPK, s.U1Nt)
    /*pf,err := json.Marshal(u1u1MtAZK1Proof)
    if err != nil {
	return
    }
    msgmap["U1MtAZK1Proof"] = string(pf)*/
    ret,err := EncryptMtARangeProof(u1u1MtAZK1Proof,"")
    if err != nil {
	return
    }
    pf,err := json.Marshal(ret)
    if err != nil {
	return
    }
    msgmap["U1MtAZK1Proof"] = string(pf)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleSigningRound4MtARangeProofCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound4MtARangeProofCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    old,err := DecryptMtARangeProof(s.MtAZK1Proof,KeyFile)
    if err != nil {
	return
    }

    u1rlt1 := old.MtARangeProofVerify(s.KeyType,s.KC, s.PaiPk,s.Nt)
    if !u1rlt1 {
	msgmap["MtARangeProofCheckRes"] = "FALSE"
    } else {
	msgmap["MtARangeProofCheckRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------------

func HandleSigningRound4ComCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound4ComCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    if !deCommit.Verify(s.KeyType) {
	msgmap["ComCheck"] = "FALSE"
    } else {
	msgmap["ComCheck"] = "TRUE"
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------

type BetaStar struct {
    BetaU1Star []*big.Int
    BetaU1 []*big.Int 
    VU1Star []*big.Int 
    VU1 []*big.Int
}

func HandleSigningRound4Beta(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound4Beta{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    NSalt := new(big.Int).Lsh(big.NewInt(1), uint(s.PaiKeyLen-s.PaiKeyLen/10))
    NSubN2 := new(big.Int).Mul(secp256k1.S256(s.KeyType).N1(), secp256k1.S256(s.KeyType).N1())
    NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
    // 2. MinusOne
    MinusOne := big.NewInt(-1)

    betaU1Star := make([]*big.Int, s.ThresHold)
    betaU1 := make([]*big.Int, s.ThresHold)
    for i := 0; i < s.ThresHold; i++ {
	    beta1U1Star := random.GetRandomIntFromZn(NSubN2)
	    beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)

	    tmp,err := EncryptBetaU1Star(beta1U1Star)
	    if err != nil {
		return
	    }
	    betaU1Star[i] = new(big.Int).SetBytes([]byte(tmp))
	    
	    tmp,err = EncryptBetaU1(beta1U1)
	    if err != nil {
		return
	    }

	    betaU1[i] = new(big.Int).SetBytes([]byte(tmp))
    }

    vU1Star := make([]*big.Int, s.ThresHold)
    vU1 := make([]*big.Int, s.ThresHold)
    for i := 0; i < s.ThresHold; i++ {
	    v1U1Star := random.GetRandomIntFromZn(NSubN2)
	    v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	   
	    tmp,err := EncryptVU1Star(v1U1Star)
	    if err != nil {
		return
	    }
	    vU1Star[i] = new(big.Int).SetBytes([]byte(tmp))

	    tmp,err = EncryptVU1(v1U1)
	    if err != nil {
		return
	    }
	    vU1[i] = new(big.Int).SetBytes([]byte(tmp))
    }

    beta := &BetaStar{BetaU1Star:betaU1Star,BetaU1:betaU1,VU1Star:vU1Star,VU1:vU1}
    b,err := json.Marshal(beta)
    if err != nil {
	return
    }
    msgmap["BetaStar"] = string(b)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------

func HandleSigningRound4Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound4Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    u1Gamma,err := DecryptU1Gamma(s.U1Gamma)
    if err != nil {
	return
    }

    u1KGamma1Cipher := s.CurPaiPk.HomoMul(s.KC, u1Gamma)

    betastar,err := DecryptBetaU1Star(string(s.BetaStar.Bytes()))
    if err != nil {
	return
    }

    beta1U1StarCipher, u1BetaR1, _ := s.CurPaiPk.Encrypt(betastar)
    u1KGamma1Cipher = s.CurPaiPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher)
    u1u1MtAZK2Proof := ec2.MtARespZKProofProve(s.KeyType,u1Gamma,betastar, u1BetaR1, s.UKC, u1KGamma1Cipher,s.OldPaiPk, s.OldNt)

    msgmap["U1KGamma1Cipher"],err = EncryptBigInt(u1KGamma1Cipher,"")
    if err != nil {
	return
    }

    tmp,err := EncryptMtARespZKProof(u1u1MtAZK2Proof,"")
    if err != nil {
	return
    }

    pf,err := json.Marshal(tmp)
    if err != nil {
	return
    }

    msgmap["MtAZK2Proof"] = string(pf)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------

func HandleSigningRound4Msg1(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound4Msg1{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    w1,err := DecryptU1Gamma(s.W1)
    if err != nil {
	return
    }

    u1Kw1Cipher := s.CurPaiPk.HomoMul(s.KC, w1)

    vu1star,err := DecryptVU1Star(string(s.VU1Star.Bytes()))
    if err != nil {
	return
    }

    v1U1StarCipher, u1VR1, _ := s.CurPaiPk.Encrypt(vu1star)
    u1Kw1Cipher = s.CurPaiPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
    u1u1MtAZK3Proof := ec2.MtAwcRespZKProofProve(s.KeyType,w1,vu1star, u1VR1, s.UKC,u1Kw1Cipher,s.OldPaiPk, s.OldNt)

    tmp,err := EncryptMtAwcRespZKProof(u1u1MtAZK3Proof,"")
    if err != nil {
	return
    }
    
    pf,err := json.Marshal(tmp)
    if err != nil {
	return
    }
    msgmap["MtAZK3Proof"] = string(pf)
    
    msgmap["Kw1Cipher"],err = EncryptBigInt(u1Kw1Cipher,"")
    if err != nil {
	return
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//------------------------------------------------

func HandleSigningRound5MtARespZKProofCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound5MtARespZKProofCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    clip,err := DecryptBigInt(string(s.Clipher.Bytes()),KeyFile)
    if err != nil {
	return
    }
   
    mta,err := DecryptMtARespZKProof(s.MtAZK2Proof,KeyFile)
    if err != nil {
	return
    }
   
    b := mta.MtARespZKProofVerify(s.KeyType,s.UKC, clip, s.PaiPk,s.Nt)
    if !b {
	msgmap["MtARespZKProofCheckRes"] = "FALSE"
    } else {
	msgmap["MtARespZKProofCheckRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//--------------------------------------------------

func HandleSigningRound5ComCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound5ComCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    _,xG := deCommit.DeCommit(s.KeyType)

    clip,err := DecryptBigInt(string(s.Cipher.Bytes()),KeyFile)
    if err != nil {
	return
    }
  
    mtawc,err := DecryptMtAwcRespZKProof(s.MtAZK3Proof,KeyFile)
    if err != nil {
	return
    }
  
    b := mtawc.MtAwcRespZKProofVefify(s.KeyType,xG,s.UKC,clip, s.PaiPk,s.Nt)
    if !b {
	msgmap["ComCheck"] = "FALSE"
    } else {
	msgmap["ComCheck"] = "TRUE"
    }
   
    paisk,err := DecryptPaillierSk(s.PaiSk)
    if err != nil {
	return
    }

    clip2,err := DecryptBigInt(string(s.U1KGamma1Cipher.Bytes()),KeyFile)
    if err != nil {
	return
    }
  
    alpha1U1, _ := paisk.Decrypt(clip2)
    u1U1, _ := paisk.Decrypt(clip)
    msgmap["Alpha1U1"] = fmt.Sprintf("%v",alpha1U1)
    msgmap["U1U1"] = fmt.Sprintf("%v",u1U1)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//------------------------------------------------

func HandleSigningRound5Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound5Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    delta1 := s.Alpha1[0]
    for i := 0; i < s.ThresHold; i++ {
	    if i == 0 {
		    continue
	    }
	    delta1 = new(big.Int).Add(delta1, s.Alpha1[i])
    }
    for i := 0; i < s.ThresHold; i++ {
	    betau1,err := DecryptBetaU1(string(s.BetaU1[i].Bytes()))
	    if err != nil {
		return
	    }

	    delta1 = new(big.Int).Add(delta1, betau1)
    }
    delta1 = new(big.Int).Mod(delta1, secp256k1.S256(s.KeyType).N1())
    msgmap["delta1"] = fmt.Sprintf("%v",delta1) 

    sigma1 := s.UU1[0]
    for i := 0; i < s.ThresHold; i++ {
	    if i == 0 {
		    continue
	    }
	    sigma1 = new(big.Int).Add(sigma1, s.UU1[i])
    }
    for i := 0; i < s.ThresHold; i++ {
	    vu1,err := DecryptVU1(string(s.VU1[i].Bytes()))
	    if err != nil {
		return
	    }

	    sigma1 = new(big.Int).Add(sigma1, vu1)
    }

    sigma1 = new(big.Int).Mod(sigma1, secp256k1.S256(s.KeyType).N1())
    msgmap["sigma1"] = fmt.Sprintf("%v",sigma1)

    // gg20: calculate T_i = g^sigma_i * h^l_i = sigma_i*G + l_i*h*G
    l1 := random.GetRandomIntFromZn(secp256k1.S256(s.KeyType).N1())
    hx,hy,err := ec2.CalcHPoint(s.KeyType)
    if err != nil {
	fmt.Printf("calc h point fail, err = %v",err)
	return
    }

    l1Gx,l1Gy := secp256k1.S256(s.KeyType).ScalarMult(hx,hy,l1.Bytes())
    sigmaGx,sigmaGy := secp256k1.S256(s.KeyType).ScalarBaseMult(sigma1.Bytes())
    t1X,t1Y := secp256k1.S256(s.KeyType).Add(sigmaGx,sigmaGy,l1Gx,l1Gy)
    // gg20: generate the ZK proof of T_i
    tProof := ec2.TProve(s.KeyType,t1X,t1Y,hx,hy,sigma1,l1)
    if tProof == nil {
	return
    }
    //

    msgmap["t1X"] = fmt.Sprintf("%v",t1X)
    msgmap["t1Y"] = fmt.Sprintf("%v",t1Y)
    b,err := json.Marshal(tProof)
    if err != nil {
	return
    }
    msgmap["tProof"] = string(b)

    msgmap["l1"],err = EncryptL1(l1)
    if err != nil {
	return
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------

func HandleSigningRound6Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound6Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    deltaSum := s.Delt[0]
    for k,v := range s.Delt {
	if k == 0 {
		continue
	}

	deltaSum = new(big.Int).Add(deltaSum,v)
    }
    deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256(s.KeyType).N1())
    msgmap["DeltaSum"] = fmt.Sprintf("%v",deltaSum)
    
    u1Gamma,err := DecryptU1Gamma(s.U1Gamma)
    if err != nil {
	return
    }

    u1GammaZKProof := ec2.ZkUProve(s.KeyType,u1Gamma)
    pf,err := json.Marshal(u1GammaZKProof)
    if err != nil {
	return
    }
    msgmap["U1GammaZKProof"] = string(pf)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleSigningRound7ComCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound7ComCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    if !deCommit.Verify(s.KeyType) {
	msgmap["ComCheck"] = "FALSE"
	str, err := json.Marshal(msgmap)
	if err != nil {
	    return
	}

	socket.Write(conn,string(str))
	return
    }

    _, u1GammaG := deCommit.DeCommit(s.KeyType)
    if !ec2.ZkUVerify(s.KeyType,u1GammaG,s.ZKProof) {
	msgmap["ComCheck"] = "FALSE"
    } else {
	msgmap["ComCheck"] = "TRUE"
    }

    msgmap["u1GammaG0"] = fmt.Sprintf("%v",u1GammaG[0])
    msgmap["u1GammaG1"] = fmt.Sprintf("%v",u1GammaG[1])
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleSigningRound7DeCom(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound7DeCom{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    _, u1GammaG := deCommit.DeCommit(s.KeyType)
    msgmap["u1GammaG0"] = fmt.Sprintf("%v",u1GammaG[0])
    msgmap["u1GammaG1"] = fmt.Sprintf("%v",u1GammaG[1])
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleSigningRound7Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound7Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    deltaSumInverse := new(big.Int).ModInverse(s.DeltaSum, secp256k1.S256(s.KeyType).N1())
    if deltaSumInverse == nil {
	return
    }

    deltaGammaGx, deltaGammaGy := secp256k1.S256(s.KeyType).ScalarMult(s.GammaX, s.GammaY, deltaSumInverse.Bytes())

    // 4. get r = deltaGammaGx
    r := deltaGammaGx
    zero, _ := new(big.Int).SetString("0", 10)
    if r.Cmp(zero) == 0 {
	    return
    }

    if r == nil || deltaGammaGy == nil {
	    return
    }

    msgmap["deltaGammaGx"] = fmt.Sprintf("%v",deltaGammaGx)
    msgmap["deltaGammaGy"] = fmt.Sprintf("%v",deltaGammaGy)

    u1K,err := DecryptU1Gamma(s.U1K)
    if err != nil {
	return
    }

    // gg20: compute ZK proof of consistency between R_i and E_i(k_i) 
    bigRK1Gx,bigRK1Gy := secp256k1.S256(s.KeyType).ScalarMult(deltaGammaGx,deltaGammaGy,u1K.Bytes())

    pdlWSlackStatement := &ec2.PDLwSlackStatement{
	    PK:         s.PaiPk,
	    CipherText: s.UKC,
	    K1RX:	bigRK1Gx,
	    K1RY:   bigRK1Gy,
	    Rx:     deltaGammaGx,
	    Ry:     deltaGammaGy,
	    H1:         s.Nt.H1,
	    H2:         s.Nt.H2,
	    NTilde:     s.Nt.Ntilde,
    }

    paisk,err := DecryptPaillierSk(s.PaiSk)
    if err != nil {
	return
    }

    pdlWSlackWitness := &ec2.PDLwSlackWitness{
	    SK: paisk,
	    K1: u1K,
	    K1Ra:  s.U1Ra,
    }
    pdlWSlackPf := ec2.NewPDLwSlackProof(s.KeyType,pdlWSlackWitness, pdlWSlackStatement)
    if pdlWSlackPf == nil {
	return
    }
    b,err := json.Marshal(pdlWSlackPf)
    if err != nil {
	return
    }
    msgmap["WSlackPf"] = string(b)

    msgmap["BigRK1Gx"] = fmt.Sprintf("%v",bigRK1Gx)
    msgmap["BigRK1Gy"] = fmt.Sprintf("%v",bigRK1Gy)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleSigningRound8PDLwSlackCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound8PDLwSlackCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    if !ec2.PDLwSlackVerify(s.KeyType,s.PdlWSlackStatement,s.PdlwSlackPf) {
	msgmap["PDLwSlackCheckRes"] = "FALSE"
    } else {
	msgmap["PDLwSlackCheckRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------------

func HandleSigningRound8CalcK1R(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound8CalcK1R{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    K1Rx,K1Ry := secp256k1.S256(s.KeyType).Add(s.OldK1Rx,s.OldK1Ry,s.IncK1Rx,s.IncK1Ry)
    msgmap["K1Rx"] = fmt.Sprintf("%v",K1Rx)
    msgmap["K1Ry"] = fmt.Sprintf("%v",K1Ry)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------------

func HandleSigningRound8Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound8Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    if s.K1Rx.Cmp(secp256k1.S256(s.KeyType).GX()) != 0 || s.K1Ry.Cmp(secp256k1.S256(s.KeyType).GY()) != 0 {
	msgmap["RCheckRes"] = "FALSE"
	str, err := json.Marshal(msgmap)
	if err != nil {
	    return
	}

	socket.Write(conn,string(str))
	return
    }

    msgmap["RCheckRes"] = "TRUE"

    S1X,S1Y := secp256k1.S256(s.KeyType).ScalarMult(s.DeltaGammaGx,s.DeltaGammaGy,s.Sigma1.Bytes())
    hx,hy,err := ec2.CalcHPoint(s.KeyType)
    if err != nil {
	return
    }

    l1,err := DecryptL1(string(s.L1.Bytes()))
    if err != nil {
	return
    }

    stProof := ec2.NewSTProof(s.KeyType,s.T1X,s.T1Y,S1X,S1Y,s.DeltaGammaGx,s.DeltaGammaGy,hx,hy,s.Sigma1,l1)
    if stProof == nil {
	return
    }

    pf,err := json.Marshal(stProof)
    if err != nil {
	return
    }

    msgmap["StProof"] = string(pf)

    msgmap["S1X"] = fmt.Sprintf("%v",S1X)
    msgmap["S1Y"] = fmt.Sprintf("%v",S1Y)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------

func HandleSigningRound9Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound9Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    hx,hy,err := ec2.CalcHPoint(s.KeyType)
    if err != nil {
	return 
    }

    var s1x *big.Int
    var s1y *big.Int
    
    for k := range s.S1X {
	if ok := ec2.STVerify(s.KeyType,s.S1X[k],s.S1Y[k],s.T1X[k],s.T1Y[k],s.DeltaGammaGx,s.DeltaGammaGy,hx,hy,s.STProof[k]); !ok {
	    msgmap["STCheckRes"] = "FALSE"
	    str, err := json.Marshal(msgmap)
	    if err != nil {
		return
	    }

	    socket.Write(conn,string(str))
	    return
	}

	if k == 0 {
	    s1x = s.S1X[k]
	    s1y = s.S1Y[k]
	    continue
	}

	s1x,s1y = secp256k1.S256(s.KeyType).Add(s1x,s1y,s.S1X[k],s.S1Y[k])
    }

    if s1x.Cmp(s.Pkx) != 0 || s1y.Cmp(s.Pky) != 0 {
	msgmap["STCheckRes"] = "FALSE"
    } else {
	msgmap["STCheckRes"] = "TRUE"
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleSigningRound10Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound10Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    u1K,err := DecryptU1K(string(s.K1.Bytes()))
    if err != nil {
	return
    }

    mk1 := new(big.Int).Mul(s.TxHash, u1K)
    rSigma1 := new(big.Int).Mul(s.R, s.Sigma1)
    us1 := new(big.Int).Add(mk1, rSigma1)
    us1 = new(big.Int).Mod(us1, secp256k1.S256(s.KeyType).N1())

    msgmap["US1"] = fmt.Sprintf("%v",us1)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleSigningRound11Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.SigningRound11Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    s1 := s.S[0]

    for k,_ := range s.S {
	    if k == 0 {
		continue
	    }

	    s1 = new(big.Int).Add(s1, s.S[k])
    }
    s1 = new(big.Int).Mod(s1, secp256k1.S256(s.KeyType).N1())

    msgmap["S"] = fmt.Sprintf("%v",s1)
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------------

func HandleEDKGRound1Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDKGRound1Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    //1.1-1.2 generate 32-bits privatekey', then bit calculation to privatekey
    rand := cryptorand.Reader

    var sk [32]byte
    var pk [32]byte
    var zkPk [64]byte

    if s.KeyType == smpc.SR25519 {
	    skScalar, err := ed_ristretto.NewRandomScalar()
	    if err != nil {
		return
	    }

	    PK := new(r255.Element).ScalarBaseMult(skScalar)

	    skScalar.Encode(sk[:0])
	    PK.Encode(pk[:0])

	    zkPk, err = ed_ristretto.Prove2(sk, pk)
	    if err != nil {
		return
	    }
    }else{
	    var skTem [64]byte
	    if _, err = io.ReadFull(rand, skTem[:]); err != nil {
		    fmt.Println("Error: io.ReadFull(rand, sk)")
		    return
	    }

	    ed.ScReduce(&sk, &skTem)
	    var A ed.ExtendedGroupElement
	    ed.GeScalarMultBase(&A, &sk)
	    A.ToBytes(&pk)

	    zkPk, err = ed.Prove2(sk,pk)
	    if err != nil {
		return
	    }
    }

    CPk, DPk, err := ed.Commit(pk)
    if err != nil {
	return
    }

    msgmap["sk"],err = EDKGEncryptSk(sk)
    if err != nil {
	return
    }

    msgmap["pk"] = hex.EncodeToString(pk[:])
    msgmap["CPk"] = hex.EncodeToString(CPk[:])
    msgmap["DPk"] = hex.EncodeToString(DPk[:])
    msgmap["zkPk"] = hex.EncodeToString(zkPk[:])
    //sigbit, _ := hex.DecodeString(string(sig[:]))
    //var t [32]byte
    //copy(t[:], msg3.DPk[32:])
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleEDKGRound4ComCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDKGRound4ComCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    CPkFlag := ed.Verify(s.CPk,s.DPk)
    if !CPkFlag {
	msgmap["ComCheck"] = "FALSE"
	str, err := json.Marshal(msgmap)
	if err != nil {
	    return
	}

	socket.Write(conn,string(str))
	return 
    }

    var t [32]byte
    copy(t[:], s.DPk[32:])

    var zkPkFlag = false
    if s.KeyType == smpc.SR25519 {
	    zkPkFlag = ed_ristretto.VerifyZk2(s.ZkPk, t)
    }else{
	    zkPkFlag = ed.VerifyZk2(s.ZkPk, t)
    }
    if !zkPkFlag {
	msgmap["ComCheck"] = "FALSE"
    } else {
	msgmap["ComCheck"] = "TRUE"
    }
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-------------------------------------------

type EDKGRound4ReturnValue struct {
    Uids [][32]byte
    CfsBBytes [][32]byte
    //Shares [][32]byte
    Shares []string
}

func HandleEDKGRound4Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDKGRound4Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    // 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
    var a [32]byte
    var aDigest [64]byte

    h := sha512.New()
    _, err = h.Write(s.DPk[32:])
    if err != nil {
	    return
    }

    _, err = h.Write(s.PkSet[:])
    if err != nil {
	    return
    }

    h.Sum(aDigest[:0])
    if s.KeyType == smpc.SR25519 {
	    ed_ristretto.ScReduce(&a, &aDigest)
    }else{
	    ed.ScReduce(&a, &aDigest)
    }

    sk,err := EDKGDecryptSk(s.Sk)
    if err != nil {
	return
    }

    // 2.6 calculate ask
    var ask [32]byte
    var temSk2 [32]byte
    copy(temSk2[:], sk[:32])

    if s.KeyType == smpc.SR25519 {
	    ed_ristretto.ScMul(&ask, &a, &temSk2)
    }else{
	    ed.ScMul(&ask, &a, &temSk2)
    }

    // 2.7 calculate vss

    var uids [][32]byte
    for _, v := range s.Ids {
	var tem [32]byte
	tmp := v.Bytes()
	copy(tem[:], tmp[:])
	if len(v.Bytes()) < 32 {
	    l := len(v.Bytes())
	    for j := l; j < 32; j++ {
		    tem[j] = byte(0x00)
	    }
	}
	uids = append(uids, tem)
    }
    
    var(
	    cfsBBytes [][32]byte
	    shares [][32]byte
    )

    if s.KeyType == smpc.SR25519 {
	_, cfsBBytes, shares,err = ed_ristretto.Vss(ask, uids, s.ThresHold,s.DnodeCount)
    }else{
	_, cfsBBytes, shares,err = ed.Vss(ask, uids,s.ThresHold,s.DnodeCount)
    }

    if cfsBBytes == nil || shares == nil || err != nil {
	if err != nil {
	    return
	}

	return
    }

    tmp := make([]string,len(shares))
    for k,v := range shares {
	t,err := EncryptByte32(v,"")
	if err != nil {
	    return
	}

	tmp[k] = t
    }

    ret := &EDKGRound4ReturnValue{Uids:uids,CfsBBytes:cfsBBytes,Shares:tmp}
    b,err := json.Marshal(ret)
    if err != nil {
	return
    }

    msgmap["Ret"] = string(b)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//----------------------------------------------

func HandleEDKGRound6VssCheck(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDKGRound6VssCheck{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    sh,err := DecryptByte32(s.Share,KeyFile)
    if err != nil {
	return
    }
    
    var shareUFlag = false
    if s.KeyType == smpc.SR25519 {
	    shareUFlag = ed_ristretto.VerifyVss(sh,s.ID,s.CfsBBytes)
    }else {
	    shareUFlag = ed.VerifyVss(sh,s.ID,s.CfsBBytes)
    }

    if !shareUFlag {
	msgmap["VssCheckRes"] = "FALSE"
    } else {
	msgmap["VssCheckRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleEDKGRound6Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDKGRound6Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    // 3.2 verify share2
    var a2 [32]byte
    var aDigest2 [64]byte

    // 3.3 calculate tSk
    var tSk [32]byte

    h := sha512.New()
    for k, _ := range s.Shares {
	    var temPk [32]byte
	    //t := msg3.DPk[:]
	    t := (s.DPks[k])[:] 
	    copy(temPk[:], t[32:])

	    h.Reset()
	    _, err = h.Write(temPk[:])
	    if err != nil {
		    return
	    }
	    _, err = h.Write(s.PkSet2)
	    if err != nil {
		    return
	    }
	    h.Sum(aDigest2[:0])

	    var askBBytes [32]byte
	    if s.KeyType == smpc.SR25519 {
		    a2Scalar, err := ed_ristretto.BytesReduceToScalar(aDigest2[:])
		    if err != nil {
			    return
		    }
		    var A = new(r255.Element)
		    A.Decode(temPk[:])
		    askB := new(r255.Element).ScalarMult(a2Scalar, A)
		    askB.Encode(askBBytes[:0])
	    }else {
		    ed.ScReduce(&a2, &aDigest2)

		    var askB, A ed.ExtendedGroupElement
		    A.FromBytes(&temPk)
		    ed.GeScalarMult(&askB, &a2, &A)
		    askB.ToBytes(&askBBytes)
	    }

	    //t2 := msg5.CfsBBytes
	    t2 := s.CfsBBytes[k]
	    tt := t2[0]
	    if !bytes.Equal(askBBytes[:], tt[:]) {
		    return
	    }

	    //t3 := msg4.Share
	    t3,err := DecryptByte32(s.Shares[k],KeyFile)
	    if err != nil {
		return
	    }

	    if s.KeyType == smpc.SR25519 {
		    ed_ristretto.ScAdd(&tSk, &tSk, &t3)
	    }else {
		    ed.ScAdd(&tSk, &tSk, &t3)
	    }
    }

    // 3.4 calculate pk
    var finalPkBytes [32]byte

    if s.KeyType == smpc.SR25519 {
	    var finalPk = new(r255.Element)
	    i := 0
	    for k := range s.Shares {
		    var temPk [32]byte
		    //t := msg3.DPk[:]
		    t := (s.DPks[k])[:]
		    copy(temPk[:], t[32:])

		    h.Reset()
		    _, err = h.Write(temPk[:])
		    if err != nil {
			    return
		    }

		    _, err = h.Write(s.PkSet2)
		    if err != nil {
			    return
		    }

		    h.Sum(aDigest2[:0])
		    a2Scalar, _ := ed_ristretto.BytesReduceToScalar(aDigest2[:])

		    var A = new(r255.Element)
		    A.Decode(temPk[:])
		    askB := new(r255.Element).ScalarMult(a2Scalar, A)

		    if i == 0 {
			    finalPk = askB
		    } else {
			    finalPk = new(r255.Element).Add(finalPk, askB)
		    }

		    i++
	    }

	    finalPk.Encode(finalPkBytes[:0])
    } else {
	    var finalPk ed.ExtendedGroupElement
	    i := 0
	    for k := range s.Shares {
		    var temPk [32]byte
		    //t := msg3.DPk[:]
		    t := (s.DPks[k])[:]
		    copy(temPk[:], t[32:])

		    h.Reset()
		    _, err = h.Write(temPk[:])
		    if err != nil {
			    return
		    }

		    _, err = h.Write(s.PkSet2)
		    if err != nil {
			    return
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
    }

    msgmap["tSk"],err = EDKGEncryptTSk(tSk)
    if err != nil {
	return
    }

    msgmap["finalPkBytes"] = hex.EncodeToString(finalPkBytes[:])
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

type EDSigningRound1ReturnValue struct {
    Uids [][32]byte
    //Sk [32]byte
    //TSk [32]byte
    Pkfinal [32]byte

    R [32]byte
    ZkR [64]byte
    DR [64]byte
    CR [32]byte
}

func HandleEDSigningRound1Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDSigningRound1Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    
    //var sk [32]byte
    //copy(sk[:], s.Sk[:32])
    //sk,err := EDKGDecryptSk(s.Sk)
    //if err != nil {
//	return
  //  }
    
    //var tsk [32]byte
    //copy(tsk[:], s.TSk[:32])
    
    var pkfinal [32]byte
    copy(pkfinal[:], s.FinalPkBytes[:32])

    var uids [][32]byte
    for _, v := range s.IDs {
	    var tem [32]byte
	    tmp := v.Bytes()
	    copy(tem[:], tmp[:])
	    if len(v.Bytes()) < 32 {
		    l := len(v.Bytes())
		    for j := l; j < 32; j++ {
			    tem[j] = byte(0x00)
		    }
	    }
	    uids = append(uids, tem)
    }

    // [Notes]
    // 1. calculate R
    var r [32]byte
    var rTem [64]byte
    var RBytes [32]byte
    var zkR [64]byte
    var CR [32]byte
    var DR [64]byte

    rand := cryptorand.Reader
    if _, err := io.ReadFull(rand, rTem[:]); err != nil {
	    return
    }

    if s.KeyType == smpc.SR25519 {
	    ed_ristretto.ScReduce(&r, &rTem)
	    rScalar, _ := ed_ristretto.BytesReduceToScalar(r[:])
	    R := new(r255.Element).ScalarBaseMult(rScalar)

	    // 2. commit(R)
	    R.Encode(RBytes[:0])
	    CR, DR, err = ed.Commit(RBytes)
	    if err != nil {
		    return
	    }

	    // 3. zkSchnorr(rU1)
	    zkR,err = ed_ristretto.Prove2(r,RBytes)
	    if err != nil {
		    return
	    }
    }else {
	    ed.ScReduce(&r, &rTem)

	    var R ed.ExtendedGroupElement
	    ed.GeScalarMultBase(&R, &r)

	    // 2. commit(R)
	    R.ToBytes(&RBytes)
	    CR, DR, err = ed.Commit(RBytes)
	    if err != nil {
		    return
	    }

	    // 3. zkSchnorr(rU1)
	    zkR,err = ed.Prove2(r,RBytes)
	    if err != nil {
		    return
	    }
    }

    ret := &EDSigningRound1ReturnValue{Uids:uids,Pkfinal:pkfinal,R:r,ZkR:zkR,DR:DR,CR:CR}
    b,err := json.Marshal(ret)
    if err != nil {
	return
    }

    msgmap["Ret"] = string(b)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------------------

type EDSigningRound4ReturnValue struct {
    FinalRBytes [32]byte
    S [32]byte
    SBBytes [32]byte
    CSB [32]byte
    DSB [64]byte
}

func HandleEDSigningRound4Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDSigningRound4Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    var FinalRBytes [32]byte

    if s.KeyType == smpc.SR25519 {
	    FinalR := new(r255.Element)
	    for k := range s.CRs {
		    CRFlag := ed.Verify(s.CRs[k], s.DRs[k])
		    if !CRFlag {
			msgmap["Msg4CheckRes"] = "FALSE"
			str, err := json.Marshal(msgmap)
			if err != nil {
			    return
			}

			socket.Write(conn,string(str))
			return
		    }

		    var temR [32]byte
		    copy(temR[:], (s.DRs[k])[32:])

		    zkRFlag := ed_ristretto.VerifyZk2(s.ZkRs[k], temR)
		    if !zkRFlag {
			msgmap["Msg4CheckRes"] = "FALSE"
			str, err := json.Marshal(msgmap)
			if err != nil {
			    return
			}

			socket.Write(conn,string(str))
			return
		    }

		    var temRBytes [32]byte
		    copy(temRBytes[:], (s.DRs[k])[32:])
		    temR2 := new(r255.Element)
		    temR2.Decode(temRBytes[:])
		    
		    if k == 0 {
			    FinalR = temR2
		    } else {
			    FinalR = new(r255.Element).Add(FinalR, temR2)
		    }
	    }
	    FinalR.Encode(FinalRBytes[:0])
    } else {
	    var FinalR, temR2 ed.ExtendedGroupElement
	    for k := range s.CRs {
		    CRFlag := ed.Verify(s.CRs[k], s.DRs[k])
		    if !CRFlag {
			msgmap["Msg4CheckRes"] = "FALSE"
			str, err := json.Marshal(msgmap)
			if err != nil {
			    return
			}

			socket.Write(conn,string(str))
			return
		    }

		    var temR [32]byte
		    copy(temR[:], (s.DRs[k])[32:])

		    zkRFlag := ed.VerifyZk2(s.ZkRs[k], temR)
		    if !zkRFlag {
			msgmap["Msg4CheckRes"] = "FALSE"
			str, err := json.Marshal(msgmap)
			if err != nil {
			    return
			}

			socket.Write(conn,string(str))
			return
		    }

		    var temRBytes [32]byte
		    copy(temRBytes[:], (s.DRs[k])[32:])
		    temR2.FromBytes(&temRBytes)
		    if k == 0 {
			    FinalR = temR2
		    } else {
			    ed.GeAdd(&FinalR, &FinalR, &temR2)
		    }
	    }
	    FinalR.ToBytes(&FinalRBytes)
    }

    k, err := tsslib.CalKValue(s.KeyType, s.Message, s.Pkfinal[:], FinalRBytes[:])
    if err != nil {
	return
    }

    // 2.7 calculate lambda1
    var lambda [32]byte
    lambda[0] = 1
    order := ed.GetBytesOrder()

    var curByte [32]byte
    copy(curByte[:], s.CurDNodeID.Bytes())

    for kk, vv := range s.IdSign {
	    if kk == s.Index {
		    continue
	    }

	    var indexByte [32]byte
	    copy(indexByte[:], vv.Bytes())

	    var time [32]byte
	    t := indexByte //round.temp.uids[oldindex]
	    tt := curByte  //round.temp.uids[cur_oldindex]

	    if s.KeyType == smpc.SR25519 {
		    ed_ristretto.ScSub(&time, &t, &tt)
		    time = ed_ristretto.ScModInverse(time)
	    }else {
		    ed.ScSub(&time, &t, &tt)
		    time = ed.ScModInverse(time, order)
	    }

	    count := 0
	    for index:=0;index<32;index++ {
		if time[index] == byte('0') {
		    count++
		}
	    }
	    if count == 32 {
		return
	    }

	    if s.KeyType == smpc.SR25519 {
		    ed_ristretto.ScMul(&time, &time, &t)
		    ed_ristretto.ScMul(&lambda, &lambda, &time)
	    }else {
		    ed.ScMul(&time, &time, &t)
		    ed.ScMul(&lambda, &lambda, &time)
	    }
    }

    var s2 [32]byte
    var sBBytes [32]byte

    tsk,err := EDKGDecryptTSk(s.TSk)
    if err != nil {
	return
    }

    if s.KeyType == smpc.SR25519 {
	    ed_ristretto.ScMul(&s2, &lambda, &tsk)
	    //stmp := hex.EncodeToString(s2[:])
	    ed_ristretto.ScMul(&s2, &s2, &k)
	    ed_ristretto.ScAdd(&s2, &s2, &s.R)

	    // 2.9 calculate sBBytes
	    var sScalar = new(r255.Scalar)
	    sScalar.Decode(s2[:])
	    sB := new(r255.Element).ScalarBaseMult(sScalar)
	    sB.Encode(sBBytes[:0])
    }else {
	    ed.ScMul(&s2, &lambda, &tsk)

	    //stmp := hex.EncodeToString(s2[:])
	    ed.ScMul(&s2, &s2, &k)
	    ed.ScAdd(&s2, &s2, &s.R)

	    // 2.9 calculate sBBytes
	    var sB ed.ExtendedGroupElement
	    ed.GeScalarMultBase(&sB, &s2)
	    sB.ToBytes(&sBBytes)
    }

    // 2.10 commit(sBBytes)
    CSB, DSB,err := ed.Commit(sBBytes)
    if err != nil {
	return
    }

    ret := &EDSigningRound4ReturnValue{FinalRBytes:FinalRBytes,S:s2,SBBytes:sBBytes,CSB:CSB,DSB:DSB}
    b,err := json.Marshal(ret)
    if err != nil {
	return
    }

    msgmap["Ret"] = string(b)
    msgmap["Msg4CheckRes"] = "TRUE"
    
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//------------------------------------------------

func HandleEDSigningRound6Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDSigningRound6Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    var sBBytes2 [32]byte

    if s.KeyType == smpc.SR25519 {
	    sB2 := new(r255.Element)

	    for k := range s.CSBs {
		    CSBFlag := ed.Verify(s.CSBs[k], s.DSBs[k])
		    if !CSBFlag {
			msgmap["Msg6CheckRes"] = "FALSE"
			str, err := json.Marshal(msgmap)
			if err != nil {
			    return
			}

			socket.Write(conn,string(str))
			return
		    }

		    var temSBBytes [32]byte
		    copy(temSBBytes[:], (s.DSBs[k])[32:])
		    var temSB = new(r255.Element)
		    temSB.Decode(temSBBytes[:])

		    if k == 0 {
			    sB2 = temSB
		    } else {
			    sB2 = new(r255.Element).Add(sB2, temSB)
		    }
	    }
	    sB2.Encode(sBBytes2[:0])
    }else {
	    var sB2, temSB ed.ExtendedGroupElement
	    for k := range s.CSBs {
		    CSBFlag := ed.Verify(s.CSBs[k], s.DSBs[k])
		    if !CSBFlag {
			msgmap["Msg6CheckRes"] = "FALSE"
			str, err := json.Marshal(msgmap)
			if err != nil {
			    return
			}

			socket.Write(conn,string(str))
			return
		    }

		    var temSBBytes [32]byte
		    copy(temSBBytes[:], (s.DSBs[k])[32:])
		    temSB.FromBytes(&temSBBytes)

		    if k == 0 {
			    sB2 = temSB
		    } else {
			    ed.GeAdd(&sB2, &sB2, &temSB)
		    }
	    }
	    sB2.ToBytes(&sBBytes2)
    }

    k2, err := tsslib.CalKValue(s.KeyType,s.Message,s.Pkfinal[:], s.FinalRBytes[:])
    if err != nil {
	    return
    }

    // 3.6 calculate sBCal
    var sBCalBytes [32]byte

    if s.KeyType == smpc.SR25519 {
	    var FinalR2 = new(r255.Element)
	    var sBCal = new(r255.Element) 
	    var FinalPkB = new(r255.Element)
	    var k2Scalar = new(r255.Scalar)
	    k2Scalar.Decode(k2[:])

	    FinalR2.Decode(s.FinalRBytes[:])
	    FinalPkB.Decode(s.Pkfinal[:])
	    sBCal = new(r255.Element).ScalarMult(k2Scalar, FinalPkB)
	    sBCal = new(r255.Element).Add(sBCal, FinalR2)

	    sBCal.Encode(sBCalBytes[:0])
    }else {
	    var FinalR2, sBCal, FinalPkB ed.ExtendedGroupElement
	    FinalR2.FromBytes(&s.FinalRBytes)
	    FinalPkB.FromBytes(&s.Pkfinal)
	    ed.GeScalarMult(&sBCal, &k2, &FinalPkB)
	    ed.GeAdd(&sBCal, &sBCal, &FinalR2)

	    sBCal.ToBytes(&sBCalBytes)
    }

    // 3.7 verify equation
    if !bytes.Equal(sBBytes2[:], sBCalBytes[:]) {
	msgmap["Msg6CheckRes"] = "FALSE"
    } else {
	msgmap["Msg6CheckRes"] = "TRUE"
    }

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//--------------------------------------------------

func HandleEDSigningRound7Msg(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.EDSigningRound7Msg{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType

    var FinalS [32]byte
    for k := range s.S {
	    var t [32]byte
	    copy(t[:], (s.S[k])[:])

	    if s.KeyType == smpc.SR25519 {
		    ed_ristretto.ScAdd(&FinalS, &FinalS, &t)
	    }else {
		    ed.ScAdd(&FinalS, &FinalS, &t)
	    }
    }

    inputVerify := signing.InputVerify{KeyType: s.KeyType, FinalR: s.FinalRBytes, FinalS: FinalS, Message: []byte(s.Message), FinalPk: s.Pkfinal}

    var pass = signing.EdVerify(inputVerify, s.KeyType)
    if !pass {
	msgmap["EDRSVCheckRes"] = "FALSE"
	str, err := json.Marshal(msgmap)
	if err != nil {
	    return
	}

	socket.Write(conn,string(str))
	return
    } else {
	msgmap["EDRSVCheckRes"] = "TRUE"
    }

    //r
    if s.KeyType == smpc.SR25519 {
	    FinalS[31] |= 128
    }
    msgmap["FinalS"] = hex.EncodeToString(FinalS[:])
    
    rx := hex.EncodeToString(s.FinalRBytes[:])
    sx := hex.EncodeToString(FinalS[:])
   
    log.Info("=================ed signing successfully,rsv verify pass==================","r",rx,"s",sx,"keyID",s.Base.MsgPrex)

    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//-----------------------------------------------------

//ec round1 private data
//u1
func EncryptU1(u1 *big.Int) (string,error) {
    s := fmt.Sprintf("%v", u1)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptU1(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    u1,_ := new(big.Int).SetString(s,10)
    return u1,nil
}

//u1Poly
func EncryptU1Poly(u1Poly *ec2.PolyStruct2) (string,error) {
    tmp := make([]string, len(u1Poly.Poly))
    for k, v := range u1Poly.Poly {
	    tmp[k] = fmt.Sprintf("%v", v)
    }

    s := strings.Join(tmp, ":")
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptU1Poly(cm string) (*ec2.PolyStruct2,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    ugd := strings.Split(s, ":")
    u1gd := make([]*big.Int, len(ugd))
    for k, v := range ugd {
	    u1gd[k], _ = new(big.Int).SetString(v, 10)
	    if u1gd[k] == nil {
		return nil,errors.New("get data error")
	    }
    }
    u1Poly := &ec2.PolyStruct2{Poly: u1gd}
    return u1Poly,nil
}

//PrivateKey
func EncryptPaillierSk(paiSk *ec2.PrivateKey) (string,error) {
    b,err := paiSk.MarshalJSON()
    if err != nil {
	return "",err
    }

    return TeeKmsEncrypt(string(b)) //TODO
}

func  DecryptPaillierSk(cm string) (*ec2.PrivateKey,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    paisk := &ec2.PrivateKey{} 
    err = paisk.UnmarshalJSON([]byte(s))
    if err != nil {
	return nil,err
    }

    return paisk,nil
}

//P Q
func EncryptP(p *big.Int) (string,error) {
    s := fmt.Sprintf("%v", p)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptP(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    p,_ := new(big.Int).SetString(s,10)
    return p,nil
}

func EncryptQ(q *big.Int) (string,error) {
    s := fmt.Sprintf("%v", q)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptQ(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    q,_ := new(big.Int).SetString(s,10)
    return q,nil
}

// ec round2 private data 
// ByteHash bytehash type define
type ByteHash [32]byte

// Hex hash to hex string
func (h ByteHash) Hex() string { return hexutil.Encode(h[:]) }

func Keccak256Hash(data ...[]byte) (h ByteHash) {
    	if data == nil {
	    return h
	}

	d := sha3.NewKeccak256()
	for _, b := range data {
		_, err := d.Write(b)
		if err != nil {
			return h
		}
		if err != nil {
			return h
		}
	}
	d.Sum(h[:0])
	return h
}

func EncryptShare(share *big.Int,enode string) (string,error) {
    s := fmt.Sprintf("%v", share)
    //TODO

    /*cm,err := tsslib.EncryptMsg(s,enode)
    if err != nil {
	return "",err
    }

    hash := Keccak256Hash([]byte(strings.ToLower(cm))).Hex()
    log.Info("================EncryptShare================","share",share,"enode",enode,"hash",hash)
    return cm,nil*/
    return s,nil
}

func  DecryptShare(cm string,keyfile string) (*big.Int,error) {
    /*hash := Keccak256Hash([]byte(strings.ToLower(cm))).Hex()
    log.Info("===============DecryptShare=================","hash",hash,"keyfile",keyfile)
    s,err := tsslib.DecryptMsg(cm,keyfile)
    if err != nil {
	return nil,err
    }

    share,_ := new(big.Int).SetString(s,10)
    return share,nil*/

    //TODO
    share,_ := new(big.Int).SetString(cm,10)
    return share,nil
}

//sku1
func EncryptSk(sku1 *big.Int) (string,error) {
    s := fmt.Sprintf("%v", sku1)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptSk(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    p,_ := new(big.Int).SetString(s,10)
    return p,nil
}

//NtildePrivData
func EncryptNtildePrivData(priv *ec2.NtildePrivData) (string,error) {
    b,err := json.Marshal(priv)
    if err != nil {
	return "",err
    }

    return TeeKmsEncrypt(string(b)) //TODO
}

func  DecryptNtildePrivData(cm string) (*ec2.NtildePrivData,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    priv := &ec2.NtildePrivData{} 
    err = json.Unmarshal([]byte(s),priv)
    if err != nil {
	return nil,err
    }

    return priv,nil
}

//p1 p2
func EncryptP1(p *big.Int) (string,error) {
    s := fmt.Sprintf("%v", p)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptP1(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    p,_ := new(big.Int).SetString(s,10)
    return p,nil
}

func EncryptP2(q *big.Int) (string,error) {
    s := fmt.Sprintf("%v", q)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptP2(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    q,_ := new(big.Int).SetString(s,10)
    return q,nil
}

//w1
func EncryptW1(w1 *big.Int) (string,error) {
    s := fmt.Sprintf("%v", w1)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptW1(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    w1,_ := new(big.Int).SetString(s,10)
    return w1,nil
}

//u1K
func EncryptU1K(u1K *big.Int) (string,error) {
    s := fmt.Sprintf("%v", u1K)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptU1K(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    u1K,_ := new(big.Int).SetString(s,10)
    return u1K,nil
}

//u1Gamma
func EncryptU1Gamma(u1Gamma *big.Int) (string,error) {
    s := fmt.Sprintf("%v", u1Gamma)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptU1Gamma(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    u1Gamma,_ := new(big.Int).SetString(s,10)
    return u1Gamma,nil
}

//BetaU1Star
func EncryptBetaU1Star(betau1star *big.Int) (string,error) {
    s := fmt.Sprintf("%v",betau1star)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptBetaU1Star(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    betau1star,_ := new(big.Int).SetString(s,10)
    return betau1star,nil
}

//BetaU1
func EncryptBetaU1(betau1 *big.Int) (string,error) {
    s := fmt.Sprintf("%v",betau1)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptBetaU1(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    betau1,_ := new(big.Int).SetString(s,10)
    return betau1,nil
}

//VU1Star
func EncryptVU1Star(vu1star *big.Int) (string,error) {
    s := fmt.Sprintf("%v",vu1star)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptVU1Star(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    vu1star,_ := new(big.Int).SetString(s,10)
    return vu1star,nil
}

//VU1
func EncryptVU1(vu1 *big.Int) (string,error) {
    s := fmt.Sprintf("%v",vu1)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptVU1(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    vu1,_ := new(big.Int).SetString(s,10)
    return vu1,nil
}

//L1
func EncryptL1(l1 *big.Int) (string,error) {
    s := fmt.Sprintf("%v",l1)
    return TeeKmsEncrypt(s) //TODO
}

func  DecryptL1(cm string) (*big.Int,error) {
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return nil,err
    }

    l1,_ := new(big.Int).SetString(s,10)
    return l1,nil
}

//ed kg sk
func EDKGEncryptSk(sk [32]byte) (string,error) {
    s := hex.EncodeToString(sk[:])
    return TeeKmsEncrypt(s) //TODO
}

func  EDKGDecryptSk(cm string) ([32]byte,error) {
    var ret [32]byte
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return ret,err
    }

    var tmp []byte
    tmp,err = hex.DecodeString(s)
    if err != nil {
	return ret,err
    }
    var sk [32]byte
    copy(sk[:],tmp[:])

    return sk,nil
}

//ed kg tsk
func EDKGEncryptTSk(tsk [32]byte) (string,error) {
    s := hex.EncodeToString(tsk[:])
    return TeeKmsEncrypt(s) //TODO
}

func  EDKGDecryptTSk(cm string) ([32]byte,error) {
    var ret [32]byte
    s,err := TeeKmsDecrypt(cm) //TODO
    if err != nil {
	return ret,err
    }

    var tmp []byte
    tmp,err = hex.DecodeString(s)
    if err != nil {
	return ret,err
    }
    var tsk [32]byte
    copy(tsk[:],tmp[:])

    return tsk,nil
}

//---------------------------------------------------

func EncryptBigInt(n *big.Int,enode string) (string,error) {
    s := fmt.Sprintf("%v", n)
    //TODO
    return s,nil
}

func  DecryptBigInt(cm string,keyfile string) (*big.Int,error) {
    //TODO
    n,_ := new(big.Int).SetString(cm,10)
    return n,nil
}

func EncryptByte32(t [32]byte,enode string) (string,error) {
    s := hex.EncodeToString(t[:])
    return s,nil //TODO
}

func  DecryptByte32(cm string,keyfile string) ([32]byte,error) {
    //TODO
    var ret [32]byte
    var tmp []byte
    tmp,err := hex.DecodeString(cm)
    if err != nil {
	return ret,err
    }
    var t [32]byte
    copy(t[:],tmp[:])

    return t,nil
}

//-------------------------------------

func EncryptMtARangeProof(n *ec2.MtARangeProof,enode string) (*ec2.MtARangeProof,error) {
    zenc,err := EncryptBigInt(n.Z,enode)
    if err != nil {
	return nil,err
    }
    
    uenc,err := EncryptBigInt(n.U,enode)
    if err != nil {
	return nil,err
    }
    
    wenc,err := EncryptBigInt(n.W,enode)
    if err != nil {
	return nil,err
    }
    
    senc,err := EncryptBigInt(n.S,enode)
    if err != nil {
	return nil,err
    }
    
    s1enc,err := EncryptBigInt(n.S1,enode)
    if err != nil {
	return nil,err
    }
    
    s2enc,err := EncryptBigInt(n.S2,enode)
    if err != nil {
	return nil,err
    }

    ret := &ec2.MtARangeProof{
	Z:new(big.Int).SetBytes([]byte(zenc)),
	U:new(big.Int).SetBytes([]byte(uenc)),
	W:new(big.Int).SetBytes([]byte(wenc)),
	S:new(big.Int).SetBytes([]byte(senc)),
	S1:new(big.Int).SetBytes([]byte(s1enc)),
	S2:new(big.Int).SetBytes([]byte(s2enc)),
    }

    return ret,nil
}

func  DecryptMtARangeProof(n *ec2.MtARangeProof,keyfile string) (*ec2.MtARangeProof,error) {
    z,err := DecryptBigInt(string(n.Z.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    u,err := DecryptBigInt(string(n.U.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    w,err := DecryptBigInt(string(n.W.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s,err := DecryptBigInt(string(n.S.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s1,err := DecryptBigInt(string(n.S1.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s2,err := DecryptBigInt(string(n.S2.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    ret := &ec2.MtARangeProof{
	Z:z,
	U:u,
	W:w,
	S:s,
	S1:s1,
	S2:s2,
    }

    return ret,nil
}

//MtARespZKProof
func EncryptMtARespZKProof(n *ec2.MtARespZKProof,enode string) (*ec2.MtARespZKProof,error) {
    zenc,err := EncryptBigInt(n.Z,enode)
    if err != nil {
	return nil,err
    }
    
    zbarenc,err := EncryptBigInt(n.ZBar,enode)
    if err != nil {
	return nil,err
    }
    
    tenc,err := EncryptBigInt(n.T,enode)
    if err != nil {
	return nil,err
    }
    
    venc,err := EncryptBigInt(n.V,enode)
    if err != nil {
	return nil,err
    }
    
    wenc,err := EncryptBigInt(n.W,enode)
    if err != nil {
	return nil,err
    }
    
    senc,err := EncryptBigInt(n.S,enode)
    if err != nil {
	return nil,err
    }
    
    s1enc,err := EncryptBigInt(n.S1,enode)
    if err != nil {
	return nil,err
    }
    
    s2enc,err := EncryptBigInt(n.S2,enode)
    if err != nil {
	return nil,err
    }

    t1enc,err := EncryptBigInt(n.T1,enode)
    if err != nil {
	return nil,err
    }
    
    t2enc,err := EncryptBigInt(n.T2,enode)
    if err != nil {
	return nil,err
    }

    ret := &ec2.MtARespZKProof{
	Z:new(big.Int).SetBytes([]byte(zenc)),
	ZBar:new(big.Int).SetBytes([]byte(zbarenc)),
	T:new(big.Int).SetBytes([]byte(tenc)),
	V:new(big.Int).SetBytes([]byte(venc)),
	W:new(big.Int).SetBytes([]byte(wenc)),
	S:new(big.Int).SetBytes([]byte(senc)),
	S1:new(big.Int).SetBytes([]byte(s1enc)),
	S2:new(big.Int).SetBytes([]byte(s2enc)),
	T1:new(big.Int).SetBytes([]byte(t1enc)),
	T2:new(big.Int).SetBytes([]byte(t2enc)),
    }

    return ret,nil
}

func  DecryptMtARespZKProof(n *ec2.MtARespZKProof,keyfile string) (*ec2.MtARespZKProof,error) {
    z,err := DecryptBigInt(string(n.Z.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    zbar,err := DecryptBigInt(string(n.ZBar.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    t,err := DecryptBigInt(string(n.T.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    v,err := DecryptBigInt(string(n.V.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    w,err := DecryptBigInt(string(n.W.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s,err := DecryptBigInt(string(n.S.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s1,err := DecryptBigInt(string(n.S1.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s2,err := DecryptBigInt(string(n.S2.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    t1,err := DecryptBigInt(string(n.T1.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    t2,err := DecryptBigInt(string(n.T2.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    ret := &ec2.MtARespZKProof{
	Z:z,
	ZBar:zbar,
	T:t,
	V:v,
	W:w,
	S:s,
	S1:s1,
	S2:s2,
	T1:t1,
	T2:t2,
    }

    return ret,nil
}

//MtAwcRespZKProof
func EncryptMtAwcRespZKProof(n *ec2.MtAwcRespZKProof,enode string) (*ec2.MtAwcRespZKProof,error) {
    uxenc,err := EncryptBigInt(n.Ux,enode)
    if err != nil {
	return nil,err
    }
    
    uyenc,err := EncryptBigInt(n.Uy,enode)
    if err != nil {
	return nil,err
    }
    
    zenc,err := EncryptBigInt(n.Z,enode)
    if err != nil {
	return nil,err
    }
    
    zbarenc,err := EncryptBigInt(n.ZBar,enode)
    if err != nil {
	return nil,err
    }
    
    tenc,err := EncryptBigInt(n.T,enode)
    if err != nil {
	return nil,err
    }
    
    venc,err := EncryptBigInt(n.V,enode)
    if err != nil {
	return nil,err
    }
    
    wenc,err := EncryptBigInt(n.W,enode)
    if err != nil {
	return nil,err
    }
    
    senc,err := EncryptBigInt(n.S,enode)
    if err != nil {
	return nil,err
    }
    
    s1enc,err := EncryptBigInt(n.S1,enode)
    if err != nil {
	return nil,err
    }
    
    s2enc,err := EncryptBigInt(n.S2,enode)
    if err != nil {
	return nil,err
    }

    t1enc,err := EncryptBigInt(n.T1,enode)
    if err != nil {
	return nil,err
    }
    
    t2enc,err := EncryptBigInt(n.T2,enode)
    if err != nil {
	return nil,err
    }

    ret := &ec2.MtAwcRespZKProof{
	Ux:new(big.Int).SetBytes([]byte(uxenc)),
	Uy:new(big.Int).SetBytes([]byte(uyenc)),
	Z:new(big.Int).SetBytes([]byte(zenc)),
	ZBar:new(big.Int).SetBytes([]byte(zbarenc)),
	T:new(big.Int).SetBytes([]byte(tenc)),
	V:new(big.Int).SetBytes([]byte(venc)),
	W:new(big.Int).SetBytes([]byte(wenc)),
	S:new(big.Int).SetBytes([]byte(senc)),
	S1:new(big.Int).SetBytes([]byte(s1enc)),
	S2:new(big.Int).SetBytes([]byte(s2enc)),
	T1:new(big.Int).SetBytes([]byte(t1enc)),
	T2:new(big.Int).SetBytes([]byte(t2enc)),
    }

    return ret,nil
}

func  DecryptMtAwcRespZKProof(n *ec2.MtAwcRespZKProof,keyfile string) (*ec2.MtAwcRespZKProof,error) {
    ux,err := DecryptBigInt(string(n.Ux.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    uy,err := DecryptBigInt(string(n.Uy.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    z,err := DecryptBigInt(string(n.Z.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    zbar,err := DecryptBigInt(string(n.ZBar.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    t,err := DecryptBigInt(string(n.T.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    v,err := DecryptBigInt(string(n.V.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    w,err := DecryptBigInt(string(n.W.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s,err := DecryptBigInt(string(n.S.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s1,err := DecryptBigInt(string(n.S1.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    s2,err := DecryptBigInt(string(n.S2.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    t1,err := DecryptBigInt(string(n.T1.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    t2,err := DecryptBigInt(string(n.T2.Bytes()),keyfile)
    if err != nil {
	return nil,err
    }
    
    ret := &ec2.MtAwcRespZKProof{
	Ux:ux,
	Uy:uy,
	Z:z,
	ZBar:zbar,
	T:t,
	V:v,
	W:w,
	S:s,
	S1:s1,
	S2:s2,
	T1:t1,
	T2:t2,
    }

    return ret,nil
}




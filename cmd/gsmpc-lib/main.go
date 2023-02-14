package main

import (
    "fmt"
    "io"
    "net"
    //"time"
    "flag"
    "github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
    "strings"
    "math/big"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
    "encoding/json"
    "github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
    "github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
    "github.com/anyswap/FastMulThreshold-DSA/log"
)

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
    case "KGRound1Msg":
	    HandleKGRound1Msg(conn,msgmap["Content"])
	    break
    case "KGRound2Msg2":
	    HandleKGRound2Msg2(conn,msgmap["Content"])
	    break
    case "IdsVss":
	    HandleIdsVss(conn,msgmap["Content"])
	    break
    case "KGRound3Msg":
	    HandleKGRound3Msg(conn,msgmap["Content"])
	    break
    case "KGRound4VssCheck":
	    HandleKGRound4VssCheck(conn,msgmap["Content"])
	    break
    case "KGRound4DeCom":
	    HandleKGRound4DeCom(conn,msgmap["Content"])
	    break
    case "KGRound4DeCom2":
	    HandleKGRound4DeCom2(conn,msgmap["Content"])
	    break
    case "KGRound4XiCom":
	    HandleKGRound4XiCom(conn,msgmap["Content"])
	    break
    case "KGRound4Msg":
	    HandleKGRound4Msg(conn,msgmap["Content"])
	    break
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
    default:
	    return
    }
}

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

func main() {
    clientip := flag.String("ip", "", "client ip to dial") // --ip
    clientport := flag.String("port", "", "client port to dial") // --port
    flag.Parse()
    if *clientip == "" || *clientport == "" {
	log.Error("===============ip/port param error============")
	return
    }

    cli := *clientip + ":" + *clientport
    socket.ServerAddress = cli

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

//-------------------------------------------

type PolyShare struct {
    Shares []*ec2.ShareStruct2
}

//-------------------------------------------

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
    msgmap["U1"] = fmt.Sprintf("%v", u1)
    tmp := make([]string, len(u1Poly.Poly))
    for k, v := range u1Poly.Poly {
	    tmp[k] = fmt.Sprintf("%v", v)
    }
    msgmap["U1Poly"] = strings.Join(tmp, ":")

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
    tmp = make([]string, len(commitU1G.D))
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

    b,err := u1PaillierSk.MarshalJSON()
    if err != nil {
	log.Error("==============socket server,KGRound1 paillier sk marshal error====================","err",err)
	return 
    }
    msgmap["U1PaillierSk"] = string(b)

    pk, err := u1PaillierPk.MarshalJSON()
    if err != nil {
	log.Error("==============socket server,KGRound1 paillier pk marshal error====================","err",err)
	return
    }
    msgmap["U1PaillierPk"] = string(pk)

    msgmap["P"] = fmt.Sprintf("%v", p)
    msgmap["Q"] = fmt.Sprintf("%v", q)
    //

    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("==============socket server,KGRound1 message1 marshal error====================","err",err)
	return
    }

    log.Info("===========socket server,write msg to client===========","msg",string(str))
    socket.Write(conn,string(str))
}

//-----------------------------------------

func HandleKGRound2Msg2(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.KGRound2Msg2{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    num := ec2.MustGetRandomInt(s.PaillierSkNLen)
    if num == nil {
	log.Error("==============socket server,get random int====================","msg",content)
	return
    }

    sfProof := ec2.SquareFreeProve(s.PaillierSkN,num,s.PaillierSkL)
    if sfProof == nil {
	log.Error("==============socket server,get square free prove====================","msg",content)
	return
    }

    msgmap := make(map[string]string)
    msgmap["Key"] = s.MsgPrex
    msgmap["KeyType"] = s.KeyType
    msgmap["Num"] = fmt.Sprintf("%v",num)
    sf,err := sfProof.MarshalJSON()
    if err != nil {
       return 
    }
    msgmap["SfPf"] = string(sf)

    str, err := json.Marshal(msgmap)
    if err != nil {
	log.Error("==============socket server,marshal KGRound22 error====================","msg",content,"err",err)
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleIdsVss(conn net.Conn,content string) {
    if content == "" {
	return
    }

    s:= &socket.IdsVss{}
    err := s.ToObj([]byte(content))
    if err != nil {
	return
    }
    
    dul,err := ec2.ContainsDuplicate(s.Ids)
    if err != nil || dul {
	log.Error("================socket server,contain dup ids","err",err)
	return
    }

    u1Poly := &ec2.PolyStruct2{Poly: s.U1Poly}
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
    
    ushare := &ec2.ShareStruct2{ID: s.ID, Share: s.Share}
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
    
    ushare := &ec2.ShareStruct2{ID: s.ID, Share: s.Share}

    deCommit := &ec2.Commitment{C: s.C, D: s.D}
    _, u1G := deCommit.DeCommit(s.KeyType)
    msgmap["PKX"] = fmt.Sprintf("%v", u1G[0])
    msgmap["PKY"] = fmt.Sprintf("%v", u1G[1])
    msgmap["C"] = fmt.Sprintf("%v", s.Msg21C)
    msgmap["SKU1"] = fmt.Sprintf("%v", ushare.Share)
    str, err := json.Marshal(msgmap)
    if err != nil {
	return
    }

    socket.Write(conn,string(str))
}

//---------------------------------------------------

func HandleKGRound4DeCom2(conn net.Conn,content string) {
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

    ushare := &ec2.ShareStruct2{ID: s.ID, Share: s.Share}
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

    pMinus1 := new(big.Int).Sub(s.P1, big.NewInt(1))
    qMinus1 := new(big.Int).Sub(s.P2, big.NewInt(1))
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

    hvProof := ec2.HvProve(s.Ntilde,num,s.P1,s.P2)
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

    // add prove for xi 
    u1zkXiProof := ec2.ZkXiProve(s.KeyType,s.Sk)
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
    w1 := new(big.Int).Mul(lambda1, s.SkU1)
    w1 = new(big.Int).Mod(w1, secp256k1.S256(s.KeyType).N1())
    msgmap["W1"] = fmt.Sprintf("%v",w1)

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

    msgmap["U1K"] = fmt.Sprintf("%v",u1K)
    msgmap["U1Gamma"] = fmt.Sprintf("%v",u1Gamma)

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

    u1KCipher, u1R, _ := s.U1PaillierPk.Encrypt(s.U1K)

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

    u1u1MtAZK1Proof := ec2.MtARangeProofProve(s.KeyType,s.UKC,s.U1K, s.UKC2, s.U1PaiPK, s.U1Nt)
    pf,err := json.Marshal(u1u1MtAZK1Proof)
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

    u1rlt1 := s.MtAZK1Proof.MtARangeProofVerify(s.KeyType,s.KC, s.PaiPk,s.Nt)
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
	    betaU1Star[i] = beta1U1Star
	    betaU1[i] = beta1U1
    }

    vU1Star := make([]*big.Int, s.ThresHold)
    vU1 := make([]*big.Int, s.ThresHold)
    for i := 0; i < s.ThresHold; i++ {
	    v1U1Star := random.GetRandomIntFromZn(NSubN2)
	    v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
	    vU1Star[i] = v1U1Star
	    vU1[i] = v1U1
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
    
    u1KGamma1Cipher := s.CurPaiPk.HomoMul(s.KC, s.U1Gamma)
    beta1U1StarCipher, u1BetaR1, _ := s.CurPaiPk.Encrypt(s.BetaStar)
    u1KGamma1Cipher = s.CurPaiPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher)
    u1u1MtAZK2Proof := ec2.MtARespZKProofProve(s.KeyType,s.U1Gamma, s.BetaStar, u1BetaR1, s.UKC, u1KGamma1Cipher,s.OldPaiPk, s.OldNt)

    msgmap["U1KGamma1Cipher"] = fmt.Sprintf("%v",u1KGamma1Cipher)
    pf,err := json.Marshal(u1u1MtAZK2Proof)
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
    
    u1Kw1Cipher := s.CurPaiPk.HomoMul(s.KC, s.W1)
    v1U1StarCipher, u1VR1, _ := s.CurPaiPk.Encrypt(s.VU1Star)
    u1Kw1Cipher = s.CurPaiPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
    u1u1MtAZK3Proof := ec2.MtAwcRespZKProofProve(s.KeyType,s.W1, s.VU1Star, u1VR1, s.UKC,u1Kw1Cipher,s.OldPaiPk, s.OldNt)
    pf,err := json.Marshal(u1u1MtAZK3Proof)
    if err != nil {
	return
    }

    msgmap["MtAZK3Proof"] = string(pf)
    msgmap["Kw1Cipher"] = fmt.Sprintf("%v",u1Kw1Cipher)
    
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

    b := s.MtAZK2Proof.MtARespZKProofVerify(s.KeyType,s.UKC, s.Clipher, s.PaiPk,s.Nt)
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

    b := s.MtAZK3Proof.MtAwcRespZKProofVefify(s.KeyType,xG,s.UKC,s.Cipher, s.PaiPk,s.Nt)
    if !b {
	msgmap["ComCheck"] = "FALSE"
    } else {
	msgmap["ComCheck"] = "TRUE"
    }
    
    alpha1U1, _ := s.PaiSk.Decrypt(s.U1KGamma1Cipher)
    u1U1, _ := s.PaiSk.Decrypt(s.Cipher)
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
	    delta1 = new(big.Int).Add(delta1, s.BetaU1[i])
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
	    sigma1 = new(big.Int).Add(sigma1, s.VU1[i])
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

    msgmap["l1"] = fmt.Sprintf("%v",l1)

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
    
    u1GammaZKProof := ec2.ZkUProve(s.KeyType,s.U1Gamma)
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

    // gg20: compute ZK proof of consistency between R_i and E_i(k_i) 
    bigRK1Gx,bigRK1Gy := secp256k1.S256(s.KeyType).ScalarMult(deltaGammaGx,deltaGammaGy,s.U1K.Bytes())

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
    pdlWSlackWitness := &ec2.PDLwSlackWitness{
	    SK: s.PaiSk,
	    K1: s.U1K,
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

    stProof := ec2.NewSTProof(s.KeyType,s.T1X,s.T1Y,S1X,S1Y,s.DeltaGammaGx,s.DeltaGammaGy,hx,hy,s.Sigma1,s.L1)
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
    
    mk1 := new(big.Int).Mul(s.TxHash, s.K1)
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




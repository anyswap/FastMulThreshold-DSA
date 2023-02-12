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



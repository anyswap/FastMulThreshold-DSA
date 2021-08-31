
/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  haijun.cai@anyswap.exchange
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

package smpc

import (
	"os"
	"github.com/fsn-dev/cryptoCoins/coins"
	cryptocoinsconfig "github.com/fsn-dev/cryptoCoins/coins/config"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	p2psmpc "github.com/anyswap/Anyswap-MPCNode/p2p/layer2"
	smpclibec2 "github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
)

var (
	cur_enode  string
	init_times = 0
	recalc_times = 1 
	KeyFile    string
)

func init() {
	p2psmpc.RegisterRecvCallback(Call2)
	p2psmpc.SdkProtocol_registerBroadcastInGroupCallback(Call)
	p2psmpc.RegisterCallback(Call)

	RegP2pGetGroupCallBack(p2psmpc.SdkProtocol_getGroup)
	RegP2pSendToGroupAllNodesCallBack(p2psmpc.SdkProtocol_SendToGroupAllNodes)
	RegP2pGetSelfEnodeCallBack(p2psmpc.GetSelfID)
	RegP2pBroadcastInGroupOthersCallBack(p2psmpc.SdkProtocol_broadcastInGroupOthers)
	RegP2pSendMsgToPeerCallBack(p2psmpc.SendMsgToPeer)
	RegP2pParseNodeCallBack(p2psmpc.ParseNodeID)
	RegSmpcGetEosAccountCallBack(eos.GetEosAccount)
	InitChan()
}

//------------------------------------------------------------------------

type LunchParams struct {
    WaitMsg uint64
    TryTimes uint64
    PreSignNum uint64
    WaitAgree uint64
    Bip32Pre uint64
}

func Start(params *LunchParams) {
   
	cryptocoinsconfig.Init()
	coins.Init()
	
	cur_enode = p2psmpc.GetSelfID()
	
	go smpclibec2.GenRandomSafePrime()
	
	common.Info("======================smpc.Start======================","cache",cache,"handles",handles,"cur enode",cur_enode)
	err := StartSmpcLocalDb()
	if err != nil {
	    info := "======================smpc.Start," + err.Error() + ",so terminate smpc node startup"
	    common.Error(info)
	    os.Exit(1)
	    return
	}

	common.Info("======================smpc.Start,open all db success======================","cur_enode",cur_enode)
	
	PrePubDataCount = int(params.PreSignNum)
	WaitMsgTimeGG20 = int(params.WaitMsg)
	recalc_times = int(params.TryTimes)
	waitallgg20 = WaitMsgTimeGG20 * recalc_times
	WaitAgree = int(params.WaitAgree)
	PreBip32DataCount = int(params.Bip32Pre)
	
	AutoPreGenSignData()

	go HandleRpcSign()

	common.Info("================================smpc.Start,init finish.========================","cur_enode",cur_enode,"waitmsg",WaitMsgTimeGG20,"trytimes",recalc_times,"presignnum",PrePubDataCount,"bip32pre",PreBip32DataCount)
}




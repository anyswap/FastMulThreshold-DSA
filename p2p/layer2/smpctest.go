/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  huangweijun@anyswap.exchange
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

package layer2

import (
	"fmt"
	"time"
)

//call define
func call(msg interface{}) <-chan string {
	fmt.Printf("\nsmpc call: msg = %v\n", msg)
	ch := make(chan string, 800)
	return ch
}

func smpccall(msg interface{}) <-chan string {
	ch := make(chan string, 800)
	fmt.Printf("\nsmpc smpccall: msg=%v\n", msg)
	smpccallMsg := fmt.Sprintf("%v smpccall", msg)
	SmpcProtocol_broadcastInGroupOthers(smpccallMsg) // without self
	ch <- msg.(string)
	return ch
}

func smpccallret(msg interface{}) {
	fmt.Printf("smpc smpccallret: msg=%v\n", msg)
}

func main() {
	fmt.Printf("\n\nSMPC P2P test ...\n\n")
	SmpcProtocol_registerRecvCallback(call) // <- Smpcrotocol_broadcastToGroup(smpccallMsg)
	SmpcProtocol_registerMsgRecvCallback(smpccall)
	SmpcProtocol_registerMsgRetCallback(smpccallret)

	time.Sleep(time.Duration(10) * time.Second)

	//select {} // note for server, or for client

	var num int = 0
	for {
		fmt.Printf("\nSendToSmpcGroup ...\n")
		num += 1
		msg := fmt.Sprintf("%+v test SendToSmpcGroup ...", num)
		SmpcProtocol_sendToGroupOneNode(msg) // -> Handle: SmpcProtocol_registerCallback(call)
		// -> *msg Handle: SmpcProtocol_registerMsgRecvCallback(smpccall)
		//    SmpcProtocol_registerMsgRetCallback(smpccallret) <- SmpcProtocol_registerMsgRecvCallback(smpccall)
		time.Sleep(time.Duration(2) * time.Second)
	}
	select {}
}

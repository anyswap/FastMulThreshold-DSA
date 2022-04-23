/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
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
	"container/list"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"runtime/debug"
	"strings"
)

var (
    	// RPCReqQueueCache the queue of RPCReq
	RPCReqQueueCache = make(chan RPCReq, RPCMaxQueue)

	// RPCMaxWorker  max worker nums
	RPCMaxWorker = 10000

	// RPCMaxQueue max counts of RPCReq in queue
	RPCMaxQueue  = 10000

	// RPCReqQueue the channel of RPCReq
	RPCReqQueue  chan RPCReq

	// workers the array of worker
	workers      []*RPCReqWorker
)

//------------------------------------------------------------------------------

// InitChan init workers,RpcReqQueue,ReqDispatcher and start the worker.
func InitChan() {
	workers = make([]*RPCReqWorker, RPCMaxWorker)
	RPCReqQueue = make(chan RPCReq, RPCMaxQueue)
	reqdispatcher := NewReqDispatcher(RPCMaxWorker)
	reqdispatcher.Run()
}

//-----------------------------------------------------------------------------------------

// RPCReq rpc req or p2p data
type RPCReq struct {
	rpcdata WorkReq
	ch      chan interface{}
}

// ReqDispatcher worker pool
type ReqDispatcher struct {
	// A pool of workers channels that are registered with the dispatcher
	WorkerPool chan chan RPCReq
}

// NewReqDispatcher new a worker pool.
func NewReqDispatcher(maxWorkers int) *ReqDispatcher {
	pool := make(chan chan RPCReq, maxWorkers)
	return &ReqDispatcher{WorkerPool: pool}
}

// Run start the worker
func (d *ReqDispatcher) Run() {
	// starting n number of workers
	for i := 0; i < RPCMaxWorker; i++ {
		worker := NewRPCReqWorker(d.WorkerPool)
		worker.id = i
		workers[i] = worker
		worker.Start()
	}

	go d.dispatch()
}

// dispatch received a job request and dispatch it to the worker job channel.
func (d *ReqDispatcher) dispatch() {
	for {
		select {
		case req := <-RPCReqQueue:
			// a job request has been received
			go func(req RPCReq) {
				// try to obtain a worker job channel that is available.
				// this will block until a worker is idle
				reqChannel := <-d.WorkerPool

				// dispatch the job to the worker job channel
				reqChannel <- req
			}(req)
		}
	}

}

//-------------------------------------------------------------------------------------

// RPCReqWorker worker
type RPCReqWorker struct {
	RPCReqWorkerPool chan chan RPCReq
	RPCReqChannel    chan RPCReq
	rpcquit          chan bool
	id               int
	groupid          string
	limitnum         string
	SmpcFrom         string
	NodeCnt          int
	ThresHold        int
	sid              string //save the key
	approved         bool
	//
	msgacceptreqaddrres *list.List
	msgacceptreshareres *list.List
	msgacceptsignres    *list.List

	msgsyncpresign    *list.List
	msgc1             *list.List
	msgkc             *list.List
	msgmkg            *list.List
	msgmkw            *list.List
	msgdelta1         *list.List
	msgd1d1           *list.List
	msgshare1         *list.List
	msgzkfact         *list.List
	msgzku            *list.List
	msgbip32c1        *list.List
	msgmtazk1proof    *list.List
	msgc11            *list.List
	msgd11d1          *list.List
	msgcommitbigvab   *list.List
	msgzkabproof      *list.List
	msgcommitbigut    *list.List
	msgcommitbigutd11 *list.List
	msgss1            *list.List
	msgpaillierkey    *list.List

	rsv    *list.List
	pkx    *list.List
	pky    *list.List
	save   *list.List
	sku1   *list.List
	bip32c *list.List

	bacceptreqaddrres chan bool
	bacceptreshareres chan bool
	bacceptsignres    chan bool
	bsendreshareres   chan bool
	bsendsignres      chan bool
	bsyncpresign      chan bool
	bc1               chan bool
	bmkg              chan bool
	bmkw              chan bool
	bdelta1           chan bool
	bd1d1             chan bool
	bshare1           chan bool
	bzkfact           chan bool
	bzku              chan bool
	bbip32c1          chan bool
	bmtazk1proof      chan bool
	bkc               chan bool
	bcommitbigvab     chan bool
	bzkabproof        chan bool
	bcommitbigut      chan bool
	bcommitbigutd11   chan bool
	bss1              chan bool
	bpaillierkey      chan bool
	bc11              chan bool
	bd11d1            chan bool

	//ed
	bedc11       chan bool
	msgedc11    *list.List
	bedzk        chan bool
	msgedzk     *list.List
	bedd11       chan bool
	msgedd11    *list.List
	bedshare1    chan bool
	msgedshare1 *list.List
	bedcfsb      chan bool
	msgedcfsb   *list.List
	edsave       *list.List
	edsku1       *list.List
	edpk         *list.List

	bedc21    chan bool
	msgedc21 *list.List
	bedzkr    chan bool
	msgedzkr *list.List
	bedd21    chan bool
	msgedd21 *list.List
	bedc31    chan bool
	msgedc31 *list.List
	bedd31    chan bool
	msgedd31 *list.List
	beds      chan bool
	msgeds   *list.List

	acceptReqAddrChan     chan string
	acceptWaitReqAddrChan chan string
	acceptReShareChan     chan string
	acceptWaitReShareChan chan string
	acceptSignChan        chan string
	acceptWaitSignChan    chan string

	//for smpc lib
	SmpcMsg        chan string
	DNode          smpclib.DNode
	MsgToEnode     map[string]string
	PreSaveSmpcMsg []string
	Msg2Peer []string
	ApprovReplys []*ApprovReply
	Msg56     map[string]bool
}

// NewRPCReqWorker new a RPCReqWorker
func NewRPCReqWorker(workerPool chan chan RPCReq) *RPCReqWorker {
	return &RPCReqWorker{
		RPCReqWorkerPool:     workerPool,
		RPCReqChannel:        make(chan RPCReq),
		rpcquit:              make(chan bool),
		msgshare1:           list.New(),
		msgzkfact:           list.New(),
		msgzku:              list.New(),
		msgbip32c1:          list.New(),
		msgmtazk1proof:      list.New(),
		msgc1:               list.New(),
		msgd1d1:             list.New(),
		msgc11:              list.New(),
		msgkc:               list.New(),
		msgmkg:              list.New(),
		msgmkw:              list.New(),
		msgdelta1:           list.New(),
		msgd11d1:            list.New(),
		msgcommitbigvab:     list.New(),
		msgzkabproof:        list.New(),
		msgcommitbigut:      list.New(),
		msgcommitbigutd11:   list.New(),
		msgss1:              list.New(),
		msgpaillierkey:      list.New(),
		msgacceptreqaddrres: list.New(),
		msgacceptreshareres: list.New(),
		msgacceptsignres:    list.New(),
		msgsyncpresign:      list.New(),

		rsv:    list.New(),
		pkx:    list.New(),
		pky:    list.New(),
		save:   list.New(),
		sku1:   list.New(),
		bip32c: list.New(),

		bacceptreqaddrres: make(chan bool, 1),
		bacceptreshareres: make(chan bool, 1),
		bacceptsignres:    make(chan bool, 1),
		bsendreshareres:   make(chan bool, 1),
		bsendsignres:      make(chan bool, 1),
		bsyncpresign:      make(chan bool, 1),
		bc1:               make(chan bool, 1),
		bd1d1:             make(chan bool, 1),
		bc11:              make(chan bool, 1),
		bkc:               make(chan bool, 1),
		bcommitbigvab:     make(chan bool, 1),
		bzkabproof:        make(chan bool, 1),
		bcommitbigut:      make(chan bool, 1),
		bcommitbigutd11:   make(chan bool, 1),
		bss1:              make(chan bool, 1),
		bpaillierkey:      make(chan bool, 1),
		bmkg:              make(chan bool, 1),
		bmkw:              make(chan bool, 1),
		bshare1:           make(chan bool, 1),
		bzkfact:           make(chan bool, 1),
		bzku:              make(chan bool, 1),
		bbip32c1:          make(chan bool, 1),
		bmtazk1proof:      make(chan bool, 1),
		bdelta1:           make(chan bool, 1),
		bd11d1:            make(chan bool, 1),

		//ed
		bedc11:       make(chan bool, 1),
		msgedc11:    list.New(),
		bedzk:        make(chan bool, 1),
		msgedzk:     list.New(),
		bedd11:       make(chan bool, 1),
		msgedd11:    list.New(),
		bedshare1:    make(chan bool, 1),
		msgedshare1: list.New(),
		bedcfsb:      make(chan bool, 1),
		msgedcfsb:   list.New(),
		edsave:       list.New(),
		edsku1:       list.New(),
		edpk:         list.New(),
		bedc21:       make(chan bool, 1),
		msgedc21:    list.New(),
		bedzkr:       make(chan bool, 1),
		msgedzkr:    list.New(),
		bedd21:       make(chan bool, 1),
		msgedd21:    list.New(),
		bedc31:       make(chan bool, 1),
		msgedc31:    list.New(),
		bedd31:       make(chan bool, 1),
		msgedd31:    list.New(),
		beds:         make(chan bool, 1),
		msgeds:      list.New(),

		sid:       "",
		approved:      false,
		NodeCnt:   5,
		ThresHold: 5,

		acceptReqAddrChan:     make(chan string, 1),
		acceptWaitReqAddrChan: make(chan string, 1),

		acceptReShareChan:     make(chan string, 1),
		acceptWaitReShareChan: make(chan string, 1),
		acceptSignChan:        make(chan string, 1),
		acceptWaitSignChan:    make(chan string, 1),

		SmpcMsg:        make(chan string, 100),
		MsgToEnode:     make(map[string]string),
		PreSaveSmpcMsg: make([]string, 0),
		Msg2Peer: make([]string, 0),
		ApprovReplys: make([]*ApprovReply, 0),
		Msg56:     make(map[string]bool),
	}
}

// Clear  reset RPCReqWorker object 
func (w *RPCReqWorker) Clear() {

	common.Debug("======================RpcReqWorker.Clear======================", "w.id", w.id, "w.groupid", w.groupid, "key", w.sid)

	w.sid = ""
	w.approved = false
	w.groupid = ""
	w.limitnum = ""
	w.SmpcFrom = ""
	w.NodeCnt = 5
	w.ThresHold = 5

	var next *list.Element

	for e := w.msgacceptreshareres.Front(); e != nil; e = next {
		next = e.Next()
		w.msgacceptreshareres.Remove(e)
	}

	for e := w.msgacceptsignres.Front(); e != nil; e = next {
		next = e.Next()
		w.msgacceptsignres.Remove(e)
	}

	for e := w.msgacceptreqaddrres.Front(); e != nil; e = next {
		next = e.Next()
		w.msgacceptreqaddrres.Remove(e)
	}

	for e := w.msgsyncpresign.Front(); e != nil; e = next {
		next = e.Next()
		w.msgsyncpresign.Remove(e)
	}

	for e := w.msgc1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgc1.Remove(e)
	}

	for e := w.msgkc.Front(); e != nil; e = next {
		next = e.Next()
		w.msgkc.Remove(e)
	}

	for e := w.msgmkg.Front(); e != nil; e = next {
		next = e.Next()
		w.msgmkg.Remove(e)
	}

	for e := w.msgmkw.Front(); e != nil; e = next {
		next = e.Next()
		w.msgmkw.Remove(e)
	}

	for e := w.msgdelta1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgdelta1.Remove(e)
	}

	for e := w.msgd1d1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgd1d1.Remove(e)
	}

	for e := w.msgshare1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgshare1.Remove(e)
	}

	for e := w.msgzkfact.Front(); e != nil; e = next {
		next = e.Next()
		w.msgzkfact.Remove(e)
	}

	for e := w.msgzku.Front(); e != nil; e = next {
		next = e.Next()
		w.msgzku.Remove(e)
	}

	for e := w.msgbip32c1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgbip32c1.Remove(e)
	}

	for e := w.msgmtazk1proof.Front(); e != nil; e = next {
		next = e.Next()
		w.msgmtazk1proof.Remove(e)
	}

	for e := w.msgc11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgc11.Remove(e)
	}

	for e := w.msgd11d1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgd11d1.Remove(e)
	}

	for e := w.msgcommitbigvab.Front(); e != nil; e = next {
		next = e.Next()
		w.msgcommitbigvab.Remove(e)
	}

	for e := w.msgzkabproof.Front(); e != nil; e = next {
		next = e.Next()
		w.msgzkabproof.Remove(e)
	}

	for e := w.msgcommitbigut.Front(); e != nil; e = next {
		next = e.Next()
		w.msgcommitbigut.Remove(e)
	}

	for e := w.msgcommitbigutd11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgcommitbigutd11.Remove(e)
	}

	for e := w.msgss1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgss1.Remove(e)
	}

	for e := w.msgpaillierkey.Front(); e != nil; e = next {
		next = e.Next()
		w.msgpaillierkey.Remove(e)
	}

	for e := w.pkx.Front(); e != nil; e = next {
		next = e.Next()
		w.pkx.Remove(e)
	}

	for e := w.bip32c.Front(); e != nil; e = next {
		next = e.Next()
		w.bip32c.Remove(e)
	}

	for e := w.pky.Front(); e != nil; e = next {
		next = e.Next()
		w.pky.Remove(e)
	}

	for e := w.save.Front(); e != nil; e = next {
		next = e.Next()
		w.save.Remove(e)
	}

	for e := w.sku1.Front(); e != nil; e = next {
		next = e.Next()
		w.sku1.Remove(e)
	}

	for e := w.rsv.Front(); e != nil; e = next {
		next = e.Next()
		w.rsv.Remove(e)
	}

	if len(w.rpcquit) == 1 {
		<-w.rpcquit
	}
	if len(w.bshare1) == 1 {
		<-w.bshare1
	}
	if len(w.bzkfact) == 1 {
		<-w.bzkfact
	}
	if len(w.bzku) == 1 {
		<-w.bzku
	}
	if len(w.bbip32c1) == 1 {
		<-w.bbip32c1
	}
	if len(w.bmtazk1proof) == 1 {
		<-w.bmtazk1proof
	}
	if len(w.bacceptreshareres) == 1 {
		<-w.bacceptreshareres
	}
	if len(w.bacceptsignres) == 1 {
		<-w.bacceptsignres
	}
	if len(w.bsendreshareres) == 1 {
		<-w.bsendreshareres
	}
	if len(w.bsendsignres) == 1 {
		<-w.bsendsignres
	}
	if len(w.bsyncpresign) == 1 {
		<-w.bsyncpresign
	}
	if len(w.bacceptreqaddrres) == 1 {
		<-w.bacceptreqaddrres
	}
	if len(w.bc1) == 1 {
		<-w.bc1
	}
	if len(w.bd1d1) == 1 {
		<-w.bd1d1
	}
	if len(w.bc11) == 1 {
		<-w.bc11
	}
	if len(w.bkc) == 1 {
		<-w.bkc
	}
	if len(w.bcommitbigvab) == 1 {
		<-w.bcommitbigvab
	}
	if len(w.bzkabproof) == 1 {
		<-w.bzkabproof
	}
	if len(w.bcommitbigut) == 1 {
		<-w.bcommitbigut
	}
	if len(w.bcommitbigutd11) == 1 {
		<-w.bcommitbigutd11
	}
	if len(w.bss1) == 1 {
		<-w.bss1
	}
	if len(w.bpaillierkey) == 1 {
		<-w.bpaillierkey
	}
	if len(w.bmkg) == 1 {
		<-w.bmkg
	}
	if len(w.bmkw) == 1 {
		<-w.bmkw
	}
	if len(w.bdelta1) == 1 {
		<-w.bdelta1
	}
	if len(w.bd11d1) == 1 {
		<-w.bd11d1
	}

	//ed
	if len(w.bedc11) == 1 {
		<-w.bedc11
	}
	for e := w.msgedc11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedc11.Remove(e)
	}

	if len(w.bedzk) == 1 {
		<-w.bedzk
	}
	for e := w.msgedzk.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedzk.Remove(e)
	}
	if len(w.bedd11) == 1 {
		<-w.bedd11
	}
	for e := w.msgedd11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedd11.Remove(e)
	}
	if len(w.bedshare1) == 1 {
		<-w.bedshare1
	}
	for e := w.msgedshare1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedshare1.Remove(e)
	}
	if len(w.bedcfsb) == 1 {
		<-w.bedcfsb
	}
	for e := w.msgedcfsb.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedcfsb.Remove(e)
	}
	for e := w.edsave.Front(); e != nil; e = next {
		next = e.Next()
		w.edsave.Remove(e)
	}
	for e := w.edsku1.Front(); e != nil; e = next {
		next = e.Next()
		w.edsku1.Remove(e)
	}
	for e := w.edpk.Front(); e != nil; e = next {
		next = e.Next()
		w.edpk.Remove(e)
	}

	if len(w.bedc21) == 1 {
		<-w.bedc21
	}
	for e := w.msgedc21.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedc21.Remove(e)
	}
	if len(w.bedzkr) == 1 {
		<-w.bedzkr
	}
	for e := w.msgedzkr.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedzkr.Remove(e)
	}
	if len(w.bedd21) == 1 {
		<-w.bedd21
	}
	for e := w.msgedd21.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedd21.Remove(e)
	}
	if len(w.bedc31) == 1 {
		<-w.bedc31
	}
	for e := w.msgedc31.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedc31.Remove(e)
	}
	if len(w.bedd31) == 1 {
		<-w.bedd31
	}
	for e := w.msgedd31.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedd31.Remove(e)
	}
	if len(w.beds) == 1 {
		<-w.beds
	}
	for e := w.msgeds.Front(); e != nil; e = next {
		next = e.Next()
		w.msgeds.Remove(e)
	}

	if len(w.acceptWaitReqAddrChan) == 1 {
		<-w.acceptWaitReqAddrChan
	}
	if len(w.acceptReqAddrChan) == 1 {
		<-w.acceptReqAddrChan
	}
	if len(w.acceptReShareChan) == 1 {
		<-w.acceptReShareChan
	}
	if len(w.acceptSignChan) == 1 {
		<-w.acceptSignChan
	}
	if len(w.acceptWaitSignChan) == 1 {
		<-w.acceptWaitSignChan
	}

	w.SmpcMsg = make(chan string, 100)
	w.DNode = nil
	w.MsgToEnode = make(map[string]string)
	w.PreSaveSmpcMsg = make([]string, 0)
	w.Msg2Peer = make([]string, 0)
	w.ApprovReplys = make([]*ApprovReply, 0)
	w.Msg56 = make(map[string]bool)
}

// Clear2  reset RPCReqWorker object in some elements 
func (w *RPCReqWorker) Clear2() {
	common.Debug("======================RpcReqWorker.Clear2======================", "w.id", w.id, "w.groupid", w.groupid, "key", w.sid)

	var next *list.Element

	for e := w.msgacceptreshareres.Front(); e != nil; e = next {
		next = e.Next()
		w.msgacceptreshareres.Remove(e)
	}

	for e := w.msgacceptsignres.Front(); e != nil; e = next {
		next = e.Next()
		w.msgacceptsignres.Remove(e)
	}

	for e := w.msgacceptreqaddrres.Front(); e != nil; e = next {
		next = e.Next()
		w.msgacceptreqaddrres.Remove(e)
	}

	for e := w.msgsyncpresign.Front(); e != nil; e = next {
		next = e.Next()
		w.msgsyncpresign.Remove(e)
	}

	for e := w.msgc1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgc1.Remove(e)
	}

	for e := w.msgkc.Front(); e != nil; e = next {
		next = e.Next()
		w.msgkc.Remove(e)
	}

	for e := w.msgmkg.Front(); e != nil; e = next {
		next = e.Next()
		w.msgmkg.Remove(e)
	}

	for e := w.msgmkw.Front(); e != nil; e = next {
		next = e.Next()
		w.msgmkw.Remove(e)
	}

	for e := w.msgdelta1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgdelta1.Remove(e)
	}

	for e := w.msgd1d1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgd1d1.Remove(e)
	}

	for e := w.msgshare1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgshare1.Remove(e)
	}

	for e := w.msgzkfact.Front(); e != nil; e = next {
		next = e.Next()
		w.msgzkfact.Remove(e)
	}

	for e := w.msgzku.Front(); e != nil; e = next {
		next = e.Next()
		w.msgzku.Remove(e)
	}

	for e := w.msgbip32c1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgbip32c1.Remove(e)
	}

	for e := w.msgmtazk1proof.Front(); e != nil; e = next {
		next = e.Next()
		w.msgmtazk1proof.Remove(e)
	}

	for e := w.msgc11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgc11.Remove(e)
	}

	for e := w.msgd11d1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgd11d1.Remove(e)
	}

	for e := w.msgcommitbigvab.Front(); e != nil; e = next {
		next = e.Next()
		w.msgcommitbigvab.Remove(e)
	}

	for e := w.msgzkabproof.Front(); e != nil; e = next {
		next = e.Next()
		w.msgzkabproof.Remove(e)
	}

	for e := w.msgcommitbigut.Front(); e != nil; e = next {
		next = e.Next()
		w.msgcommitbigut.Remove(e)
	}

	for e := w.msgcommitbigutd11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgcommitbigutd11.Remove(e)
	}

	for e := w.msgss1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgss1.Remove(e)
	}

	for e := w.msgpaillierkey.Front(); e != nil; e = next {
		next = e.Next()
		w.msgpaillierkey.Remove(e)
	}

	for e := w.pkx.Front(); e != nil; e = next {
		next = e.Next()
		w.pkx.Remove(e)
	}

	for e := w.bip32c.Front(); e != nil; e = next {
		next = e.Next()
		w.bip32c.Remove(e)
	}

	for e := w.pky.Front(); e != nil; e = next {
		next = e.Next()
		w.pky.Remove(e)
	}

	for e := w.save.Front(); e != nil; e = next {
		next = e.Next()
		w.save.Remove(e)
	}

	for e := w.sku1.Front(); e != nil; e = next {
		next = e.Next()
		w.sku1.Remove(e)
	}

	for e := w.rsv.Front(); e != nil; e = next {
		next = e.Next()
		w.rsv.Remove(e)
	}

	if len(w.rpcquit) == 1 {
		<-w.rpcquit
	}
	if len(w.bshare1) == 1 {
		<-w.bshare1
	}
	if len(w.bzkfact) == 1 {
		<-w.bzkfact
	}
	if len(w.bzku) == 1 {
		<-w.bzku
	}
	if len(w.bbip32c1) == 1 {
		<-w.bbip32c1
	}
	if len(w.bmtazk1proof) == 1 {
		<-w.bmtazk1proof
	}
	if len(w.bacceptreshareres) == 1 {
		<-w.bacceptreshareres
	}
	if len(w.bacceptsignres) == 1 {
		<-w.bacceptsignres
	}
	if len(w.bsendreshareres) == 1 {
		<-w.bsendreshareres
	}
	if len(w.bsendsignres) == 1 {
		<-w.bsendsignres
	}
	if len(w.bsyncpresign) == 1 {
		<-w.bsyncpresign
	}
	if len(w.bacceptreqaddrres) == 1 {
		<-w.bacceptreqaddrres
	}
	if len(w.bc1) == 1 {
		<-w.bc1
	}
	if len(w.bd1d1) == 1 {
		<-w.bd1d1
	}
	if len(w.bc11) == 1 {
		<-w.bc11
	}
	if len(w.bkc) == 1 {
		<-w.bkc
	}
	if len(w.bcommitbigvab) == 1 {
		<-w.bcommitbigvab
	}
	if len(w.bzkabproof) == 1 {
		<-w.bzkabproof
	}
	if len(w.bcommitbigut) == 1 {
		<-w.bcommitbigut
	}
	if len(w.bcommitbigutd11) == 1 {
		<-w.bcommitbigutd11
	}
	if len(w.bss1) == 1 {
		<-w.bss1
	}
	if len(w.bpaillierkey) == 1 {
		<-w.bpaillierkey
	}
	if len(w.bmkg) == 1 {
		<-w.bmkg
	}
	if len(w.bmkw) == 1 {
		<-w.bmkw
	}
	if len(w.bdelta1) == 1 {
		<-w.bdelta1
	}
	if len(w.bd11d1) == 1 {
		<-w.bd11d1
	}

	//ed
	if len(w.bedc11) == 1 {
		<-w.bedc11
	}
	for e := w.msgedc11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedc11.Remove(e)
	}

	if len(w.bedzk) == 1 {
		<-w.bedzk
	}
	for e := w.msgedzk.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedzk.Remove(e)
	}
	if len(w.bedd11) == 1 {
		<-w.bedd11
	}
	for e := w.msgedd11.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedd11.Remove(e)
	}
	if len(w.bedshare1) == 1 {
		<-w.bedshare1
	}
	for e := w.msgedshare1.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedshare1.Remove(e)
	}
	if len(w.bedcfsb) == 1 {
		<-w.bedcfsb
	}
	for e := w.msgedcfsb.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedcfsb.Remove(e)
	}
	for e := w.edsave.Front(); e != nil; e = next {
		next = e.Next()
		w.edsave.Remove(e)
	}
	for e := w.edsku1.Front(); e != nil; e = next {
		next = e.Next()
		w.edsku1.Remove(e)
	}
	for e := w.edpk.Front(); e != nil; e = next {
		next = e.Next()
		w.edpk.Remove(e)
	}

	if len(w.bedc21) == 1 {
		<-w.bedc21
	}
	for e := w.msgedc21.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedc21.Remove(e)
	}
	if len(w.bedzkr) == 1 {
		<-w.bedzkr
	}
	for e := w.msgedzkr.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedzkr.Remove(e)
	}
	if len(w.bedd21) == 1 {
		<-w.bedd21
	}
	for e := w.msgedd21.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedd21.Remove(e)
	}
	if len(w.bedc31) == 1 {
		<-w.bedc31
	}
	for e := w.msgedc31.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedc31.Remove(e)
	}
	if len(w.bedd31) == 1 {
		<-w.bedd31
	}
	for e := w.msgedd31.Front(); e != nil; e = next {
		next = e.Next()
		w.msgedd31.Remove(e)
	}
	if len(w.beds) == 1 {
		<-w.beds
	}
	for e := w.msgeds.Front(); e != nil; e = next {
		next = e.Next()
		w.msgeds.Remove(e)
	}

	if len(w.acceptWaitReqAddrChan) == 1 {
		<-w.acceptWaitReqAddrChan
	}
	if len(w.acceptReqAddrChan) == 1 {
		<-w.acceptReqAddrChan
	}
	if len(w.acceptReShareChan) == 1 {
		<-w.acceptReShareChan
	}
	if len(w.acceptSignChan) == 1 {
		<-w.acceptSignChan
	}
	if len(w.acceptWaitSignChan) == 1 {
		<-w.acceptWaitSignChan
	}

	w.SmpcMsg = make(chan string, 100)
	w.DNode = nil
	w.MsgToEnode = make(map[string]string)
	w.PreSaveSmpcMsg = make([]string, 0)
	w.Msg2Peer = make([]string, 0)
	w.ApprovReplys = make([]*ApprovReply, 0)
	w.Msg56 = make(map[string]bool)
}

// Start start the worker
// register the current worker into the worker queue.
// get job from channel and run!
// reset the worker object or stop the work.
func (w *RPCReqWorker) Start() {
	go func() {

		for {
			// register the current worker into the worker queue.
			w.RPCReqWorkerPool <- w.RPCReqChannel
			select {
			case req := <-w.RPCReqChannel:
				req.rpcdata.Run(w.id, req.ch)
				w.Clear()

			case <-w.rpcquit:
				// we have received a signal to stop
				return
			}
		}
	}()
}

// Stop stop the work
func (w *RPCReqWorker) Stop() {
	go func() {
		w.rpcquit <- true
	}()
}

//----------------------------------------------------------------------------

// [start,end)

// mid := (end - start) / 2
// left = [start,start + mid)
// right = [start + mid,end)
func find(sid string,start int,end int) int {

    if end - start == 1 {
	w := workers[start]
	if w.sid != "" {
	    if strings.EqualFold(w.sid, sid) {
		   return start
	    }
	}

	return -1
    }

    mid := (end - start) / 2
    
    id := find(sid,start,start + mid)
    if id != -1 {
	return id
    }

    return find(sid,start + mid,end)
}

// FindWorker find worker by sid(key) that uniquely identifies the keygen/sign/reshare command 
func FindWorker(sid string) (*RPCReqWorker, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("FindWorker Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

	if sid == "" {
		return nil, fmt.Errorf("input worker id error")
	}

	id := find(sid,0,RPCMaxWorker)
	if id == -1 {
	    return nil,fmt.Errorf("not found worker by key = %v",sid)
	}

	return workers[id],nil

}

/*// FindWorker find worker by sid(key) that uniquely identifies the keygen/sign/reshare command 
func FindWorker(sid string) (*RPCReqWorker, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("FindWorker Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

	if sid == "" {
		return nil, fmt.Errorf("input worker id error")
	}

	wid := make(chan int, 1)
	var wg sync.WaitGroup
	for i := 0; i < RPCMaxWorker; i++ {
	    wg.Add(1)
	    go func(id int) {
		defer wg.Done()

		w := workers[id]
		if w.sid != "" {
		    if strings.EqualFold(w.sid, sid) {
			   wid <- id 
		    }
		}
	    }(i)
	}
	wg.Wait()

	select {
	    case id := <-wid:
		return workers[id],nil
	    default:
		return nil,fmt.Errorf("not found worker by key = %v",sid)
	}
}

// FindWorker find worker by sid(key) that uniquely identifies the keygen/sign/reshare command 
func FindWorker(sid string) (*RPCReqWorker, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("FindWorker Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

	if sid == "" {
		return nil, fmt.Errorf("input worker id error")
	}

	for i := 0; i < RPCMaxWorker; i++ {
		w := workers[i]

		if w.sid == "" {
			continue
		}

		if strings.EqualFold(w.sid, sid) {
			return w, nil
		}
	}

	return nil, fmt.Errorf(" The worker with the specified worker id was not found")
}
*/

//---------------------------------------------------------------------------------------------

// GetWorkerID get worker's id
func GetWorkerID(w *RPCReqWorker) (int, error) {
	if w == nil {
		return -1, fmt.Errorf("fail get worker id")
	}

	return w.id, nil
}



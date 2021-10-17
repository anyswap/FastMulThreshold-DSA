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

// Package smpc_test test the smpc
package smpc_test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"strconv"

	 "os/exec"
	 "strings"
	 "time"
)

const (
    	testBootNodeSh = "../bootnode-start-test.sh"
    	testKeyGenSh = "../gsmpc-keygen-test.sh"
	testSignSh = "../gsmpc-signing-test.sh"
)

/*func TestKeyGen(t *testing.T) {

    go func() {
	cmd := exec.Command("/bin/sh",testBootNodeSh,"../")
	_, err := cmd.Output()
	if err != nil {
	    t.Errorf("===================start bootnode fail, err = %v=======================\n",err)
	    return
	}
       
	t.Logf("=========================start bootnode success==========================\n")
    }()

    time.Sleep(time.Duration(20) * time.Second)
   
    succ := false
    go func() {
	port := strconv.Itoa(5871)
	cmd := exec.Command("/bin/sh",testKeyGenSh,"..",port,"","EC256K1")
	bytes, err := cmd.Output()
	if err != nil {
	    t.Errorf("===================test KeyGen fail, err = %v=======================\n",err)
	    return
	}
       
	exsit := strings.Contains(string(bytes),"pubkey generated successfully")
	if exsit {
	    succ = true
	    t.Logf("=========================test KeyGen success==========================\n")
	    return
	}

	t.Errorf("===================test KeyGen fail=======================\n")
    }()

    timeout := make(chan bool, 1)
    go func() {
	    syncWaitTime := 500 * time.Second
	    syncWaitTimeOut := time.NewTicker(syncWaitTime)

	    for {
		    select {
		    case <-syncWaitTimeOut.C:
			    timeout <- true
			    return
		    }
	    }
    }()
    <-timeout
	
    assert.True(t, succ, "success")
}
*/

func TestKeyGenAndSign(t *testing.T) {
    go func() {
	cmd := exec.Command("/bin/sh",testBootNodeSh,"../")
	bytes, err := cmd.Output()
	if err != nil {
	    t.Errorf("===================start bootnode fail, err = %v,bytes = %v=======================\n",err,string(bytes))
	    return
	}
       
	t.Logf("=========================start bootnode success==========================\n")
    }()

    time.Sleep(time.Duration(20) * time.Second)
   
    succ := false
    go func() {
	port := strconv.Itoa(5871)
	cmd := exec.Command("/bin/sh",testSignSh,"..",port,"","EC256K1")
	bytes, err := cmd.Output()
	if err != nil {
	    t.Errorf("===================test Signing fail, err = %v=======================\n",err)
	    return
	}
       
	exsit := strings.Contains(string(bytes),"the terminal sign res is success")
	if exsit {
	    succ = true
	    t.Logf("=========================test Signing success==========================\n")
	    return
	}

	t.Errorf("===================test Signing fail,bytes = %v=======================\n",string(bytes))
    }()

    timeout := make(chan bool, 1)
    go func() {
	    syncWaitTime := 570 * time.Second
	    syncWaitTimeOut := time.NewTicker(syncWaitTime)

	    for {
		    select {
		    case <-syncWaitTimeOut.C:
			    timeout <- true
			    return
		    }
	    }
    }()
    <-timeout
	
    assert.True(t, succ, "success")
}



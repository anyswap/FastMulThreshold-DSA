package client

import (
    "net"
    "sync"
    "github.com/anyswap/FastMulThreshold-DSA/internal/common"
)
 
type SocketClient struct {
    Network   string
    Address   string //for example: 127.0.0.1:8000
    OnMessage func(msg string) error
    Connect   net.Conn
    Wg        sync.WaitGroup
}
 
func (client *SocketClient) Start() error {
    
    client.Wg.Add(1)
    go HandleMessage(client)
    
    return nil
}
 
func HandleMessage(client *SocketClient) {
    var buffer [4096]byte
    
    defer client.Wg.Done()
    
    for true {
	readcount, err := client.Connect.Read(buffer[:])
	if err != nil {
	    common.Error("read msg from server err","err",err)
	    break
	}

	msg := string(buffer[:readcount])
	if client.OnMessage(msg) != nil {
	    break
	}
    }
}



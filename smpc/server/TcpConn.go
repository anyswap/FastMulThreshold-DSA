package server
 
import (
    "net"
    "strings"
    "time"
    "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
    "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
)
 
//client connection,one connect,one TcpConn
type TcpConn struct {
    Id       string   //client id
    Connect  net.Conn
    Server   *SocketServer
    LastTime int64 //the last time for communication
}
 
func MakeClient(connnect net.Conn, server *SocketServer) *TcpConn {
    client := &TcpConn{
	    Id:       connnect.RemoteAddr().String(),
	    Connect:  connnect,
	    Server:   server,
	    LastTime: time.Now().Unix(),
    }
    return client
}
 
func (conn *TcpConn) HandleMessage(msg string) {
}

//----------------------------------------------------



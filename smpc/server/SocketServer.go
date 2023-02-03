package server
 
import (
    "fmt"
    "net"
    "sync"
    "time"
)
 
type SocketServer struct {
    Network             string
    Address             string                            //for example 127.0.0.1:8000
    Clients             map[string]*TcpConn         
    ClientTimeOutSecond int64                             //client timeout,close the client when not recieving msg in N seconds
    MaxClientNum        int                              
    CurrentClientNum    int                              
    OnError             func(msg string, err error)       
    OnStart             func(server *SocketServer)        
    OnClientConnect     func(client *TcpConn)             //be called when client connecting successfully
    OnClientClose       func(client *TcpConn)             //be called when client is closed
    OnMessage           func(client *TcpConn, msg string) //recieved msg from client
}
 
func (server *SocketServer) Start() {
    listener, err := net.Listen(server.Network, server.Address)
    if err != nil {
	server.OnError("Listen fail", err)
	return
    }
    
    defer listener.Close()
    
    common.Info("socket server start successfully","network",server.Network,"address",server.Address)
    
    go server.CheckClient()

    for true {
	conn, err := listener.Accept()
	if err != nil {
		server.OnError("Accept fail", err)
		continue
	}

	if server.CurrentClientNum >= server.MaxClientNum {
	    common.Info("The maximum number of connections has been reached", "current client nums",server.CurrentClientNum)
	    conn.Close()
	    continue
	}

	client := MakeClient(conn, server)
	server.OnClientConnect(client)
	server.AddClient(client)

	var buffer [4096]byte

	readcount, err := conn.Connect.Read(buffer[:])
	if err != nil {
	    conn.Server.RemoveClient(conn)
	    conn.Server.OnError("read data error,close the connection", err)
	    break
	}
	
	conn.LastTime = time.Now().Unix()
	msg := string(buffer[:readcount])
	if msg == "" {
	    conn.Server.OnError("read data fail", nil)
	    continue
	}
	
	go client.HandleMessage(msg)
	//vs := &VSocketData{}
	//if err := vs.UnmarshalJSON([]byte(msg)); err == nil {
	//    go client.HandleMessage(vs)
	//}

    }
}
 
var mutex sync.Mutex
 
func (server *SocketServer) AddClient(client *TcpConn) {
    mutex.Lock()
    defer mutex.Unlock()
    server.Clients[client.Id] = client
    server.CurrentClientNum++
    common.Info("add client", "new client nums",server.CurrentClientNum)
}
 
func (server *SocketServer) RemoveClient(client *TcpConn) {
    mutex.Lock()
    defer mutex.Unlock()
    if _, ok := server.Clients[client.Id]; ok {
	client.Connect.Close()
	delete(server.Clients, client.Id)
	server.OnClientClose(client)
	server.CurrentClientNum--
	common.Info("remove client","new client nums", server.CurrentClientNum)
    }
}
 
func (server *SocketServer) CheckClient() {
    for true {
	    if server.ClientTimeOutSecond < 1 {
		    time.Sleep(5 * time.Second)
		    continue
	    }

	    mutex.Lock()
	    nowTime := time.Now().Unix()
	    for key, value := range server.Clients {
		    if nowTime-value.LastTime > server.ClientTimeOutSecond {
		    value.Connect.Close()
		    common.Info("remove timeout clients","key",key,"clients nums",len(server.Clients))
		    }
	    }
	    mutex.Unlock()
	    time.Sleep(5 * time.Second)
    }
}



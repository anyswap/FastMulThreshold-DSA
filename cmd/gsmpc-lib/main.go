package main
 
import (
    "fmt"
    "github.com/anyswap/FastMulThreshold-DSA/smpc/server"
)

//-----------------------------------------------------------------

func main() {
    clientip := flag.String("ip", "", "client ip to dial") // --ip
    clientport := flag.String("port", "", "client port to dial") // --port
    if *clientip == "" || *clientport == "" {
	return
    }

    cli := *clientip + ":" + *clientport

    (&server.SocketServer{
	    Network:             "tcp4",
	    Address:             cli,
	    Clients:             make(map[string]*server.TcpConn),
	    ClientTimeOutSecond: 3600,
	    MaxClientNum:        2,
	    OnError: func(msg string, err error) {
		    common.Error(msg,"err",err)
	    },
	    OnStart: func(server *server.SocketServer) {
		    common.Info("server start successfully")
	    },
	    OnClientConnect: func(client *server.TcpConn) {
		    common.Info("client connect to server successfully","client id",client.Id)
	    },
	    OnClientClose: func(client *server.TcpConn) {
		    common.Info("client connect close","client id",client.Id)
	    },
	    OnMessage: func(client *server.TcpConn, msg string) {
		    common.Info("recieved msg from client","msg",msg)
		    //client.Connect.Write([]byte("xxxx"))
	    },
    }).Start()
}



package socket 

import (
    "github.com/anyswap/FastMulThreshold-DSA/log"
    "bytes"
    "net"
    "encoding/json"
)

func Write(conn net.Conn, content string) (int, error) {
    log.Info("========socket write, send msg===========","remote addr",conn.RemoteAddr(), "content",content)
    var bytebuf bytes.Buffer
    bytebuf.WriteString(content)
    bytebuf.WriteByte(MessageDelimiter)

    bytearr := bytebuf.Bytes()
    return conn.Write(bytearr)
}

func Read(conn net.Conn) (string, error) {
    var str string
    var bytebuf bytes.Buffer
    
    bytearr := make([]byte, 1)
    
    for {
        if _, err := conn.Read(bytearr); err != nil {
            return str, err
        }

        item := bytearr[0]
        if item == MessageDelimiter {
            break
        }

        bytebuf.WriteByte(item)
    }

    str = bytebuf.String()
    log.Info("===========socket read,recv msg============", "remote addr",conn.RemoteAddr(), "str",str)
    return str, nil
}

//---------------------------------------------

func SendMsgData(conn net.Conn,msg SocketMessage) error {
    s,err := msg.ToJson()
    if err != nil {
	log.Error("===============socket.SendMsgData,socketmessage error==========","err",err)
	return err
    }

    msgmap := make(map[string]string)
    msgmap["Content"] = string(s)
    msgmap["MsgType"] = msg.GetMsgType()

    data,err := json.Marshal(msgmap)
    if err != nil {
	log.Error("===============socket.SendMsgData,msgmap error==========","err",err)
	return err
    }

    _,err = Write(conn,string(data))
    return err
}




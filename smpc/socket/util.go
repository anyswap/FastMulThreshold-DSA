package socket 

import (
    "github.com/anyswap/FastMulThreshold-DSA/log"
    "bytes"
    "net"
    "os"
    "io/ioutil"
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

//------------------------------------------------------

func WriteFile(file string,data string) error {
    var kfd *os.File
    var err error

    kfd, err = os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0600)
    if err != nil {
	f,err := os.Create(file)
	if err != nil {
	    log.Error("====================WriteFile, create file error=========================","err",err)
	    return err
	}

	 _,err = f.Write([]byte(data))
	 if err != nil {
	    f.Close()
	     return err
	 }

	f.Close()
	 return nil
    }

    _,err = kfd.WriteString(data)
    if err != nil {
	log.Error("====================WriteFile,write string error=========================","err",err)
	kfd.Close()
	return err
    }

    log.Debug("====================WriteFile,write string successfully=========================")
    kfd.Close()
    return nil
}

func ReadFile(file string) (string,error) {
    f, err := ioutil.ReadFile(file)
    if err != nil {
	return "",err
    }

    return string(f),nil
}



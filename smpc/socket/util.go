package socket 

import (
    "github.com/anyswap/FastMulThreshold-DSA/log"
    "bytes"
    "net"
    "os"
    "io/ioutil"
    "encoding/binary"
    "encoding/json"
    "github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

var (
    MSG_PREFIX = []byte("VSOCK_MSG_LEN:")
    MSG_LENGTH_PREFIX = 4
    READ_ONE_TIME_BYTES = 1024
)

func Write(conn net.Conn, content string) (int, error) {

    contentBytes := []byte(content)
    contentBytesLen := len(contentBytes)

	lengthBytes := make([]byte, MSG_LENGTH_PREFIX)
	binary.BigEndian.PutUint32(lengthBytes, uint32(contentBytesLen))

    var bytebuf bytes.Buffer
    bytebuf.Write(MSG_PREFIX)
    bytebuf.Write(lengthBytes)
    bytebuf.Write(contentBytes)

    bytearr := bytebuf.Bytes()

    log.Info("========socket write, send msg===========","remote addr",conn.RemoteAddr(), "length", contentBytesLen, "content",content)
    return conn.Write(bytearr)
}

func Read(conn net.Conn) (string, error) {
    prefixBytes := make([]byte, MSG_LENGTH_PREFIX + len(MSG_PREFIX))

    for {
        if _, err := conn.Read(prefixBytes); err != nil {
            return "", err
        }
    
        if bytes.Equal(MSG_PREFIX, prefixBytes[:len(MSG_PREFIX)]){
            break
        }
    }

    lengthBytes := prefixBytes[len(MSG_PREFIX):]
    contentBytesLen := int(binary.BigEndian.Uint32(lengthBytes))

    // read content
    var contentBuf bytes.Buffer
    temBytes := make([]byte, READ_ONE_TIME_BYTES)
    for {
        if contentBytesLen < READ_ONE_TIME_BYTES {
            break
        }
        if _, err := conn.Read(temBytes); err != nil {
            return "", err
        }
        if _, err := contentBuf.Write(temBytes); err != nil {
            return "", err
        }
        contentBytesLen -= READ_ONE_TIME_BYTES
    }
    // read left content
    temBytes = make([]byte, contentBytesLen)
    if _, err := conn.Read(temBytes); err != nil {
        return "", err
    }
    if _, err := contentBuf.Write(temBytes); err != nil {
        return "", err
    }
    str := contentBuf.String()

    log.Info("===========socket read,recv msg============", "remote addr",conn.RemoteAddr(), "length", contentBytesLen, "content",str)
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

    bytesMap := common.StringMap2BytesMap(msgmap)
    data, err := json.Marshal(bytesMap)

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

//--------------------------------------------------

func Exists(path string) bool {
    _, err := os.Stat(path)
    if err != nil {
	if os.IsExist(err) {
	    return true
	}
	
	return false
    }
    
    return true
}

func IsDir(path string) bool {
    s, err := os.Stat(path)
    if err != nil {
	return false
    }
    
    return s.IsDir()
}

func IsFile(path string) bool {
    return !IsDir(path)
}

//-------------------------------------------------------






package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/crypto"
	nitroToolkit "github.com/anyswap/nitro-toolkit"
)

// LoadECDSA loads a secp256k1 private key from the given file.
func LoadECDSA(enodeIDpriv string) (*ecdsa.PrivateKey, error) {
	key, err := hex.DecodeString(enodeIDpriv)
	if err != nil {
		return nil, err
	}

	return crypto.ToECDSA(key)
}

//TODO
func TeeKmsGetEncDataKey(keyID string) (string,string,error) {
    return "123456781234567812345678","encTEEdatakey123456781234567812345678",nil
}

func TeeKmsGetDataKey(encdatakey string)  (string,error) {
    return "123456781234567812345678",nil
}

//TODO
func TeeKmsEnc(data string,datakey string) (string,error) {
    encryptCode := AesEncrypt(data,datakey)
    return encryptCode,nil
}

//TODO
func TeeKmsDec(cm string,datakey string) (string,error) {
    decryptCode := AesDecrypt(cm,datakey)
    return decryptCode,nil
}

//TODO
type Atte struct {
    AccessKey string
    AccessSk string
    Token string
}

func TeeGetAttestation(t *Atte) (string,error) {
    return "attestation",nil
}

//--------------------------------------------------------

var (
    // simulation the tee encryption
    DATA_KEY = []byte("12345678901234567890123456789012")
)

func NitroKmsEncrypt(data string) (string,error) {
    dataBytes := []byte(data)
    cipherBytes, err := nitroToolkit.EncryptByDataKey(DATA_KEY, dataBytes)
    if err != nil {
        return "", err
    }
    return string(cipherBytes), nil
}

func NitroKmsDecrypt(cm string) (string,error) {
    cipherBytes := []byte(cm)
    dataBytes, err := nitroToolkit.DecryptByDataKey(DATA_KEY, cipherBytes)
    if err != nil {
        return "", err
    }
    return string(dataBytes), nil
}

//TODO
func TeeKmsEncrypt(data string) (string,error) {
    return data,nil
}

//TODO
func TeeKmsDecrypt(cm string) (string,error) {
    return cm,nil
}

//TODO
func GetTeeValidateData(keyID string) (string,error) {
    return "XXXXXXXX",nil
}

//TODO
func TeeCheckValidateData(keyID string,data string) (bool,error) {
    return true,nil
}



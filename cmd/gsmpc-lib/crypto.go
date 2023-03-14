package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/crypto"
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
    return "datakey","encdatakey",nil
}

func TeeKmsGetDataKey(encdatakey string)  (string,error) {
    return "datakey",nil
}

//TODO
func TeeKmsEnc(data string,datakey string) (string,error) {
    return data,nil  //TODO
}

//TODO
func TeeKmsDec(cm string,datakey string) (string,error) {
    return cm,nil  //TODO
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



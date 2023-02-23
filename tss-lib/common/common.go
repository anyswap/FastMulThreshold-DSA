package common 

import (
    "github.com/gtank/merlin"
    "crypto/sha512"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
    "crypto/ecdsa"
    "errors"
    "math/big"
    "github.com/anyswap/FastMulThreshold-DSA/crypto"
    "encoding/hex"
    "github.com/anyswap/FastMulThreshold-DSA/crypto/ecies"
    crand "crypto/rand"
)

//----------------------------------------------

const EC256K1 string = "EC256K1"
const ED25519 string = "ED25519"
const EC256STARK string = "EC256STARK"
const SR25519 string = "SR25519"

var VALID_SIG_TYPES = []string{EC256K1, ED25519, EC256STARK, SR25519}

//-------------------------------------------------

// for ed25519 and sr25519, calculate the challenge k
func CalKValue(keyType string, message, pkFinal, RFinal []byte) ([32]byte, error){
	var k [32]byte
	if keyType == SR25519 {
		transcript := merlin.NewTranscript("SigningContext")

		transcript.AppendMessage([]byte(""), []byte("substrate"))
		transcript.AppendMessage([]byte("sign-bytes"), message)
		transcript.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
		transcript.AppendMessage([]byte("sign:pk"), pkFinal)
		transcript.AppendMessage([]byte("sign:R"), RFinal)

		outK := transcript.ExtractBytes([]byte("sign:c"), 64)
		
		var kHelper [64]byte
		copy(kHelper[:], outK[:])
		ed_ristretto.ScReduce(&k, &kHelper)
	}else{
		// 2.6 calculate k=H(FinalRBytes||pk||M)
		var kDigest [64]byte

		h := sha512.New()
		_, err := h.Write(RFinal)
		if err != nil {
			return k, err
		}
		_, err = h.Write(pkFinal)
		if err != nil {
			return k, err
		}
		_, err = h.Write(message)
		if err != nil {
			return k, err
		}

		h.Sum(kDigest[:0])
		ed.ScReduce(&k, &kDigest)
	}

	return k, nil
}

//-----------------------------------------------

// EncryptMsg encrypt msg 
func EncryptMsg(msg string, enodeID string) (string, error) {
    	if msg == "" || enodeID == "" {
	    return "",errors.New("encrypt msg fail")
	}

	hprv, err1 := hex.DecodeString(enodeID)
	if err1 != nil {
		return "", err1
	}

	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(hprv) / 2
	p.X.SetBytes(hprv[:half])
	p.Y.SetBytes(hprv[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return "", errors.New("id is invalid secp256k1 curve point")
	}

	var cm []byte
	pub := ecies.ImportECDSAPublic(p)
	cm, err := ecies.Encrypt(crand.Reader, pub, []byte(msg), nil, nil)
	if err != nil {
		return "", err
	}

	return string(cm), nil
}

// DecryptMsg decrypt msg
func DecryptMsg(cm string,keyfile string) (string, error) {
    	if cm == "" {
	    return "",errors.New("decrypt msg fail")
	}

	nodeKey, errkey := crypto.LoadECDSA(keyfile)
	if errkey != nil {
		return "", errkey
	}

	prv := ecies.ImportECDSA(nodeKey)
	var m []byte
	m, err := prv.Decrypt([]byte(cm), nil, nil)
	if err != nil {
		return "", err
	}

	return string(m), nil
}

//---------------------------------------------

// TODO
func EncryptTee(data string, pub string) (string, error) {
    return data,nil
}

// TODO
func DecryptTee(cm string,priv string) (string,error) {
    return cm,nil
}

//--------------------------------------------------
 





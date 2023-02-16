package common 

import (
    "github.com/gtank/merlin"
    "crypto/sha512"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
    "github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
)

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





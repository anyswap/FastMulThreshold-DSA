
package smpc 

import (
    "math/big"
    "encoding/hex"
    //"encoding/gob"
    //"encoding/json"
    //"bytes"
    "strings"
    "fmt"
    "crypto/rand"
    "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
)

type SortableIDSSlice []*big.Int

func (s SortableIDSSlice) Len() int {
	return len(s)
}

func (s SortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s SortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

//commitment question 2
func GetRandomInt(length int) *big.Int {
	// NewInt allocates and returns a new Int set to x.
	/*one := big.NewInt(1)
	// Lsh sets z = x << n and returns z.
	maxi := new(big.Int).Lsh(one, uint(length))

	// TODO: Random Seed, need to be replace!!!
	// New returns a new Rand that uses random values from src to generate other random values.
	// NewSource returns a new pseudo-random Source seeded with the given value.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	// Rand sets z to a pseudo-random number in [0, n) and returns z.
	rndNum := new(big.Int).Rand(rnd, maxi)*/
	one := big.NewInt(1)
	maxi := new(big.Int).Lsh(one, uint(length))
	maxi = new(big.Int).Sub(maxi, one)
	rndNum, err := rand.Int(rand.Reader, maxi)
	if err != nil {
		return nil
	}

	return rndNum
}

func DECDSA_Sign_Calc_v(r, deltaGammaGy, pkx, pky, R, S *big.Int, hashBytes []byte, invert bool) int {
	//v
	recid := secp256k1.Get_ecdsa_sign_v(r, deltaGammaGy)
	if invert == true {
		recid ^= 1
	}

	////check v
	ys := secp256k1.S256().Marshal(pkx, pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
		pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(R.Bytes(), S.Bytes()...)
	for j := 0; j < 4; j++ {
		rsvBytes2 := append(rsvBytes1, byte(j))
		pkr, e := secp256k1.RecoverPubkey(hashBytes, rsvBytes2)
		pkr2 := hex.EncodeToString(pkr)
		pbhs2 := []rune(pkr2)
		if string(pbhs2[0:2]) == "0x" {
			pkr2 = string(pbhs2[2:])
		}
		if e == nil && strings.EqualFold(pkr2, pubkeyhex) {
			recid = j
			break
		}
	}
	/////

	return recid
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	// number of bits in a big.Word
	wordBits := 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes := wordBits / 8
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

func Verify2(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	z, _ := new(big.Int).SetString(message, 16)
	ss := new(big.Int).ModInverse(s, secp256k1.S256().N)
	zz := new(big.Int).Mul(z, ss)
	u1 := new(big.Int).Mod(zz, secp256k1.S256().N)

	zz2 := new(big.Int).Mul(r, ss)
	u2 := new(big.Int).Mod(zz2, secp256k1.S256().N)

	if u1.Sign() == -1 {
		u1.Add(u1, secp256k1.S256().P)
	}
	ug := make([]byte, 32)
	ReadBits(u1, ug[:])
	ugx, ugy := secp256k1.KMulG(ug[:])

	if u2.Sign() == -1 {
		u2.Add(u2, secp256k1.S256().P)
	}
	upk := make([]byte, 32)
	ReadBits(u2, upk[:])
	upkx, upky := secp256k1.S256().ScalarMult(pkx, pky, upk[:])

	xxx, _ := secp256k1.S256().Add(ugx, ugy, upkx, upky)
	xR := new(big.Int).Mod(xxx, secp256k1.S256().N)

	if xR.Cmp(r) == 0 {
		errstring := "============= ECDSA Signature Verify Passed! (r,s) is a Valid Signature ================"
		fmt.Println(errstring)
		return true
	}

	errstring := "================ @@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed! (r,s) is a InValid Siganture! ================"
	fmt.Println(errstring)
	return false
}


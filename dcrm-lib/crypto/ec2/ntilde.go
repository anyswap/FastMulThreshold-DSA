package ec2

import (
	"math/big"
	"fmt"
	"encoding/json"

	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

type NtildeH1H2 struct {
	Ntilde *big.Int
	H1     *big.Int
	H2     *big.Int
}

func GenerateNtildeH1H2(length int) *NtildeH1H2 {

	p := <-SafePrime //random.GetSafeRandomPrimeInt(length / 2)
	q := <-SafePrime //random.GetSafeRandomPrimeInt(length / 2)

	if p == nil || q == nil {
		return nil
	}

	////TODO tmp:1000-->4
	SafePrime <- p
	SafePrime <- q
	///////

	ntilde := new(big.Int).Mul(p, q)

	h1 := random.GetRandomIntFromZnStar(ntilde)
	h2 := random.GetRandomIntFromZnStar(ntilde)

	ntildeH1H2 := &NtildeH1H2{Ntilde: ntilde, H1: h1, H2: h2}

	return ntildeH1H2
}

func (ntilde *NtildeH1H2) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Ntilde string `json:"Ntilde"`
		H1 string `json:"H1"`
		H2 string `json:"H2"`
	}{
		Ntilde: fmt.Sprintf("%v",ntilde.Ntilde),
		H1: fmt.Sprintf("%v",ntilde.H1),
		H2: fmt.Sprintf("%v",ntilde.H2),
	})
}

func (ntilde *NtildeH1H2) UnmarshalJSON(raw []byte) error {
	var nti struct {
		Ntilde string `json:"Ntilde"`
		H1 string `json:"H1"`
		H2 string `json:"H2"`
	}
	if err := json.Unmarshal(raw, &nti); err != nil {
		return err
	}

	ntilde.Ntilde,_ = new(big.Int).SetString(nti.Ntilde,10)
	ntilde.H1,_ = new(big.Int).SetString(nti.H1,10)
	ntilde.H2,_ = new(big.Int).SetString(nti.H2,10)
	return nil
}


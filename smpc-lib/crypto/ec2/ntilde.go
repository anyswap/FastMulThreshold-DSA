package ec2

import (
	"math/big"
	"fmt"
	"encoding/json"

	//"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

type NtildeH1H2 struct {
	Ntilde *big.Int
	H1     *big.Int
	H2     *big.Int

	//add for ntilde zk
	//Alpha *big.Int
	//Beta *big.Int
	//P *big.Int
	//Q *big.Int
}

/*func GenerateNtildeH1H2(length int) *NtildeH1H2 {

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
}*/

func GenerateNtildeH1H2(length int) (*NtildeH1H2,*big.Int,*big.Int,*big.Int,*big.Int) {

    	sp1 := <- SafePrimeCh
    	sp2 := <- SafePrimeCh

	if sp1.p == nil || sp2.p == nil {
	    return nil,nil,nil,nil,nil
	}

	////TODO tmp:1000-->4
	SafePrimeCh <- sp1 
	SafePrimeCh <- sp2
	///////

	P, Q := sp1.SafePrime(), sp2.SafePrime()
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := ModInt(NTildei)

	p, q := sp1.Prime(), sp2.Prime()
	modPQ := ModInt(new(big.Int).Mul(p, q))
	f1 := GetRandomPositiveRelativelyPrimeInt(NTildei)
	alpha := GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.Inverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)


	ntildeH1H2 := &NtildeH1H2{Ntilde: NTildei, H1: h1i, H2: h2i}

	return ntildeH1H2,alpha,beta,p,q
}

func (ntilde *NtildeH1H2) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Ntilde string `json:"Ntilde"`
		H1 string `json:"H1"`
		H2 string `json:"H2"`
		//Alpha string `json:"Alpha"`
		//Beta string `json:"Beta"`
		//P string `json:"P"`
		//Q string `json:"Q"`
	}{
		Ntilde: fmt.Sprintf("%v",ntilde.Ntilde),
		H1: fmt.Sprintf("%v",ntilde.H1),
		H2: fmt.Sprintf("%v",ntilde.H2),
		//Alpha: fmt.Sprintf("%v",ntilde.Alpha),
		//Beta: fmt.Sprintf("%v",ntilde.Beta),
		//P: fmt.Sprintf("%v",ntilde.P),
		//Q: fmt.Sprintf("%v",ntilde.Q),
	})
}

func (ntilde *NtildeH1H2) UnmarshalJSON(raw []byte) error {
	var nti struct {
		Ntilde string `json:"Ntilde"`
		H1 string `json:"H1"`
		H2 string `json:"H2"`
		//Alpha string `json:"Alpha"`
		//Beta string `json:"Beta"`
		//P string `json:"P"`
		//Q string `json:"Q"`
	}
	if err := json.Unmarshal(raw, &nti); err != nil {
		return err
	}

	ntilde.Ntilde,_ = new(big.Int).SetString(nti.Ntilde,10)
	ntilde.H1,_ = new(big.Int).SetString(nti.H1,10)
	ntilde.H2,_ = new(big.Int).SetString(nti.H2,10)
	//ntilde.Alpha,_ = new(big.Int).SetString(nti.Alpha,10)
	//ntilde.Beta,_ = new(big.Int).SetString(nti.Beta,10)
	//ntilde.P,_ = new(big.Int).SetString(nti.P,10)
	//ntilde.Q,_ = new(big.Int).SetString(nti.Q,10)
	return nil
}


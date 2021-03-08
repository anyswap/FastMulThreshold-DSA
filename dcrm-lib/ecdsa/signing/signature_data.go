package signing 

import (
	"math/big"
	//"strings"
	//"fmt"
	//"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
)

type PrePubData struct {
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
}


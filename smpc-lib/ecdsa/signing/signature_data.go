package signing

import (
	"math/big"
	//"strings"
	//"fmt"
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
)

type PrePubData struct {
	K1     *big.Int
	R      *big.Int
	Ry     *big.Int
	Sigma1 *big.Int
}

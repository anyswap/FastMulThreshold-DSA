package signing

import (
	"math/big"
)

type PrePubData struct {
	K1     *big.Int
	R      *big.Int
	Ry     *big.Int
	Sigma1 *big.Int
}

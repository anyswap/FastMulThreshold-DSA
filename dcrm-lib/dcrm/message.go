
package dcrm 

import (
    //"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
    //"math/big"
    //"strings"
    //"fmt"
    //"strconv"
)

type Message interface {
	GetFromID() string //x,fi(x) ---> id,skui
	GetFromIndex() int
	GetToID() []string
	IsBroadcast() bool
	OutMap() map[string]string
}


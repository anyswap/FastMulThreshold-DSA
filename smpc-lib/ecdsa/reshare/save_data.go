/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package reshare

import (
	"math/big"
	//"strings"
	//"fmt"
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

type ReshareData struct {
	NewSk *big.Int
	SkU1  *big.Int
}


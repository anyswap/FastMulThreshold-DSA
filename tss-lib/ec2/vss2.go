/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  xing.chang@anyswap.exchange
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

package ec2

import (
	"math/big"
	"errors"

	s256 "github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
)

// PolyGStruct2 (x,y)
type PolyGStruct2 struct {
	PolyG [][]*big.Int //x and y
}

// PolyStruct2 coefficient set
type PolyStruct2 struct {
	Poly []*big.Int // coefficient set
}

//---------------------------------------------------

// ShareStruct2 f(xi)
type ShareStruct2 struct {
	ID    *big.Int // ID, x coordinate
	Share *big.Int
}

//-----------------------------------------------------

// GetSharesID get ID
func GetSharesID(ss *ShareStruct2) *big.Int {
	if ss != nil {
		return ss.ID
	}

	return nil
}

// Vss2Init  Initialize Lagrange polynomial coefficients 
func Vss2Init(keytype string,secret *big.Int, t int) (*PolyStruct2, *PolyGStruct2, error) {
    	if secret == nil || t <= 1 {
	    return nil,nil,errors.New("param error")
	}

	poly := make([]*big.Int, 0)
	polyG := make([][]*big.Int, 0)

	poly = append(poly, secret)
	pointX, pointY := s256.S256(keytype).ScalarBaseMult(secret.Bytes())
	polyG = append(polyG, []*big.Int{pointX, pointY})

	for i := 0; i < t-1; i++ {
		rndInt := random.GetRandomIntFromZn(s256.S256(keytype).N1())
		poly = append(poly, rndInt)

		pointX, pointY := s256.S256(keytype).ScalarBaseMult(rndInt.Bytes())
		polyG = append(polyG, []*big.Int{pointX, pointY})
	}
	polyStruct := &PolyStruct2{Poly: poly}
	polyGStruct := &PolyGStruct2{PolyG: polyG}

	return polyStruct, polyGStruct, nil
}

// Vss2  Calculate Lagrange polynomial value 
func (polyStruct *PolyStruct2) Vss2(keytype string,ids []*big.Int) ([]*ShareStruct2, error) {
	if ids == nil || len(ids) == 0 {
	    return nil,errors.New("param error")
	}
    	
	dul,err := ContainsDuplicate(ids)
	if err != nil || dul {
	    return nil,errors.New("param error")
	}

	shares := make([]*ShareStruct2, 0)

	for i := 0; i < len(ids); i++ {
		shareVal,err := calculatePolynomial2(keytype,polyStruct.Poly, ids[i])
		if err != nil {
		    return nil,err
		}

		shareStruct := &ShareStruct2{ID: ids[i], Share: shareVal}
		shares = append(shares, shareStruct)
	}

	return shares, nil
}

// Verify2 Verify Lagrange polynomial value
func (share *ShareStruct2) Verify2(keytype string,polyG *PolyGStruct2) bool {

	idVal := share.ID

	computePointX, computePointY := polyG.PolyG[0][0], polyG.PolyG[0][1]

	for i := 1; i < len(polyG.PolyG); i++ {
		pointX, pointY := s256.S256(keytype).ScalarMult(polyG.PolyG[i][0], polyG.PolyG[i][1], idVal.Bytes())

		computePointX, computePointY = s256.S256(keytype).Add(computePointX, computePointY, pointX, pointY)
		idVal = new(big.Int).Mul(idVal, share.ID)
		idVal = new(big.Int).Mod(idVal, s256.S256(keytype).N1())
	}

	originalPointX, originalPointY := s256.S256(keytype).ScalarBaseMult(share.Share.Bytes())

	if computePointX.Cmp(originalPointX) == 0 && computePointY.Cmp(originalPointY) == 0 {
		return true
	}
	
	return false
}

// Combine2 Calculating Lagrange interpolation formula 
func Combine2(keytype string,shares []*ShareStruct2) (*big.Int, error) {
    	if shares == nil || len(shares) == 0 {
	    return nil,errors.New("param error")
	}

	// build x coordinate set
	xSet := make([]*big.Int, 0)
	for _, share := range shares {
		xSet = append(xSet, share.ID)
	}

	// for
	secret := big.NewInt(0)

	for i, share := range shares {
		times := big.NewInt(1)

		// calculate times()
		for j := 0; j < len(xSet); j++ {
			if j != i {
				sub := new(big.Int).Sub(xSet[j], share.ID)
				subInverse := new(big.Int).ModInverse(sub, s256.S256(keytype).N1())
				if subInverse == nil {
				    return nil,errors.New("calc times fail")
				}
				div := new(big.Int).Mul(xSet[j], subInverse)
				times = new(big.Int).Mul(times, div)
				times = new(big.Int).Mod(times, s256.S256(keytype).N1())
			}
		}

		// calculate sum(f(x) * times())
		fTimes := new(big.Int).Mul(share.Share, times)
		secret = new(big.Int).Add(secret, fTimes)
		secret = new(big.Int).Mod(secret, s256.S256(keytype).N1())
	}

	return secret, nil
}

func calculatePolynomial2(keytype string,poly []*big.Int, id *big.Int) (*big.Int,error) {
    if poly == nil || id == nil {
	return nil,errors.New("param error")
    }

    idnum := new(big.Int).Mod(id,s256.S256(keytype).N1())
    if idnum.Cmp(zero) == 0 || id.Cmp(zero) == 0 {
	return nil,errors.New("id can not be equal to 0 or 0 modulo the order of the curve")
    }

	lastIndex := len(poly) - 1
	result := poly[lastIndex]

	for i := lastIndex - 1; i >= 0; i-- {
		result = new(big.Int).Mul(result, id)
		result = new(big.Int).Add(result, poly[i])
		result = new(big.Int).Mod(result, s256.S256(keytype).N1())
	}

	return result,nil
}


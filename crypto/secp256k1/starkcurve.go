package secp256k1

import (
	"crypto/elliptic"
	"math/big"
)

// Stark Curve, see https://docs.starkware.co/starkex-v4/crypto/stark-curve
// y^2 = x^3 + alpha*x + beta (mod p)
type StarkCurve struct {
	P                                  *big.Int
	N                                  *big.Int
	Alpha, Beta                        *big.Int
	Gx, Gy                             *big.Int
	BitSize                            int // the size of the underlying field
	ShiftPointx, ShiftPointy           *big.Int
	MinusShiftPointx, MinusShiftPointy *big.Int
	Max                                *big.Int
}

func (starkCurve *StarkCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       curve.P,
		N:       curve.N,
		B:       curve.Beta,
		Gx:      curve.Gx,
		Gy:      curve.Gy,
		BitSize: curve.BitSize,
	}
}

// IsOnCurve returns true if the given (x,y) lies on the Stark Curve.
func (starkCurve *StarkCurve) IsOnCurve(x, y *big.Int) bool {
	y2 := new(big.Int).Mul(y, y)
	y2 = y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3 = new(big.Int).Mul(x3, x)

	alphax := new(big.Int).Mul(curve.Alpha, x)
	x3 = x3.Add(x3, alphax)

	x3 = x3.Add(x3, curve.Beta)
	x3 = x3.Mod(x3, curve.P)

	return x3.Cmp(y2) == 0
}

// Add returns the sum of P(x1,y1) and Q(x2,y2), note, P != Q
func (starkCurve *StarkCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return curve.Double(x1, y1)
	}

	xDelta := new(big.Int).Sub(x1, x2)
	xDeltaInv := new(big.Int).ModInverse(xDelta, curve.P)
	yDelta := new(big.Int).Sub(y1, y2)

	k := new(big.Int).Mul(yDelta, xDeltaInv)
	k = new(big.Int).Mod(k, curve.P)

	k2 := new(big.Int).Mul(k, k)
	xRlt := new(big.Int).Sub(k2, x1)
	xRlt = new(big.Int).Sub(xRlt, x2)
	xRlt = new(big.Int).Mod(xRlt, curve.P)

	x1SubX := new(big.Int).Sub(x1, xRlt)
	yRlt := new(big.Int).Mul(k, x1SubX)
	yRlt = new(big.Int).Sub(yRlt, y1)
	yRlt = new(big.Int).Mod(yRlt, curve.P)

	return xRlt, yRlt
}

// Double returns 2*(x,y)
func (starkCurve *StarkCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	threeX2Alpha := new(big.Int).Mul(big.NewInt(3), x1)
	threeX2Alpha = new(big.Int).Mul(threeX2Alpha, x1)
	threeX2Alpha = new(big.Int).Add(threeX2Alpha, curve.Alpha)

	twoY1 := new(big.Int).Mul(big.NewInt(2), y1)
	twoY1Inv := new(big.Int).ModInverse(twoY1, curve.P)

	k := new(big.Int).Mul(threeX2Alpha, twoY1Inv)
	k = new(big.Int).Mod(k, curve.P)

	k2 := new(big.Int).Mul(k, k)
	xRlt := new(big.Int).Sub(k2, x1)
	xRlt = new(big.Int).Sub(xRlt, x1)
	xRlt = new(big.Int).Mod(xRlt, curve.P)

	x1SubX := new(big.Int).Sub(x1, xRlt)
	yRlt := new(big.Int).Mul(k, x1SubX)
	yRlt = new(big.Int).Sub(yRlt, y1)
	yRlt = new(big.Int).Mod(yRlt, curve.P)

	return xRlt, yRlt
}

// ScalarBaseMult returns k*B, where B is a curve point and k is
// an integer in byte array of big-endian form.
func (starkCurve *StarkCurve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	kInt := new(big.Int).SetBytes(k)
	return starkCurve.ScalarMultInt(Bx, By, kInt)
}

// ScalarBaseMult returns k*B, where B is a curve point and kInt is
// an integer in big.Int form.
func (starkCurve *StarkCurve) ScalarMultInt(Bx, By, kInt *big.Int) (*big.Int, *big.Int) {
	kInt = new(big.Int).Mod(kInt, curve.N)

	if kInt.Cmp(big.NewInt(1)) == 0 {
		return Bx, By
	}

	if new(big.Int).Mod(kInt, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		doubleBx, doubleBy := starkCurve.Double(Bx, By)
		return starkCurve.ScalarMultInt(doubleBx, doubleBy, new(big.Int).Div(kInt, big.NewInt(2)))
	}

	xRlt, yRlt := starkCurve.ScalarMultInt(Bx, By, new(big.Int).Sub(kInt, big.NewInt(1)))
	xRlt, yRlt = starkCurve.Add(xRlt, yRlt, Bx, By)

	return xRlt, yRlt
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (starkCurve *StarkCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return starkCurve.ScalarMult(curve.Gx, curve.Gy, k)
}

// Marshal converts a point into the form specified in section 4.3.6 of ANSI X9.62.
func (starkCurve *StarkCurve) Marshal(x, y *big.Int) []byte {
	byteLen := (starkCurve.BitSize + 7) >> 3
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point flag
	readBits(x, ret[1:1+byteLen])
	readBits(y, ret[1+byteLen:])
	return ret
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On error, x = nil.
func (starkCurve *StarkCurve) Unmarshal(data []byte) (x, y *big.Int) {
	byteLen := (starkCurve.BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return
	}
	if data[0] != 4 { // uncompressed form
		return
	}
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return
}

//return value is normalized.
func (starkCurve *StarkCurve) KMulG(k []byte) (*big.Int, *big.Int) {
	return starkCurve.ScalarBaseMult(k)
}

func (starkCurve *StarkCurve) N3() *big.Int {
	N3 := new(big.Int).Mul(starkCurve.N, starkCurve.N)
	N3 = new(big.Int).Mul(N3, starkCurve.N)
	return N3
}

func (starkCurve *StarkCurve) N1() *big.Int {
    return starkCurve.N
}

func (starkCurve *StarkCurve) GX() *big.Int {
    return starkCurve.Gx
}

func (starkCurve *StarkCurve) GY() *big.Int {
    return starkCurve.Gy
}

// GetY get y^2
func (starkCurve *StarkCurve) GetY(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	alx := new(big.Int).Mul(x, starkCurve.Alpha)
	y2 := x3.Add(x3, alx)
	y2 = y2.Add(y2,starkCurve.Beta)
	return y2
}

var curve = new(StarkCurve)

// # Elliptic curve parameters.
// assert 2**N_ELEMENT_BITS_ECDSA < EC_ORDER < FIELD_PRIME

func init() {
	curve.P, _ = new(big.Int).SetString("3618502788666131213697322783095070105623107215331596699973092056135872020481", 10)
	curve.N, _ = new(big.Int).SetString("3618502788666131213697322783095070105526743751716087489154079457884512865583", 10)
	curve.Alpha, _ = new(big.Int).SetString("1", 10)
	curve.Beta, _ = new(big.Int).SetString("3141592653589793238462643383279502884197169399375105820974944592307816406665", 10)
	curve.Gx, _ = new(big.Int).SetString("874739451078007766457464989774322083649278607533249481151382481072868806602", 10)
	curve.Gy, _ = new(big.Int).SetString("152666792071518830868575557812948353041420400780739481342941381225525861407", 10)
	curve.BitSize = 252
	curve.ShiftPointx, _ = new(big.Int).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	curve.ShiftPointy, _ = new(big.Int).SetString("1713931329540660377023406109199410414810705867260802078187082345529207694986", 10)
	curve.MinusShiftPointx, _ = new(big.Int).SetString("2089986280348253421170679821480865132823066470938446095505822317253594081284", 10)
	curve.MinusShiftPointy, _ = new(big.Int).SetString("1904571459125470836673916673895659690812401348070794621786009710606664325495", 10)
	curve.Max, _ = new(big.Int).SetString("3618502788666131106986593281521497120414687020801267626233049500247285301248", 10) // 2^251
}

// Stark returns a StarkCurve instance
func Stark() *StarkCurve {
	return curve
}



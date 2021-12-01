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

package ec2_test

import (
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/stretchr/testify/assert"
	"math/big"
	"sort"
	"testing"
)

func TestVss2Init(t *testing.T) {
	u1 := random.GetRandomIntFromZn(secp256k1.S256().N)
	_, u1PolyG, _ := ec2.Vss2Init(u1, 3)
	for i := 0; i < len(u1PolyG.PolyG); i++ {
		assert.NotZero(t, u1PolyG.PolyG[i][0])
		assert.NotZero(t, u1PolyG.PolyG[i][1])
		ret := secp256k1.S256().IsOnCurve(u1PolyG.PolyG[i][0], u1PolyG.PolyG[i][1])
		assert.True(t, ret)
	}
}

func TestVss2(t *testing.T) {
	u1 := random.GetRandomIntFromZn(secp256k1.S256().N)
	u1Poly, u1PolyG, _ := ec2.Vss2Init(u1, 3)
	for i := 0; i < len(u1PolyG.PolyG); i++ {
		assert.NotZero(t, u1PolyG.PolyG[i][0])
		assert.NotZero(t, u1PolyG.PolyG[i][1])
		ret := secp256k1.S256().IsOnCurve(u1PolyG.PolyG[i][0], u1PolyG.PolyG[i][1])
		assert.True(t, ret)
	}

	//enode1,_ := new(big.Int).SetString("524da89d8bd8f051e9b24660941e772f60e2e7a4ab0c48d1671ecfb9844e9cf1f0a9ef697be8118fe7bc9f2782a5a2bad912856bcb3a4dfda0aafcbdc9c282af",10)
	//enode2,_ := new(big.Int).SetString("8908863d56914eaa420afca83f43206f65ff56e42faeecb9e24f77740838819313f789bf7c4941b162e696147df409e47eb95ea351eac016ce8b7bf38fd269b2",10)
	//enode3,_ := new(big.Int).SetString("ee10b450a564e9cda30b37b9497a11ede5583e8964ba01ae85bbba7b421e403b1ab710f87d5b93c700ca459661b889412b9d781fbef8094ee282b46f4a90508b",10)
	//enode4,_ := new(big.Int).SetString("785708c037dcb3527075fe85797e5997c33202508daaa8ee45e99f73121047f3bb3dd2662ce5f0bb9b8e83cd2e56b3d99d2156433fef5185f66d2bb21d944e25",10)
	//enode5,_ := new(big.Int).SetString("730c8fc7142d15669e8329138953d9484fd4cce0c690e35e105a9714deb741f10b52be1c5d49eeeb6f00aab8f3d2dec4e3352d0bf56bdbc2d86cb5f89c8e90d0",10)

	var ids smpclib.SortableIDSSlice
	enodes := []string{"524da89d8bd8f051e9b24660941e772f60e2e7a4ab0c48d1671ecfb9844e9cf1f0a9ef697be8118fe7bc9f2782a5a2bad912856bcb3a4dfda0aafcbdc9c282af", "8908863d56914eaa420afca83f43206f65ff56e42faeecb9e24f77740838819313f789bf7c4941b162e696147df409e47eb95ea351eac016ce8b7bf38fd269b2", "ee10b450a564e9cda30b37b9497a11ede5583e8964ba01ae85bbba7b421e403b1ab710f87d5b93c700ca459661b889412b9d781fbef8094ee282b46f4a90508b", "785708c037dcb3527075fe85797e5997c33202508daaa8ee45e99f73121047f3bb3dd2662ce5f0bb9b8e83cd2e56b3d99d2156433fef5185f66d2bb21d944e25", "730c8fc7142d15669e8329138953d9484fd4cce0c690e35e105a9714deb741f10b52be1c5d49eeeb6f00aab8f3d2dec4e3352d0bf56bdbc2d86cb5f89c8e90d0"}
	for i := 0; i < 5; i++ {
		uid := big.NewInt(i+1) 
		ids = append(ids, uid)
	}
	sort.Sort(ids)

	shares, err := u1Poly.Vss2(ids)
	assert.NoError(t, err)
	for _, share := range shares {
		ret := share.Verify2(u1PolyG)
		assert.True(t, ret)
	}
}

func TestCombine2(t *testing.T) {
	u1, _ := new(big.Int).SetString("3334747394230983325243207970954899590842441253149295381558648242110081293330", 10)
	u2, _ := new(big.Int).SetString("69039181184174029818470298267328820110013585784220774880124345655174594749061", 10)
	u3, _ := new(big.Int).SetString("14867692866148859006086889155133300611365049455876397123617203957782293499325", 10)
	u4, _ := new(big.Int).SetString("84793511064568272149980886713210270911035531383314504494511304398691848103881", 10)
	u5, _ := new(big.Int).SetString("60841277345123397920834696016664146929546891435110670397947900149315293244142", 10)

	id1, _ := new(big.Int).SetString("53618612272167874423319834687974778412293696801310558561041950376332309251074", 10)
	id2, _ := new(big.Int).SetString("54921957341908846327991236707470353323420933608233375424223802952423356273424", 10)
	id3, _ := new(big.Int).SetString("55554820072087080797082013913708076641941533809080830582031668626477915287514", 10)
	id4, _ := new(big.Int).SetString("60318458834590464192620032882393176022119815649037676016914795650913223224233", 10)
	id5, _ := new(big.Int).SetString("115787261728302521653708661579759215305126272044286142279837734005010875313981", 10)

	sku1, _ := new(big.Int).SetString("31191155413895758490308293179882186383085667250661674133654187820857154180677", 10)
	sku2, _ := new(big.Int).SetString("47074940619208118544250574667751837749046355150235507843803424053911198813112", 10)
	sku3, _ := new(big.Int).SetString("64402190692031667657924912059763629636297143519526964063936831306627647090315", 10)
	sku4, _ := new(big.Int).SetString("34772545226428570215016578677967881376777770447360028779798133967936336399940", 10)
	sku5, _ := new(big.Int).SetString("79875137852131204821645001934236208017593200315324988641558008769062905261078", 10)

	sk := u1
	sk = new(big.Int).Add(sk, u2)
	sk = new(big.Int).Add(sk, u3)
	sk = new(big.Int).Add(sk, u4)
	sk = new(big.Int).Add(sk, u5)
	sk = new(big.Int).Mod(sk, secp256k1.S256().N)

	shareU1 := &ec2.ShareStruct2{ID: id1, Share: sku1}
	shareU2 := &ec2.ShareStruct2{ID: id2, Share: sku2}
	shareU3 := &ec2.ShareStruct2{ID: id3, Share: sku3}
	shareU4 := &ec2.ShareStruct2{ID: id4, Share: sku4}
	shareU5 := &ec2.ShareStruct2{ID: id5, Share: sku5}

	shares := []*ec2.ShareStruct2{shareU1, shareU2, shareU3, shareU4, shareU5}
	computeSK, _ := ec2.Combine2(shares[:3])

	assert.Equal(t, 0, sk.Cmp(computeSK), "wrong sk ", computeSK, " is not ", sk)
}

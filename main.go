package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bn256"
)

func HashToBigInt(s string) *big.Int {
	h := sha256.Sum256([]byte(s))
	return new(big.Int).SetBytes(h[:])
}

func BigIntInv(v *big.Int) *big.Int {
	return new(big.Int).Exp(
		v,
		new(big.Int).Add(
			big.NewInt(-2),
			bn256.Order),
		bn256.Order,
	)
}

func PointSum(arr []*bn256.G1) *bn256.G1 {
	s := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(arr); i++ {
		s = new(bn256.G1).Add(s, arr[i])
	}
	return s
}

func main() {
	caSecret := "fapDoodle"

	userName := []string{"alice", "bob"}
	userWatermark := make([]*big.Int, 0)
	for i := 0; i < len(userName); i++ {
		userWatermark = append(userWatermark, HashToBigInt(userName[i]+caSecret))
	}

	attrs := make([]*big.Int, 0)
	attrs = append(attrs, HashToBigInt("citizen:US"))
	attrs = append(attrs, HashToBigInt("age:adult"))
	attrs = append(attrs, HashToBigInt("citizen:US"))

	attrsP := make([]*bn256.G1, 0)
	for i := 0; i < len(attrs); i++ {
		attrsP = append(attrsP, new(bn256.G1).ScalarBaseMult(attrs[i]))
	}

	attrsPSum := PointSum(attrsP)

	for u := 0; u < len(userName); u++ {
		blindAttrsP := make([]*bn256.G1, 0)
		for i := 0; i < len(attrs); i++ {
			blindAttrsP = append(blindAttrsP, new(bn256.G1).ScalarMult(attrsP[i], userWatermark[u]))
		}

		blindAttrsPSum := PointSum(blindAttrsP)
		unBlindAttrsPSum := new(bn256.G1).ScalarMult(blindAttrsPSum, BigIntInv(userWatermark[u]))

		fmt.Printf("%s: Sum_i[a_i G1]: %v\n", userName[u], attrsPSum)
		fmt.Printf("%s: Sum_i[a_i u0 G1]: %v\n", userName[u], blindAttrsPSum)
		fmt.Printf("%s: Sum_i[a_i u0 G1]/u0: %v\n", userName[u], unBlindAttrsPSum)
		fmt.Printf("\n")
	}

}

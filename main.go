package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bn256"
)

/*
  // attributes that can match
  a[i] = Hash(A[i])

  // each attribute issued to a user
  Sum_i [ s w[u] a[i] G1 ]

  // paired with the inverse to cancel the watermark
  // and add in a nonce:

  (f/s) G2
*/

func HashToBigInt(s string) *big.Int {
	h := sha256.Sum256([]byte(s))
	return new(big.Int).SetBytes(h[:])
}

func HashGT(p *bn256.GT) []byte {
	h := sha256.Sum256(p.Marshal())
	return h[:]
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

type File struct {
	Nonce *big.Int
}

func (f *File) Init(caSecret string) *File {
	r, _ := rand.Int(rand.Reader, bn256.Order)
	s := HashToBigInt(caSecret)
	f.Nonce = new(big.Int).Mul(r, BigIntInv(s))
	return f
}

type User struct {
	Name         string
	PlainAttrs   []string
	Watermark    *big.Int
	WatermarkInv *big.Int
	Attrs        []*bn256.G1
	Unwrap       *bn256.G2
}

func (u *User) Init(caSecret string) *User {
	s := HashToBigInt(caSecret)
	u.Watermark = HashToBigInt(u.Name + caSecret)
	u.WatermarkInv = BigIntInv(u.Watermark)
	u.Unwrap = new(bn256.G2).ScalarBaseMult(u.WatermarkInv)
	for p := 0; p < len(u.PlainAttrs); p++ {
		a := new(bn256.G1).ScalarBaseMult(
			new(big.Int).Mul(
				HashToBigInt(u.PlainAttrs[p]),
				new(big.Int).Mul(u.Watermark, s),
			),
		)
		u.Attrs = append(u.Attrs, a)
	}
	return u
}

func main() {
	caSecret := "fapDoodle"

	files := []File{
		{},
	}
	files[0].Init(caSecret)

	users := []User{
		{
			Name: "alice",
			PlainAttrs: []string{
				"citizen:US",
				"citizen:NL",
				"citizen:adult",
			},
		},
		{
			Name: "bob",
			PlainAttrs: []string{
				"citizen:US",
				"citizen:NL",
				"citizen:adult",
			},
		},
	}

	for i := 0; i < len(users); i++ {
		users[i].Init(caSecret)
	}

	for i := 0; i < len(users); i++ {
		u := users[i]
		attrsPSum := bn256.Pair(PointSum(u.Attrs), u.Unwrap)
		fmt.Printf("%s: Sum_i[a_i G1]: %s\n", u.Name, hex.EncodeToString(HashGT(attrsPSum)))
	}

}

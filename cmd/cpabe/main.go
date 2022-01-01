package main

import "bytes"
import "math/big"
import "crypto/sha256"
import "crypto/rand"
import "golang.org/x/crypto/bn256"
import "log"
import "encoding/hex"

// N just needs to be prime for testing
var N = bn256.Order

type Pt struct {
	X *big.Int
	Y *big.Int
}

func V(v string, S *big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte(v))
	h.Write(S.Bytes())
	sum := h.Sum(nil)
	return Mod(new(big.Int).SetBytes(sum[:]))
}

func H(v *big.Int, S *big.Int) *big.Int {
	h := sha256.New()
	h.Write(v.Bytes())
	h.Write(S.Bytes())
	sum := h.Sum(nil)
	return Mod(new(big.Int).SetBytes(sum[:]))
}

// Hash an y into an (x,y) point
// H(x,y) = (u H y, y)
func NewPt(y *big.Int, u *big.Int, S *big.Int) *Pt {
	return &Pt{
		X: Mul(H(y, S), u),
		Y: y,
	}
}

func Inv(n *big.Int) *big.Int {
	return new(big.Int).Exp(
		n,
		new(big.Int).Sub(
			N,
			big.NewInt(2),
		),
		N,
	)
}

func Mod(n *big.Int) *big.Int {
	return new(big.Int).Mod(n, N)
}

func Add(a, b *big.Int) *big.Int {
	return Mod(new(big.Int).Add(a, b))
}

func Sub(a, b *big.Int) *big.Int {
	return Mod(new(big.Int).Sub(a, b))
}

func Mul(a, b *big.Int) *big.Int {
	return Mod(new(big.Int).Mul(a, b))
}

// This only works in prime finite field!  phi vs modulus
func Exp(a, b *big.Int) *big.Int {
	return Mod(new(big.Int).Exp(a, b, N))
}

func Neg(a *big.Int) *big.Int {
	return Mod(new(big.Int).Neg(a))
}

func Const(a int64) *big.Int {
	return Mod(big.NewInt(a))
}

func Dot(xs, ys []*big.Int) *big.Int {
	sum := Const(0)
	for i := 0; i < len(xs); i++ {
		sum = Add(sum, Mul(xs[i], ys[i]))
	}
	return sum
}

// Think of this as an alternate sum operator that has algebraic properties we want.
//
// k =   (  x0,y0) L (  x1,y1) L (  x2,y2)
//   =   (u x0,y0) L (u x1,y1) L (u x2,y2)
//   =   (u HH 0,H 0) L (u HH 1,H 1) L (u HH 2,H 2)
//
// When the x points are scaled by u, we get the same answer.
// This is a key to letting us watermark per user.
//
// Return y*num, and 1/den as a pair.  They both have factors of u that must cancel
func Coefficients(target *big.Int, p []*Pt) ([]*big.Int, []*big.Int) {
	sum := Const(0)
	ns := make([]*big.Int, 0)
	ds := make([]*big.Int, 0)
	n := len(p)
	for j := 0; j < n; j++ {
		ynum := Mul(
			p[j].Y,
			Exp(
				p[j].X,
				Const(int64(n)-1),
			),
		)
		den := Const(1)
		for i := 0; i < n; i++ {
			if i != j {
				den = Mul(den, Inv(Sub(p[j].X, p[i].X)))
			}
		}
		n := Mod(ynum)
		d := Mod(den)
		ns = append(ns, n)
		ds = append(ds, d)
		sum = Mod(Add(sum, Mul(n, d)))
	}
	ns = append(ns, Mod(Sub(target, sum)))
	ds = append(ds, Const(1))
	return ns, ds
}

func Rand() *big.Int {
	v, _ := rand.Int(rand.Reader, N)
	return Mod(v)
}

func Pub1(v *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarBaseMult(v)
}

func Pub2(v *big.Int) *bn256.G2 {
	return new(bn256.G2).ScalarBaseMult(v)
}

func HT(p *bn256.GT) []byte {
	h := sha256.Sum256(p.Marshal())
	return h[:]
}

type Cert struct {
	Nonce  *big.Int
	Exp    int64
	Shares map[string]*bn256.G2
}

type PadlockCase struct {
	Required []string
	FilePub  *bn256.G1
	Outcome  []byte
}

//
// caPub1 = (S G1)
// caPub2 = (S G2)
// filePub1 = (f G1)
// filePub2 = (f G2)
//
// // Encrypt
// \prod_j e( caPub1, f a_j filePub2)
// =
// e(caPub1, (f \sum_j a_j) filePub2)
//
// // Given:
// A_j = a_j caPub2
//
// // Decrypt
// \prod_j e( filePub1, A_j)
// =
// e(filePub1, \sum_j A_j)
//
func Issue(S *big.Int, attrs []string) *Cert {
	nonce := Rand()
	invNonce := Inv(nonce)
	shares := make(map[string]*bn256.G2)
	for _, a_j := range attrs {
		v := Mul(invNonce, Mul(S, V(a_j, S)))
		shares[a_j] = Pub2(v)
	}
	return &Cert{Shares: shares, Nonce: nonce}
}
func MakePadlockCase(caPub1 *bn256.G1, S *big.Int, attrs []string) *PadlockCase {
	sum := Const(0)
	f := Rand()
	for _, attr_j := range attrs {
		a_j := Mul(f, V(attr_j, S))
		sum = Add(sum, a_j)
	}
	outcome :=
		HT(bn256.Pair(caPub1, new(bn256.G2).ScalarBaseMult(sum)))
	return &PadlockCase{
		Required: attrs,
		FilePub:  Pub1(f),
		Outcome:  outcome,
	}
}
func UnlockCase(padlockCase *PadlockCase, cert *Cert) []byte {
	total := new(bn256.G2).ScalarBaseMult(Const(0))
	for _, attr_j := range padlockCase.Required {
		a_j, ok := cert.Shares[attr_j]
		if ok {
			total.Add(total, new(bn256.G2).ScalarMult(a_j, cert.Nonce))
		}
	}
	return HT(bn256.Pair(padlockCase.FilePub, total))
}

func Hex(v []byte) string {
	return hex.EncodeToString(v)
}

func main() {
	// This random number IS the CA
	S := Rand()
	caPub1 := Pub1(S)

	// Some attributes that we want the CA to issue into a cert
	attrs := []string{"citizen:US", "age:adult"}
	cert := Issue(S, attrs)

	// Round-trip test
	padlockCase := MakePadlockCase(caPub1, S, attrs)
	unlock := UnlockCase(padlockCase, cert)

	log.Printf("\npadlockCase:%v\n\n unlockCase:%v", Hex(padlockCase.Outcome), Hex(unlock))

	if bytes.Compare(padlockCase.Outcome, unlock) != 0 {
		panic("decrypt and encrypt are inconsistent")
	}
}

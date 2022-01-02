package main

import "crypto/rsa"
import "crypto/rand"
import "log"
import "encoding/json"
import "math/big"
import "crypto/sha256"

func AsJsonPretty(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

/*
  This is an interface for which multiplicative inverse is unavailable.
*/
type PowerRing interface {
	Add(a, b *big.Int) *big.Int
	Neg(a *big.Int) *big.Int
	Sub(a, b *big.Int) *big.Int // Add(a,Neg(b))
	Mul(a, b *big.Int) *big.Int
	Exp(a, b *big.Int) *big.Int
	Rand() *big.Int
	Value(a []byte) *big.Int
	Hash(a []byte) *big.Int  // Hash(a) = Value(sha256(a))
	Bytes(a *big.Int) []byte //v = Bytes(Value(v))
}

/*
  An RSA group is a group in which division is a private operation.
  Division is required to to invert powers.
*/
type RSAGroup struct {
	N   *big.Int // Public modulus
	D   *big.Int
	E   *big.Int
	P   *big.Int
	Q   *big.Int
	Phi *big.Int
}

/* The full RSA group can create multiplicateive inverses */
func NewRSAGroup(bits int) *RSAGroup {
	// Use the key generator just for its primes
	privKey, _ := rsa.GenerateKey(rand.Reader, bits)
	p := privKey.Primes[0]
	q := privKey.Primes[1]
	one := big.NewInt(1)
	g := &RSAGroup{
		N: new(big.Int).Mul(p, q),
		D: privKey.D,
		E: big.NewInt(int64(privKey.E)),
		P: p,
		Q: q,
		Phi: new(big.Int).Mul(new(big.Int).Sub(p,one),new(big.Int).Sub(q,one)), 
	}
	return g
}

/* Not just cast to public, but actually stripped of Phi */
func (g *RSAGroup) Public() PowerRing {
	return &RSAGroup{
		N:   g.N,
	}
}

func (g *RSAGroup) Value(a []byte) *big.Int {
	return new(big.Int).SetBytes(a)
}
func (g *RSAGroup) Hash(a []byte) *big.Int {
	return new(big.Int).SetBytes(sha256.New().Sum(a))
}
func (g *RSAGroup) Bytes(a *big.Int) []byte {
	return a.Bytes()
}

func (g *RSAGroup) Rand() *big.Int {
	r, _ := rand.Int(rand.Reader, g.N)
	return new(big.Int).Mod(r, g.N)
}

func (g *RSAGroup) Const(n int64) *big.Int {
	return big.NewInt(n)
}

func (g *RSAGroup) Add(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, b), g.N)
}
func (g *RSAGroup) Sub(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(a, b), g.N)
}
func (g *RSAGroup) Neg(a *big.Int) *big.Int {
	return g.Add(a, g.N)
}

func (g *RSAGroup) Mul(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, b), g.N)
}

func (g *RSAGroup) Exp(a, b *big.Int) *big.Int {
	return new(big.Int).Exp(a, b, g.N)
}

func main() {
	// Create a new group
	g := NewRSAGroup(16)
	one := g.Const(1)
	two := g.Const(2)
	three := g.Const(3)
	five := g.Const(5)
	phi := g.Phi

	// Mark as: signed, true, false, watermark to u
	// Clearly, these are random values!
	//sR := g.Rand()
	s := new(big.Int).Exp(g.E,two,phi)
	sPriv := new(big.Int).Exp(g.D,two,phi)

	//tR := g.Rand()
	t := new(big.Int).Exp(g.E,three,phi)
	tPriv := new(big.Int).Exp(g.D,three,phi)

	//fR := g.Rand()
	f := new(big.Int).Exp(g.E,five,phi)
	fPriv := new(big.Int).Exp(g.D,five,phi)

	w_uR := g.Rand()
	w_u := new(big.Int).Exp(g.E,w_uR,phi)
	w_uPriv := new(big.Int).Exp(g.D,w_uR,phi)

	_ = one
	r := g.Rand()
	log.Printf("r^1 = (r^{E^tR))^{D^tR} = %d = %d = %d = %d = %d = %d",
		r,
		g.Exp(g.Exp(r, g.D), g.E), 
		g.Exp(g.Exp(r, g.E),g.D),
		g.Exp(g.Exp(g.Exp(g.Exp(r, g.E),g.D),g.E),g.D),
		g.Exp(g.Exp(g.Exp(g.Exp(r, g.E),g.E),g.D),g.D),
		g.Exp(g.Exp(g.Exp(g.Exp(r, g.D),g.E),g.E),g.D),
	)

	n := g.N
	d := g.D
	e := g.E

	log.Printf("(n,d,e) = (%d,%d,%d)", n, d, e)
	log.Printf("(n,sPriv,s) = (%d,%d,%d)", n, sPriv, s)
	log.Printf("(n,tPriv,t) = (%d,%d,%d)", n, tPriv, t)
	log.Printf("(n,fPriv,f) = (%d,%d,%d)", n, fPriv, f)
	log.Printf("phi = %d", phi)
	log.Printf("t = %d", t)
	log.Printf("tPriv = %d", tPriv)
	log.Printf("r = %d", r)
	log.Printf("((r^e mod N)^d mod N) = %d", g.Exp(g.Exp(r,e),d))
	log.Printf("((r^(e*d mod Phi) mod N) = %d", g.Exp(r,new(big.Int).Mod(new(big.Int).Mul(e,d),phi)))
	log.Printf("((r^(t*tPriv mod Phi) mod N) = %d", g.Exp(r,new(big.Int).Mod(new(big.Int).Mul(t,tPriv),phi)))
	_ = s
	_ = sPriv
	_ = t
	_ = tPriv
	_ = f
	_ = fPriv
	_ = w_u
	_ = w_uPriv

}

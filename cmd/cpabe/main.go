package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/rfielding/cpabe/lang"
	"golang.org/x/crypto/bn256"
)

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

func B(v *big.Int) []byte {
	h := sha256.Sum256(v.Bytes())
	return h[:]
}

type Cert struct {
	PubCAM  []byte               `json:"pubca"`
	PubCA   *bn256.G1            `json:"-"`
	Nonce   *big.Int             `json:"-"`
	NonceM  []byte               `json:"nonce"`
	Exp     int64                `json:"exp"`
	Shares  map[string]*bn256.G2 `json:"-"`
	SharesM map[string][]byte    `json:"shares"`
}

type Padlock struct {
	Policy *lang.Policy   `json:"policy"`
	Cases  []*PadlockCase `json:"padlock"`
}

func NewPadlock(caPub1 *bn256.G1, S *big.Int, p *lang.Policy, keys map[string][]byte) (*Padlock, error) {
	reverse := func(arr []*PadlockCase) []*PadlockCase {
		for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
			arr[i], arr[j] = arr[j], arr[i]
		}
		return arr
	}
	cases := make([]*PadlockCase, 0)
	for _, u := range p.Unlocks {
		if u.Requirement.Or != nil {
			required := make([]string, 0)
			// Get the subset of keys that this unlock produces
			keyMap := make(map[string][]byte)
			for _, key := range u.Keys {
				k := string(key)
				keyMap[k] = keys[k]
			}
			for i := 0; i < len(u.Requirement.Or); i++ {
				for a := 0; a < len(u.Requirement.Or[i].And); a++ {
					required = append(
						required,
						u.Requirement.Or[i].And[a].Is,
					)
				}
				cases = append(cases, MakePadlockCase(caPub1, S, required, keyMap))
			}
		}
	}
	// padlock cases accumulate keys, so reverse the
	// list to get the most specific match
	cases = reverse(cases)
	return &Padlock{
		Policy: p,
		Cases:  cases,
	}, nil
}

func (p *Padlock) Unlock(c *Cert) map[string][]byte {
	for _, v := range p.Cases {
		if v.IsSatisfied(c) {
			return UnlockCase(v, c)
		}
	}
	return nil
}

type PadlockCase struct {
	Required []string          `json:"required"`
	FilePub  *bn256.G1         `json:"-"`
	FilePubM []byte            `json:"filepub"`
	Fixes    map[string][]byte `json:"fixes"`
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
func Issue(S *big.Int, attrs []string, exp int64) *Cert {
	nonce := Rand()
	invNonce := Inv(nonce)
	sharesM := make(map[string][]byte)
	shares := make(map[string]*bn256.G2)
	for _, a_j := range attrs {
		v := Mul(invNonce, Mul(S, V(a_j, S)))
		shares[a_j] = Pub2(v)
		sharesM[a_j] = Pub2(v).Marshal()
	}
	return &Cert{
		PubCA:   Pub1(S),
		PubCAM:  Pub1(S).Marshal(),
		Shares:  shares,
		SharesM: sharesM,
		Nonce:   nonce,
		NonceM:  B(nonce),
		Exp:     exp,
	}
}
func MakePadlockCase(caPub1 *bn256.G1, S *big.Int, attrs []string, Kresults map[string][]byte) *PadlockCase {
	sum := Const(0)
	f := Rand()
	for _, attr_j := range attrs {
		a_j := Mul(f, V(attr_j, S))
		sum = Add(sum, a_j)
	}
	outcome :=
		HT(bn256.Pair(caPub1, new(bn256.G2).ScalarBaseMult(sum)))
	fixes := make(map[string][]byte)
	for k, v := range Kresults {
		fixes[k] = Xor(v, outcome)
	}
	return &PadlockCase{
		Required: attrs,
		FilePub:  Pub1(f),
		FilePubM: Pub1(f).Marshal(),
		Fixes:    fixes,
	}
}

func (pc *PadlockCase) IsSatisfied(c *Cert) bool {
	for _, k := range pc.Required {
		if c.Shares[k] == nil {
			return false
		}
	}
	return true
}

func UnlockCase(padlockCase *PadlockCase, cert *Cert) map[string][]byte {
	if padlockCase.FilePub == nil {
		InitPadlockCase(padlockCase)
	}
	if cert.PubCA == nil {
		InitCert(cert)
	}
	total := new(bn256.G2).ScalarBaseMult(Const(0))
	for _, attr_j := range padlockCase.Required {
		a_j, ok := cert.Shares[attr_j]
		if ok {
			total.Add(total, new(bn256.G2).ScalarMult(a_j, cert.Nonce))
		}
	}
	outcome := HT(bn256.Pair(padlockCase.FilePub, total))
	fixed := make(map[string][]byte)
	for k, v := range padlockCase.Fixes {
		fixed[k] = Xor(outcome, v)
	}
	return fixed
}

// InitPadlockCase must be called if p was created from json
func InitPadlockCase(p *PadlockCase) error {
	b, err := base64.StdEncoding.DecodeString(string(p.FilePubM))
	if err != nil {
		return fmt.Errorf("Unable to unmarshal cert nonce: %v", err)
	}
	pFilePub, ok := new(bn256.G1).Unmarshal(b)
	if !ok {
		return fmt.Errorf("Unable to unmarshal file public key")
	}
	p.FilePub = pFilePub
	return nil
}

// InitCert must be called if c was created from json
func InitCert(c *Cert) error {
	// Deserialize the nonce
	b, err := base64.StdEncoding.DecodeString(string(c.NonceM))
	if err != nil {
		return fmt.Errorf("Unable to unmarshal cert nonce: %v", err)
	}
	c.Nonce = new(big.Int).SetBytes(b)

	// Deserialize the CA public key
	b, err = base64.StdEncoding.DecodeString(string(c.PubCAM))
	if err != nil {
		return fmt.Errorf("Unable to unmarshal cert ca public key: %v", err)
	}
	cPubCA, ok := new(bn256.G1).Unmarshal(b)
	if !ok {
		return fmt.Errorf("unable to unmarshal ca public key point")
	}
	c.PubCA = cPubCA

	// Iterate attributes to recreate their structure
	for k, _ := range c.SharesM {
		b, err = base64.StdEncoding.DecodeString(string(c.SharesM[k]))
		if err != nil {
			return fmt.Errorf("Unable to unmarshal cert ca public key: %v", err)
		}
		cShares, ok := new(bn256.G2).Unmarshal(b)
		if !ok {
			return fmt.Errorf("unable to load point for share %s", k)
		}
		c.Shares[k] = cShares
	}

	return nil
}

func Xor(a []byte, b []byte) []byte {
	c := make([]byte, len(a))
	for i, _ := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func Hex(v []byte) string {
	return hex.EncodeToString(v)
}

func AsJson(v interface{}) string {
	j, _ := json.MarshalIndent(v, "", "  ")
	return string(j)
}

func AsJsonSmall(v interface{}) string {
	j, _ := json.Marshal(v)
	return string(j)
}

var examplePolicies = []string{`
---
display: 
  label: SECRET//SQUIRREL
  background: red
  foreground: white
unlocks: 
  is_legal: 
    keys: 
    - Read
    requirement:
      and:
      - every:
        - age
        - adult
      - some:
        - citizen
        - US
        - NL
      - every:
        - not-citizen
        - SA
        - PK
  is_owner: 
    keys: 
    - Write
    - Read
    requirement:
      and:
      - require: is_legal
      - some:
        - email
        - r@gmail.com
        - d@gmail.com
`,
}

func main() {
	policy, err := lang.Parse(examplePolicies[0])
	if err != nil {
		panic(err)
	}

	// Round-trip test
	keyMap := map[string][]byte{
		"Read":  B(Rand()),
		"Write": B(Rand()),
	}

	S := V("squeamish ossifrage", Const(0))
	caPub1 := Pub1(S)

	// Some attributes that we want the CA to issue into a cert
	allAttrs := []string{
		"citizen:US",
		"age:adult",
		"email:r@gmail.com",
		"not-citizen:SA",
		"not-citizen:PK",
	}
	exp := time.Now().Add(time.Duration(24*60) * time.Hour).Unix()
	cert := Issue(S, allAttrs, exp)

	// Make a padlock
	padlock, err := NewPadlock(caPub1, S, policy, keyMap)
	if err != nil {
		panic(err)
	}

	log.Printf("Cert:\n%s", AsJson(cert))

	// TODO: write padlock.Unlock that walks
	// cases and returns map of keys
	keys := padlock.Unlock(cert)
	log.Printf("Keys: %v", AsJson(keys))

}

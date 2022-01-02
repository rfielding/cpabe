package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/go-yaml/yaml"
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
	Rule  interface{}    `json:"rule"`
	Cases []*PadlockCase `json:"padlock"`
}

func NewPadlock(y interface{}, keys map[string][]byte) (*Padlock, error) {
	var err error

	// Transform policy into or-of-and
	y, err = EnumeratePolicy(y)
	if err != nil {
		return nil, err
	}

	cases := make([]*PadlockCase, 0)
	if ya, yok := y.([]interface{}); yok {
		for i := 2; i < len(ya); i += 3 {
			name := ya[i].(string)
			keys := ya[i+1].([]interface{})
			rule := ya[i+2].([]interface{})
			for r := 1; r < len(rule); r++ {
				_ = r
				_ = name
				_ = keys
			}
		}
	}
	return &Padlock{
		Rule:  y,
		Cases: cases,
	}, nil
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

/*
  Policy language:

  Policy function:

  (Policy ($LABEL,$FOREGROUND,$BACKGROUND)
    ($ACTION_i)+
  )

  // To create labels on policies
  // The KEYGRANT specifies which keys need to be calculated on success,
  // which may be zero or more than one.
  $ACTION_i := $NAME $KEYGRANT $BOOL

  // To calculate access keys
  $BOOL := (and $BOOL+)
  $BOOL := (or $BOOL+)
  // At least one val must exist (field is separated to make policy less verbose)
  $BOOL := (some $FIELD $VAL_i+)
  // Every val must exist
  $BOOL := (every $FIELD $VAL_i+)

  // An ! on the start of a field is just literally used, and lets us express definite negation

  Example translation:

  Read:  age:21+ citizenship:NL !citizenship:SA !citizenship:PK
  Read:  age:21+ citizenship:US !citizenship:SA !citizenship:PK
  Write: age:21+ citizenship:NL !citizenship:SA !citizenship:PK email:r@gmail.com
  Write: age:21+ citizenship:NL !citizenship:SA !citizenship:PK email:d@gmail.com
  Write: age:21+ citizenship:US !citizenship:SA !citizenship:PK email:r@gmail.com
  Write: age:21+ citizenship:US !citizenship:SA !citizenship:PK email:d@gmail.com

  Note that the number of cases can get large with the use of "some" and "or".
  But once we have a key for a case (ie: Read,Write), we can skip all such cases.

*/
var examplePolicies = []string{`
[ Policy, [Adult/21+,white,black],
  IsLegal,[Read],[
    and, [every, age, 21+], [some, citizenship, NL, US], [every, no-citizenship, SA, PK]
  ],
  IsOwner,[Write],[
    and, [every, email, r@gmail.com], IsLegal
  ],
]
`}

func BIsOp(b interface{}, op string) bool {
	barr, barrok := b.([]interface{})
	if barrok {
		return barr[0] == op
	}
	return false
}

func EnumerateBools(b interface{}, env map[string]interface{}) (interface{}, error) {
	arr, arrOk := b.([]interface{})
	if !arrOk {
		return b, nil
	}
	if len(arr) == 0 {
		return b, fmt.Errorf("zero length arrays not allowed in boolean condition")
	}
	// Depth first recursion
	for i := 1; i < len(arr); i++ {
		bChild, err := EnumerateBools(arr[i], env)
		if err != nil {
			return b, err
		}
		arr[i] = bChild
	}
	// Strings in and/or must be references
	if arr[0] == "and" || arr[0] == "or" {
		// Flatten out references literally
		for i := 1; i < len(arr); i++ {
			ref, refOk := arr[i].(string)
			if refOk && env[ref] != nil {
				arr[i] = env[ref]
			}
		}
	}
	// The every keyword is a macro for AND, to stop repeating the attribute name repeatedly
	if arr[0] == "every" {
		// Flatten every into and cases
		newArr := make([]interface{}, len(arr)-1)
		if len(arr) < 3 {
			return false, fmt.Errorf("'every' keyword is called like [every $FIELD $Vi+]")
		}
		fieldName := arr[1]
		for i := 2; i < len(arr); i++ {
			newArr[i-1] = fmt.Sprintf("%s:%s", fieldName, arr[i])
		}
		newArr[0] = "and"
		return newArr, nil
	}
	// Some is a macro to reduce the verbosity of attribute names in or case
	if arr[0] == "some" {
		// Flatten every into or cases
		newArr := make([]interface{}, len(arr)-1)
		if len(arr) < 3 {
			return false, fmt.Errorf("'some' keyword is called like [some $FIELD $Vi+]")
		}
		fieldName := arr[1]
		for i := 2; i < len(arr); i++ {
			newArr[i-1] = []interface{}{"and", fmt.Sprintf("%s:%s", fieldName, arr[i])}
		}
		newArr[0] = "or"
		return newArr, nil
	}
	// Sanity check
	if arr[0] == "and" || arr[0] == "or" {
		// This is the only case that should happen now
	} else {
		return b, fmt.Errorf("There should only be and/or expressions at this point in the transformation")
	}
	// Everything is and/or or an attribute
	// Sort attributes, before and, before or
	for i := 1; i < len(arr); i++ {
		for j := 1; j < len(arr); j++ {
			isArri, iok := arr[i].([]interface{})
			isArrj, jok := arr[j].([]interface{})
			// Attributes are less than arrays
			if !iok && jok {
				tmp := arr[i]
				arr[i] = arr[j]
				arr[j] = tmp
			}
			// Sort attributes
			if !iok && !jok {
				is, isok := arr[i].(string)
				js, jsok := arr[j].(string)
				if isok && jsok && strings.Compare(is, js) > 0 {
					tmp := arr[i]
					arr[i] = arr[j]
					arr[j] = tmp
				}
			}
			// and before or
			if iok && jok {
				if len(isArri) == 0 {
					return b, fmt.Errorf("Expecting non-empty array in booleans")
				}
				if len(isArrj) == 0 {
					return b, fmt.Errorf("Expecting non-empty array in booleans")
				}
				tmp := arr[i]
				arr[i] = arr[j]
				arr[j] = tmp
			}
		}
	}

	flattenNested := func(arr []interface{}, op string) ([]interface{}, error) {
		// Merge nested and adjacent ops
		if arr[0] == op {
			newArr := []interface{}{op}
			for i := 1; i < len(arr); i++ {
				nestArr, ok := arr[i].([]interface{})
				if ok && len(nestArr) == 0 {
					return arr, fmt.Errorf("nested %s array needs at least one element", op)
				}
				// something to flatten
				if ok && nestArr[0] == op {
					// flatten its children into ours
					for j := 1; j < len(nestArr); j++ {
						newArr = append(newArr, nestArr[j])
					}
				} else {
					newArr = append(newArr, arr[i])
				}
			}
			return newArr, nil
		}
		return arr, nil
	}

	// Flatten nested and
	arr, err := flattenNested(arr, "and")
	if err != nil {
		return arr, err
	}

	// Flatten nested or
	arr, err = flattenNested(arr, "or")
	if err != nil {
		return arr, err
	}

	distribute := func(arr []interface{}) ([]interface{}, error) {
		if arr[0] == "or" {
			return arr, nil
		}
		start := 0
		// handle: [and, ..., [or, ...]]
		for i := start + 2; i < len(arr); i++ {
			if arri, iok := arr[i].([]interface{}); iok && BIsOp(arr[i], "or") {
				// ["and",...,["or",...],...]
				for start < i && !BIsOp(arr[start+1], "or") {
					for j := 1; j < len(arri); j++ {
						arr[i].([]interface{})[j] = append(
							arr[i].([]interface{})[j].([]interface{}),
							arr[start+1],
						)
					}
					arr[i] = arri
					start++
					arr[start] = "and"
				}
			}
		}
		arr = arr[start:]

		/// XXXXX There are major problems here, and I have given up on correct OR conditions
		/// for the moment.  Using raw interface{} is just too much here.
		start = 0
		for i := start + 2; i < len(arr); i++ {
			arri, iok := arr[i].([]interface{})
			arrs, sok := arr[start+1].([]interface{})
			if iok && sok && arri[0] == "or" && arrs[0] == "or" {
				for ii := 1; ii < len(arri); ii++ {
					for si := 1; si < len(arri); si++ {
					}
				}
			}
		}

		// If we are at:  ["and",["or",...]], then just ["or",...]
		if len(arr) == 2 && arr[0] == "and" && BIsOp(arr[1], "or") {
			return arr[1].([]interface{}), nil
		}
		return arr, nil
	}

	arr, err = distribute(arr)
	if err != nil {
		return arr, err
	}
	return arr, nil
}

func EnumeratePolicy(p interface{}) (interface{}, error) {
	topLevel, topLevelOk := p.([]interface{})
	if !topLevelOk {
		return p, fmt.Errorf("We expect a json/yaml LISP as array at top level")
	}
	if len(topLevel) < 3 {
		return p, fmt.Errorf("We expect at least [Policy, LABELS, (Ni Vi Bi)+")
	}
	topCommand, topCommandOk := topLevel[0].(string)
	if !topCommandOk {
		return p, fmt.Errorf("We expect to call [Policy, ...] at top level")
	}
	if topCommand != "Policy" {
		return p, fmt.Errorf("We expect [Policy,...] to be called at the top")
	}
	labels, labelsOk := topLevel[1].([]interface{})
	if !labelsOk {
		return p, fmt.Errorf("We expect security labels like [Policy,[SECRETSQUIRREL,white,red],... at the top")
	}

	log.Printf("label: %s, fg: %s, bg: %s", labels[0], labels[1], labels[2])
	env := make(map[string]interface{})
	for idx := 2; idx < len(topLevel); idx += 3 {
		name, nameOk := topLevel[idx].(string)
		if !nameOk {
			return p, fmt.Errorf("Expecting a condition name at index %d of top level call.", idx)
		}
		keys, keysOk := topLevel[idx+1].([]interface{})
		if !keysOk {
			return p, fmt.Errorf("Expecting the names of keys to return on this condition at index %d.", idx)
		}
		keySet := make([]string, 0)
		for i, v := range keys {
			k, kok := v.(string)
			if !kok {
				return p, fmt.Errorf("We are expecting a named key in array at %d[%d]", idx, i)
			}
			keySet = append(keySet, k)
		}
		bools, boolsOk := topLevel[idx+2].([]interface{})
		if !boolsOk {
			return p, fmt.Errorf("Should have a boolean condition at %d", idx)
		}
		newBools, err := EnumerateBools(bools, env)
		if err != nil {
			return p, fmt.Errorf("When checking boolean condition: %v", err)
		}
		topLevel[idx+2] = newBools
		env[name] = newBools
	}

	return p, nil
}

func main() {
	var y interface{}
	err := yaml.Unmarshal([]byte(examplePolicies[0]), &y)
	if err != nil {
		panic(err)
	}
	y2, err := EnumeratePolicy(y)
	log.Printf("%s", AsJsonSmall(y2))
	if err != nil {
		panic(err)
	}

	// Using the CA password to create the secret,
	// it's up to CA to have enough entropy.
	S := V("squeamish ossifrage", Const(0))
	caPub1 := Pub1(S)

	// Some attributes that we want the CA to issue into a cert
	allAttrs := []string{"citizen:US", "age:adult", "email:rob.fielding@gmail.com"}
	exp := time.Now().Add(time.Duration(24*60) * time.Hour).Unix()
	cert := Issue(S, allAttrs, exp)

	// Round-trip test
	Kr := B(Rand())
	Kw := B(Rand())

	attrs := []string{"citizen:US", "age:adult"}
	padlockCase := MakePadlockCase(caPub1, S, attrs, map[string][]byte{"R": Kr, "W": Kw})
	unlock := UnlockCase(padlockCase, cert)["R"]

	log.Printf("\n         Kr:%v\n\nunlockCase:%v", Hex(Kr), Hex(unlock))

	if bytes.Compare(Kr, unlock) != 0 {
		panic("decrypt and encrypt are inconsistent")
	}

	log.Printf("%s", AsJson(cert))
	log.Printf("%s", AsJson(padlockCase))
}

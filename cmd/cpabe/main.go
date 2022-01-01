package main

/*
  CA issues attributes like:
  - The CA has a secret "s"
  - f_i is factual statement i, attested with a MAC
  - Presume that the MAC is:  a_i = Hash(f_i || s)
  - We can pack attestations together into a single JWT,
    just so that we can sign the attributes together,
    and give it an exp date for non-crypt-enforceable checks.

  Example:
    user u, approaches CA with a list of facts it wants attested:
      [f_0, f_1, ... , f_N]

    The actual value of u is not known to the user.  It can be a fresh random value.
    The CA uses suggested facts as advisory input, and signs some set of facts
    together into one JWT:


    So, the JWT is something like this, where attributes are attested by points on elliptic curves.
    Note that negated facts are just like other facts.  They are explicitly witnessed with a value.

    {
      "exp": 8479321,
      "attributes": {
        "email:rob.fielding@gmail.com": [1234,89423],
	"age:adult": [890432,9342],
        "citizen:US": [890243,09823],
        "!citizen:NK": [990243,29823]
      },
      "keys": {
        "pubG1": [234234,89432],
        "pubG2": [098423,89023]
      }
    }

    Multiplying IBE keys together:

   G1, G2 # public
   (c G1)  # CA pub key
   (p G1)  # padlock pub key

   c H2(a0) # known to user
   c H2(a1) # known to user

   e(c G1, p G2 + p H2(a0) + p H2(a1))
   =
   e(c G1, p G2) * e(c G1,p H2(a0)) * e(c G1,p H2(a1)) # public lock create
   =
   e(p G1, c G2 + c H2(a0) + c H2(a1))
   =
   e(p G1, c G2) * e(p G1, c H2(a0)) * e(p G1, c H2(a1))

# If instead of addition of "c H2(ai)", we pass through poly points, then
# for the points, the (x,y) = (vx,y) for points yielding the same key k.
# this can be used to watermark attributes, by letting user attributes be scaled by u,
# which cancels out in poly fit "addition"

  # some public scheme to make points deterministic as a function of fact in the attr
  # secretly create points outside of the EC scheme
  x = H("clr:secret")
  y = H(x)
  (x,y)    # points will not be co-linear, because the y is random

  the operator "L" is inclusion of points in Lagrange Poly interpolation, and it determines some point.

   A0 L A1
   A0 L A2 L A3

  This makes creating the value a dot product at runtime, but expressed multiplicatively, with exponents that we must supply
  to produce the key.  V0 and V1 were calculated by the lock.  a0 and a1 must be in the right proportion to produce
  the correct answer.  The vector length can be extended by 1 to include the error diff for target key as well. aN will
  pad with a 1.

  e(p G1, c V0 G2)^a0 * e(p G1, c V1 G2)^a1

  \sum_j y_j \prod_i^{i!=j} (x - x_j)/(x_i - x_j)

  During padlock creation, the (x,y) pairs produce k, to be used in (k p G1), so that after pairing it gets (k c G2)
*/
import "math/big"
import "crypto/sha256"
import "golang.org/x/crypto/bn256"
import "log"

// N just needs to be prime for testing
var N = bn256.Order

type Pt struct {
	X *big.Int
	Y *big.Int
}

// Be careful with this in bn256!!
//
// H(wellKnown) G2 != H2(wellKnown)
//  Becase of (1/H(wellKnown) * H(wellKnown) G2 = G2
//
func H(v string) *big.Int {
	h := sha256.Sum256([]byte(v))
	return new(big.Int).SetBytes(h[:])
}

// Hash an y into an (x,y) point
// H(x,y) = (u H y, y)
func NewPt(y *big.Int, u *big.Int) *Pt {
	h := sha256.Sum256(y.Bytes())
	x := new(big.Int).SetBytes(h[:])
	return &Pt{
		X: Mod(new(big.Int).Mul(x, u)), 
		Y: Mod(y),
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
	return new(big.Int).Mod(n,N)
}

func Dot(xs, ys []*big.Int) *big.Int {
	sum := big.NewInt(0)
	for i := 0; i < len(xs); i++ {
		sum = new(big.Int).Add(sum, new(big.Int).Mul(xs[i],ys[i]))
	}
	return Mod(sum)	
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
func Coefficients(target *big.Int,p []*Pt) ([]*big.Int,[]*big.Int) {
	sum := big.NewInt(0)
	x := big.NewInt(0)
	ns := make([]*big.Int,0)
	ds := make([]*big.Int,0)
	for j := 0; j < len(p); j++ {
		ynum := p[j].Y
		den := big.NewInt(1)
		for i := 0; i < len(p); i++ {
			if i != j {
				ynum = new(big.Int).Mul(ynum, new(big.Int).Sub(x,      p[j].X))
				den  = new(big.Int).Mul(den,  new(big.Int).Sub(p[i].X, p[j].X))
			}
		}
		// TODO: we can multiply n * r, and d * (1/r)
		n := Mod(ynum)
		d := Mod(Inv(den))
		ns = append(ns,n)
		ds = append(ds,d)
		sum = Mod(new(big.Int).Add(sum, new(big.Int).Mul(n,d)))
	}
	ns = append(ns, Mod(new(big.Int).Sub(target,sum)))
	ds = append(ds, big.NewInt(1))
	return ns,ds
}

 /*
  For public coefficients, u=1.  so, uden is published with the lock.
  For users, for each j, they have aj = (-py*px*u)^{n-1} instead of any actual point pairs.
  They need to pair with (1/u) to match.

 */
func main() {
	// Test with a small group
	N = big.NewInt(7727)
	K := big.NewInt(7000)
	u := big.NewInt(22)
	one := big.NewInt(1)
	a := NewPt(H(""),one)
	a0 := NewPt(H("SECRET"),one)
	a1 := NewPt(H("CRYPTO"),one)
	b := NewPt(H(""),u)
	b0 := NewPt(H("SECRET"),u)
	b1 := NewPt(H("CRYPTO"),u)

	aX,aY := Coefficients(K,[]*Pt{a,a0,a1})
	log.Printf("a: %v %v",aX,aY)
	log.Printf("a0 L a1: %v",Dot(aX,aY))

	bX,bY := Coefficients(K,[]*Pt{b,b0,b1})
	bX[1] = aX[1]
	bY[1] = aY[1]
	log.Printf("b: %v %v",bX,bY)
	log.Printf("b0 L b1: %v",Dot(bX,bY))

	//v := big.NewInt(7000)
	//invv := Mod(Inv(v))
	//v_invv := Mod(new(big.Int).Mul(v,invv))
	//log.Printf("%v * %v = %v", v, invv, v_invv)
}

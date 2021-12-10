package main

import (
	//"bufio"
	"io/ioutil"
	"os"
	//"strings"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bn256"
)

func HashToBigInt(s string) *big.Int {
	h := sha256.Sum256([]byte(s))
	return new(big.Int).SetBytes(h[:])
}

func HashGT(p *bn256.GT) []byte {
	h := sha256.Sum256(p.Marshal())
	return h[:]
}

// we rely on key generation as:
// the ca calculates all: (s H(a_i)) values for users
// the ca public key is: (s G1)
// the file key is (k G1)
//   e( k G1, s H(a_i) G2)    // how recipient, that knows k, calculates key
// = e( s G1, k H(a_i) G2)    // how sender calculates key
// = e(G1, H(a_i) G2)^{sk}    // both are same as this
//
// so: sender pairs (CAPub, FileSecret)
//     receiver pairs (FilePublic, AttrSecret)
type Output struct {
	Kind       string `json:"Kind,omitempty"`       // file extension
	CAName     string `json:"CAName,omitempty"`     // the name of the CA corresopnding to CAPub
	CASecret   string `json:"CASecret,omitempty"`   // s
	CAPub_sG1      string `json:"CAPub,omitempty"`      // s G1
	AttrName   string `json:"AttrName,omitempty"`   // actual public key attribute
	AttrSecret_shG2 string `json:"AttrSecret,omitempty"` // s H(a_i) G2
	FileSecret_khG2 string `json:"FileSecret,omitempty"` // k H(a_i) G2.  k is never saved anywhere
	FilePublic_kG1 string `json:"FilePublic,omitempty"` // k G1
	SecretKeyGT  string `json:"SecretKey,omitempty"`  // the actual secret, created from pairing
}

func (o *Output) GetCASecret_s() *big.Int {
	return HashToBigInt(o.CASecret)
}

func (o *Output) GetCAPub_sG1() *bn256.G1 {
	if len(o.CAPub_sG1) != 0 {
		b, err := hex.DecodeString(o.CAPub_sG1)
		if err != nil {
			panic(err)
		}
		v, ok := new(bn256.G1).Unmarshal(b)
		if !ok {
			panic("unable to unmarshal public key")
		}
		return v
	}
	s := o.GetCASecret_s()
	return new(bn256.G1).ScalarBaseMult(s)
}

func ReadOutput(name string, kind string) *Output {
	fname := fmt.Sprintf("%s.%s", name, kind)
	if _, err := os.Stat(fname); os.IsNotExist(err) {
		fmt.Printf("file not found: %s\n", fname)
		os.Exit(-1)
	}
	rBytes, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(fmt.Sprintf("When ReadOutput(%s,%s), ioutil.ReadFile(%s) %v", name, kind, fname, err))
	}
	if err != nil {
		panic(err)
	}
	var obj Output
	err = json.Unmarshal(rBytes, &obj)
	if err != nil {
		panic(err)
	}
	return &obj
}

func WriteOutput(o *Output, name string) {
	j, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		panic(err)
	}
	fname := fmt.Sprintf("%s.%s", name, o.Kind)
	err = ioutil.WriteFile(fname, j, 0700)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote: %s\n	", fname)
}

func main() {
	if os.Args[1] == "ca" && len(os.Args) == 4 {
		// Make the directory of CA info
		caname := os.Args[2]
		os.MkdirAll(caname, 0700)
		casecret := &Output{
			Kind:     "ca-secret",
			CAName:   caname, // a directory of stuff, where this file is ./root.ibcasecret
			CASecret: os.Args[3],
		}
		WriteOutput(casecret, caname+"/root")

		// We need the name to find the file
		// Read in a secret to generate the public key, or issue attribues
		s := casecret.GetCASecret_s()
		sG1 := new(bn256.G1).ScalarBaseMult(s)
		WriteOutput(
			&Output{
				Kind:   "ca",
				CAPub_sG1:  hex.EncodeToString(sG1.Marshal()),
				CAName: caname,
			},
			caname+"/root",
		)
		return
	}

	if os.Args[1] == "issue" && len(os.Args) == 4 {
		caname := os.Args[2]
		attr := os.Args[3]
		casecret := ReadOutput(caname+"/root", "ca-secret")
		hattr := HashToBigInt(attr)
		s := casecret.GetCASecret_s()
		sh := new(big.Int).Mul(s,hattr)
		shG2 := new(bn256.G2).ScalarBaseMult(sh)
		WriteOutput(
			&Output{
				Kind:       "issue",
				CAPub_sG1:      hex.EncodeToString(casecret.GetCAPub_sG1().Marshal()),
				AttrSecret_shG2: hex.EncodeToString(shG2.Marshal()),
				AttrName: attr,
				CAName:     casecret.CAName,
			},
			caname+"/"+attr,
		)
		return
	}

	if os.Args[1] == "lock" && len(os.Args) == 4 {
		caname := os.Args[2]
		attr := os.Args[3]
		k, _ := rand.Int(rand.Reader, bn256.Order)
//		k := big.Int(1)
		hattr := HashToBigInt(attr)
		hk := new(big.Int).Mul(k,hattr)
		khG2 := new(bn256.G2).ScalarBaseMult(hk)
		sG1 := ReadOutput(caname+"/root", "ca")
		kG1 := new(bn256.G1).ScalarBaseMult(k)
		keyGT := bn256.Pair(sG1.GetCAPub_sG1(), khG2)
		fpub_kG1 := hex.EncodeToString(kG1.Marshal())
		WriteOutput(
			&Output{
				Kind:       "lock-secret",
				CAPub_sG1:      sG1.CAPub_sG1,
				FileSecret_khG2: hex.EncodeToString(khG2.Marshal()),
				FilePublic_kG1: fpub_kG1,
				AttrName:   attr,
				SecretKeyGT:  hex.EncodeToString(keyGT.Marshal()),
			},
			caname+"/"+attr,
		)
		WriteOutput(
			&Output{
				Kind:       "lock",
				CAPub_sG1:      sG1.CAPub_sG1,
				FilePublic_kG1: fpub_kG1,
				AttrName:   attr,
			},
			caname+"/"+attr,
		)
		return
	}

	if os.Args[1] == "unlock" && len(os.Args) == 4 {
		caname := os.Args[2]
		attr := os.Args[3]
		lockpub := ReadOutput(caname+"/"+attr, "lock")
		attrpriv := ReadOutput(caname+"/"+attr, "issue")
		kG1bytes, err := hex.DecodeString(lockpub.FilePublic_kG1)
		if err != nil {
			panic(err)
		}
		kG1, ok := new(bn256.G1).Unmarshal(kG1bytes)
		if !ok {
			panic(fmt.Sprintf("unable to unmarshal G1 group for public key of file"))
		}
		shG2bytes, err := hex.DecodeString(attrpriv.AttrSecret_shG2)
		if err != nil {
			panic(err)
		}
		shG2, ok := new(bn256.G2).Unmarshal(shG2bytes)
		if !ok {
			panic(fmt.Sprintf("Unable to unmarshal G2 group for private key of attribute"))
		}
		keyGT := bn256.Pair(kG1, shG2)
		WriteOutput(
			&Output{
				Kind:      "unlock-secret",
				AttrName:  attr,
				SecretKeyGT: hex.EncodeToString(keyGT.Marshal()),
			},
			caname+"/"+attr,
		)
		return
	}
	fmt.Printf("usage: ibe ca ${caName} # generate a CA pub key caname.pub from a given caname.ibecasecret")
	fmt.Printf("usage: ibe issue ${caName} ${attr} # creates ${attr}.ibecaissue")
	fmt.Printf("usage: ibe lock ${caName} ${attr} # creates ${attr}.ibelockpub and ${attr}.ibelockprivate")
	fmt.Printf("usage: ibe unlock ${caName} ${attr} # creates ${attr}.ibelockpub and ${attr}.ibelockprivate")
}

package main

import (
	//"bufio"
	"io/ioutil"
	"os"
	//"strings"
	//"crypto/rand"
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

type Output struct {
	Kind     string `json:"Kind,omitempty"`
	CASecret string `json:"CASecret,omitempty"`
	CAName string `json:"CAName,omitempty"`
	CAPub    string `json:"CAPub,omitempty"`
	AttrName string `json:"AttrName,omitempty"`
	Attr     string `json:"Attr,omitempty"`
}

func (o *Output) GetCASecret() *big.Int {
	return HashToBigInt(o.CASecret)
}

func (o *Output) GetCAPub() *bn256.G1 {
	if len(o.CAPub) != 0 {
		b, err := hex.DecodeString(o.CAPub)
		if err != nil {
			panic(err)
		}
		v, ok := new(bn256.G1).Unmarshal(b)
		if !ok {
			panic("unable to unmarshal public key")
		}
		return v
	}
	return new(bn256.G1).ScalarBaseMult(o.GetCASecret())
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
	if len(os.Args) > 1 {
		if os.Args[1] == "ibecapub" && len(os.Args) == 3 {
			// We need the name to find the file
			caname := os.Args[2]
			// Read in a secret to generate the public key, or issue attribues
			casecret := ReadOutput(caname, "ibecasecret")
			s := casecret.GetCASecret()
			sG1 := new(bn256.G1).ScalarBaseMult(s)
			WriteOutput(
				&Output{
					Kind:  "ibecapub",
					CAPub: hex.EncodeToString(sG1.Marshal()),
					CAName: caname,
				},
				caname,
			)
			return
		}

		if os.Args[1] == "ibeissue" && len(os.Args) == 4 {
			caname := os.Args[2]
			attr := os.Args[3]
			casecret := ReadOutput(ca, "ibecasecret")
			s := casecret.GetCASecret()
			shG2 := new(bn256.G2).ScalarBaseMult(s)
			shG2 = shG2.ScalarBaseMult(HashToBigInt(attr))
			WriteOutput(
				&Output{
					Kind:  "ibeissue",
					CAPub: hex.EncodeToString(casecret.GetCAPub().Marshal()),
					Attr:  hex.EncodeToString(shG2.Marshal()),
					CAName: casecret.CAName,
				},
				attr,
			)
			return
		}
	}
	fmt.Printf("usage: ibe capub ${caName} # generate a CA pub key caname.pub from a given caname.casecret")
	fmt.Printf("usage: ibe caissue ${caName} ${attr} # creates ${addr}.caissue")
}

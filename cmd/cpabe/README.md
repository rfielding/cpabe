# Ciphertext Policy Attribute Based Encryption

This is doing a basic variation on Identity Based Encryption,
where we can do key derivations based on a boolean combination
of attested attributes.  This uses the `bn256` elliptic curve
pairing to do it.  The basic idea is that when creating 
the padlock, a nonce it used to pair with the public
key of the CA.  When a user unlocks, f and s are effectively
swapped.

```
e(f G1, a0 s G2 + a2 s G2 + ... + aN s G2)
=
e(s G1, a0 f G2 + a2 f G2 + ... + aN f G2)
=
e(G1, G2)^{f a0 s + f a1 s + ... f s G2}
```

CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Write User Cert W
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "NF3vH5/RViYFl5uFB9cjU9VQdAf1lOCFjbf9bAwjzCQ=",
  "exp": 1646597405,
  "shares": {
    "age:adult": "W3ZdgrMk6EGXjb77cXUhOdEHyU2oorGHq0xlcy+pLFps2p4C01E0zrJ6wMzmQs/HFm9eeaZYPG/bdJqev0psUY7aEel0sBl1kp6IVW6MHyz4DeZyv5T+qNtYtyUdFeBwdIRnK+pQgdyn5kNFAZbEnQCe/OXqkiJ13pYA1tm4Q70=",
    "citizen:US": "Ue3EcWtAcFEEDEY6cMGZ8W/ihJR8boFf75FSyRzTS+5ijbkjBzolHwgrL7McZTzyyNNbldnPxbvXnsg+eY5WzgAjJTgDgcpqouanusVaup9B0R8cpU+cRpHjaiD0l12mVRJN08p3FM/axYN0eEkP3TcaQP7Ig8nglG37d00Rj2g=",
    "email:r@gmail.com": "HY7/Lb676pnj1fg8est1HSQM+h/LNe2ock8yP+CHPQd3zA/YyuuVL1ZxZ97chojb0chI+TdAL4QNO+iFA35ne3Y0jyavCOBZZcqulfoYg5BM8f/ibysDNtvL079uQVQcNMmoiY+JT+cQGVktK/vHreEnhLbuEnt8cNSirTSD2z0=",
    "not-citizen:PK": "A6271AVAQVE47t9tJa2a9vSp5Tio90Tw4OrFsQGI+NAiL+jOvaey6Zjb5jBww/PREzP4YNGSWJqydD8KDoMF7mnTiLgSaTn+CMCu7EnVbIyiCGJUnT4mWvcS+ND72xKHVatQk/utNnm12Jfk67PAkTMZHRX4GID/uGosQq0lP7I=",
    "not-citizen:SA": "IBV56+ipGASoQH02rp7nE8n2tTzGgTOV5+os/m3S9QdcU/GbxRwv8yK+n8miYFpswO9dV1ulq5g2j/0gNCn6kkz0xcLmfb0MXaviCFXK+VCEuIc/qmQa+xGMrAOCuWazK9FshBjUMrkLNk4SNzIG6ktJ+IQCRtgbEfSHCrhVt4s="
  }
}
```
Write User Cert R
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "aGr3QWt9E7zifPrEeheTWmIajIrN5jz1Uz4yd50Eq1A=",
  "exp": 1646597405,
  "shares": {
    "age:adult": "B+rmw0isfr+07d07zGbrTSOiF19rUo32gC9ao0hTAiKI5gBr0xB2d6G6/sXQkGZiv7kBs3IfCCTtElPM8yqUiCmxsJRdRLL1+zZUbK3RjZLIazGiVQLIzsaJyJi7N1TZZP5EsG8uaxfah+EEh66STpj4cZSGGWegu+PhCfuoq/o=",
    "citizen:US": "dHOXOAY8POIxTkPQEQeLeZ7rHpJrsnnSFXxlZbk1bZJq4J+KmL0XFmZMvgx7RVlmw5Y6vSdP13c3de730MxiclXr5CDOS/L5DO999wvZPWsY8UGhEyAP/kriVwTBPwaFXUMKGv20wPBDer2HgNPLwuS2QkoL1vfKLSJdOBk7no8=",
    "email:e@gmail.com": "DWvf+NVbiUQk0V4pYsA73UI7UAqPQNAeBLoOEk9B6jkD+1s7EHrsaSA+N7qbmeBA0K6WwHDPe73zWelKUo7O/SPvezDSbBs8iQ8hLz83C3ko3Ok0IsNNoYjXkp81mcHWLDTXaeadK2RsynK5DOhfLsxTd4FnXDvg0KQ9vGDQyaw=",
    "not-citizen:PK": "P/KtEXMsVx5TLn8A1IE2AdVow/UCAWoYufU3NXcKIk+EpOLMCnTwQSURKv36N923EXACIfF7u06F3kzlwR/GbQbcl0pFyUlOyRcsfTjTdDrDmq192Tm6+OGMiN+N0VIrSv+GDjpFwherpN9tLsMPlD7gDTrJSTekXJ831hMLTlM=",
    "not-citizen:SA": "VJCxqJxmjFZjfNwosw0OyBXIUoXb8J5IVyj562A6rKQqkqKoxUrjW2UtL8P98QPSjWADFrUg/6cS887MCDdUI3kGnOBr++etkGuFuirZ6CanBp6oKa4jBCBopaPN7bASaLVexw2fYzYo8XsL5iZxfmDjQbDOveyYkpS7o04KItA="
  }
}
```
Padlock
```yaml


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

```
Expected keys
```yaml

{
  "Read": "87Dm5YtuhLS/1IE+fOSLUFFyWd05JmF+57Gmc4mywuk=",
  "Write": "Xa4/85bW2jisrigl+mjZCKvfZZegjjpyu29+Ip5Ndc8="
}
```
Keys yielded by unlock with certW
```json

{
  "Read": "87Dm5YtuhLS/1IE+fOSLUFFyWd05JmF+57Gmc4mywuk=",
  "Write": "Xa4/85bW2jisrigl+mjZCKvfZZegjjpyu29+Ip5Ndc8="
}
```
Keys yielded by unlock with certR
```json

{
  "Read": "87Dm5YtuhLS/1IE+fOSLUFFyWd05JmF+57Gmc4mywuk="
}
```

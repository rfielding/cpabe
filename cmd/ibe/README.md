# Identity Based Encryption:

run this command to generate a CA, using
a secret string.  Say that the CA password is 'farkDoodle',
and the CA is simply called 'trusted'.
  
```bash
echo farkDoodle | ibe capub > trusted.ibepub
```

`trusted.ibepub` is an encode of bn256,
and it's a spec of being G1 in bn256 for a point, which is
a pair (X,Y) of big.Int

```bash
CaPublic = Sha256(${secret}) G1
```

the ca can grant ownership of strings to users.  Say that
we name attributes after what is in the string, and use email 
addresses

```bash
  echo farkDoodle | ibe issue 'rob.fielding@gmail.com' > 'rob.fielding@gmail.com.ibepriv'
```   

Where this attribute is a point (X,Y) in the bn256 curve

```
Attribute = Sha256("farkDoodle") * Sha256("rob.fielding@gmail.com") G2
```

To generate an encrypt key for the public key `rob.fielding@gmail.com`

as the sender..., which outputs: a file nonce, attribute, grant

```bash
  ibe to /home/rfielding/resume.doc trusted.ibepub 'rob.fielding@gmail.com' > ciphertex.ibekey
```   

as the recipient...

```bash
  ibe decrypt ciphertex.ibekey
```   


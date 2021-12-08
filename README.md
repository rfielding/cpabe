EC Pairings over bn256
==================

This is an attempt to solve the core problem of attribute based encryption, where the goal is to be able to use CA-issued attributes to AND together properties to pass a threshold and generate an AES key.

For example, imagine that we have a complete language for and and or combinations....

```
# encrypt the file TO a boolean threshold
cat resume.pdf | go run cpabe.go -encryptTo '(and age:adult (or citizen:US citizen:NL))' > resume.pdf.encrypted

# decrypt the file WITH a set of attested attributes
cat resume.pdf.encrypted | go run cpabe.go -decryptFrom 'age:adult citizen:US'
```


This is a form of user-controlled DRM to have a key derivation function that doesn't require that a file is encrypted to any individual.  Instead of storing the key literally in some encrypted form; a key-derivation data structure is stored.  Users have a set of attested attributes that function like a certificate.  The certificate need not have any Personlly Identifying Information in them as well.  We can easily transform this into two cases that can possibly match

- (and age:adult citizen:US)
- (and age:adult citizen:NL)

If we have a target AES key `k` that we want to encrypt, then we can store the key xored with a case for attributes AND together.

It is a central problem in AttributeBasedCryptography to ensure that the attributes all come from the SAME user.  That way, an adult from UK cannot colude with a non-adult citizen of US to produce a key.  This means that we have to defend against legitimate users abusing intermediate steps of computation to elevate their access.

![cpabe](cpabe-pairing.png)

> Note!  I have not yet solved the problem with this.  The product rule over un-watermarked attributes creates a problem.  `f` limits collusion to individual files, but I have not yet found a way to decisively force all combined attributes to come from the same user.  I have read that it is possible to do this, and that it requires curves like this; so I am using this repo to get to know pairings well enough to eventually figure it out.

Combinations of attributes would create a user profile with O(2^n) items if AND had to be pre-computed for every case; in which case paring would be unnecessary.  You could do all of this with simple SHA hashing.

A solution to this problem that is kind of impractical, but would solve it would be that the user has to have the CA explicitly bind together (f,u) to keep the user from figuring out the value of u or 1/u, or f, or 1/f.  It is trivial to calculate the inverse of an integer in this group.  

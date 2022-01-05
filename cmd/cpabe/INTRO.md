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

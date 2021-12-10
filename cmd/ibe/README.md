# Identity Based Encryption:

Create a directory called `trusted` with public key `trusted/root.ca` written into it.
This is the public key file for the cert authority. It is the only required publicv key
in the system.

> The file `trusted/root.ca-secret` is there too for the `issue` operation.

```
./ibe ca trusted jlkadlkjqfvklj4ty890zadsx2x3euhi23exhui23ehxui23eiuh23xeuhi23ehxu2i3exhu2iehi
```

This creates a private key for a user-desired value, like an email address.  This way, you don't need to look up the public key of who you want to send to.  You just need to trust a CA, like `trusted/root.ca`.  The file is a private key for the owner of `rob.fielding@gmail.com`, and it's in the file `trusted/rob.fielding@gmail.com.issue`

```
./ibe issue trusted rob.fielding@gmail.com
```

Create key material (ie: for an AES key) for anyone that has been issued the attribute.  Note that every time this is run, there is a different nonce. The file ends up in `trusted/rob.fielding@gmail.com.lock`

```
./ibe lock trusted rob.fielding@gmail.com
```

In order to actually encrypt a file, we need to use it before we lose the value k that was used for the nonce.  So, a temp file `trusted/rob.fielding@gmail.com.lock-secret` exists so that a ciphertext can be created with the key, and the `FilePublic` associated with the ciphertext.  Beware that the way we name files, we clobber re-created attributes with new `k` values.  You just need to make sure that the FilePublic matches up with the SecretKey that you actually encrypt the file with; before you delete `rusted/rob.fielding@gmail.com.lock-secret` (after you generate your ciphertext with it).

The owner of attribute `rob.fielding@gmail.com` can combine the ciphertext's FilePublic with AttrSecret to recover the AES key that was used to encrypt the file.

```
./ibe unlock trusted rob.fielding@gmail.com
```

This just dumps the files, so we can note that lock-secret and unlock-secret generate the same key material.

```
cat trusted/*
```


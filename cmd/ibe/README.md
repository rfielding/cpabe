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

In order to actually encrypt a file, we need to use it before we lose the value k that was used for the nonce.  So, a temp file `trusted/rob.fielding@gmail.com.lock-secret` exists so that a ciphertext can be created with the key, and the `FilePublic` associated with the ciphertext.  Beware that the way we name files, we clobber re-created attributes with new `k` values.  You just need to make sure that the FilePublic matches up with the SecretKey that you actually encrypt the file with; before you delete `trusted/rob.fielding@gmail.com.lock-secret` (after you generate your ciphertext with it).

The owner of attribute `rob.fielding@gmail.com` can combine the ciphertext's FilePublic with AttrSecret to recover the AES key that was used to encrypt the file.

```
./ibe unlock trusted rob.fielding@gmail.com
```

This just dumps the files, so we can note that lock-secret and unlock-secret generate the same key material.

```
cat trusted/*
```

Here is what a run looks like:

```

wrote: trusted/root.ca-secret
	wrote: trusted/root.ca
	wrote: trusted/rob.fielding@gmail.com.issue
	wrote: trusted/rob.fielding@gmail.com.lock-secret
	wrote: trusted/rob.fielding@gmail.com.lock
	wrote: trusted/rob.fielding@gmail.com.unlock-secret
	{
  "Kind": "issue",
  "CAName": "trusted",
  "CAPub": "2b2b66d95a917d63e34093970ae59f32ef8781783064e0ef82f5199135ac044e855e5bf5c7885a195d37b7490960af7dfee68a59f472be17459a42d4703febba",
  "AttrName": "rob.fielding@gmail.com",
  "AttrSecret": "09f6d46aa420f405e36ad8a1e6b17585f871261943670d94c6acce28d778a3af51d4cf0fa27acd55c47fa2bf029fd1fc03786168eb87e45b04e02cc5b38dbec47f717dcc7d164afa6d41ab1df81b468fda13e61721c7b60bfc6fb904c79a820b01190b6dbc8373fdc20e2af0cf1af477e381c983475daf730b306cf6a6ce71cf"
}{
  "Kind": "lock",
  "CAPub": "2b2b66d95a917d63e34093970ae59f32ef8781783064e0ef82f5199135ac044e855e5bf5c7885a195d37b7490960af7dfee68a59f472be17459a42d4703febba",
  "AttrName": "rob.fielding@gmail.com",
  "FilePublic": "59d6b3eaf2817ff39f38017a9bc7b541b8a1a35e6bb63248136ce09f56e111c546176de4aa409f9c820f06529b9a24c117af152680d9d5df21e21d49376272e2"
}{
  "Kind": "lock-secret",
  "CAPub": "2b2b66d95a917d63e34093970ae59f32ef8781783064e0ef82f5199135ac044e855e5bf5c7885a195d37b7490960af7dfee68a59f472be17459a42d4703febba",
  "AttrName": "rob.fielding@gmail.com",
  "FileSecret": "63314ad8e27d243e756ceb563fa6e11107b107431581749e6e6c1b11661add9a892b6376267bd6a7081d0055d2de6066032be35fe4efca1f086e5c45a6d79a2f3c0d0e6b1f9913415ad08c9360dffe99f9062d5e9eab8bf8ba386b6902d09497462763d76c73945fb8e2ff8cc7fbae5d113d52fbd1c836dd5b720cfebfbb1711",
  "FilePublic": "59d6b3eaf2817ff39f38017a9bc7b541b8a1a35e6bb63248136ce09f56e111c546176de4aa409f9c820f06529b9a24c117af152680d9d5df21e21d49376272e2",
  "SecretKey": "5f133e30fd1f8a3c7fd4173da11367a71417a5be4a315c0e7dd4579664fbae8c3c5a33adfcb06440e8d53a28206d3ce42643d8cf46896a04c192e94ee1eeaf246618bfcf21595d9d40555f49eca26e68d2bfae411e66534beb8bf2e1fa6f4948090925efe8a2d5f26a20513cbad089e251f0729bbfbd768dccc147197000a6f9222b4bc46d719a506d73ac0c248b4917886eeaf088055a831506774a88addc3a20f2fa0492c443272b0e3d3f8ceace7cd54b61127b79a443a87c790a14fd2a396dcdbba4f4cf37cb602c2571c128a19f4de570157f1e9f28b944cce14edb16855bc9fe0581a67809299707ab55645a3c78a3d8986b5e361131488adeb64b63730958d61616bb70eecf0f2100105fc2e9a471f69e6bcf231b8b977227519859370729fae43947eceb8cd577ea4f15e1d7b91e9c32461c543e30b19ce0945c973875bf3aa1e8cb4fc7db55a6f8c301aece8e7715dc30db1614dbf1e923cac464c68b96f3208d4f096907318672a1f366ddc53c58b593b7ceed6c4e3ba4a84730fc"
}{
  "Kind": "unlock-secret",
  "AttrName": "rob.fielding@gmail.com",
  "SecretKey": "5f133e30fd1f8a3c7fd4173da11367a71417a5be4a315c0e7dd4579664fbae8c3c5a33adfcb06440e8d53a28206d3ce42643d8cf46896a04c192e94ee1eeaf246618bfcf21595d9d40555f49eca26e68d2bfae411e66534beb8bf2e1fa6f4948090925efe8a2d5f26a20513cbad089e251f0729bbfbd768dccc147197000a6f9222b4bc46d719a506d73ac0c248b4917886eeaf088055a831506774a88addc3a20f2fa0492c443272b0e3d3f8ceace7cd54b61127b79a443a87c790a14fd2a396dcdbba4f4cf37cb602c2571c128a19f4de570157f1e9f28b944cce14edb16855bc9fe0581a67809299707ab55645a3c78a3d8986b5e361131488adeb64b63730958d61616bb70eecf0f2100105fc2e9a471f69e6bcf231b8b977227519859370729fae43947eceb8cd577ea4f15e1d7b91e9c32461c543e30b19ce0945c973875bf3aa1e8cb4fc7db55a6f8c301aece8e7715dc30db1614dbf1e923cac464c68b96f3208d4f096907318672a1f366ddc53c58b593b7ceed6c4e3ba4a84730fc"
}{
  "Kind": "ca",
  "CAName": "trusted",
  "CAPub": "2b2b66d95a917d63e34093970ae59f32ef8781783064e0ef82f5199135ac044e855e5bf5c7885a195d37b7490960af7dfee68a59f472be17459a42d4703febba"
}{
  "Kind": "ca-secret",
  "CAName": "trusted",
  "CASecret": "jlkadlkjqfvklj4ty890zadsx2x3euhi23exhui23ehxui23eiuh23xeuhi23ehxu2i3exhu2iehi"
}
```

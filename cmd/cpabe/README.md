
CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Write User Cert
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "YePYgNSi92Cq5IaF+iMp5Q8aYfeWTqkOfZzkUYe5UZc=",
  "exp": 1646596838,
  "shares": {
    "age:adult": "diAfimITn3n1EHLP+eBW2y76DcZJ2N9mKL8sFSIilPpBMgUZ68j9PihMT7xWB15QEUyEjDd5oQhMl613iIdn3Tnv3uONBRq8HU40R8muKoAPLKJegfnZPaGr69I/FCc+TJ8YUJO8DNRR0/pw9pZXH5GkphQsYFxP2ExHPdEs3c4=",
    "citizen:US": "b6+6f0cXTTPRxecYkGynXFDJ3pEnK4xWPgiYu6/hrcY7Pyy6ouOiALIITwr/vPSlmiN3N89PSFcjhXKm7tMMbBq5v+Jwkru79YeqjDOkuYsdmC5xTy6uRtnvWt7ea3uZjSeXoKqO++6eBmZeToBCfAlApDbMr0FVbMbR7kShmgc=",
    "email:r@gmail.com": "Aee4iEZ/VBUlQmAUoz3Z3YrdpzvgwI6RotSMaxGFni2OXR1GbKbKYJu/FnKuOGVY21Hu4EDRvBEFRGZdYhaKxFOWx/xVg1TNs/vmi/h3loN5qSDue/95uFudt74t80uGHjoIpxekZ+TEyg8gnXoAZG6/XuQqFJWjOEumfCuOGL8=",
    "not-citizen:PK": "aemsQgQfjmBa/C9t3FSujywjuR24EcDDPyYn4trcDpCAwPzjb/In2QfsgHt99EB9N5MAPxW3rlMG5A2nAy0AKgHh4r7myEE+JaHEqaOOh3yJu7eSnfbSYtqXqeeIPyRZbQj37uUBayccg1crs8DXWBqVvcuyNFu0e1qBJxuXQ4c=",
    "not-citizen:SA": "gIxPtXKSHHl91opFz+2+7F1qi4Uls47zzz4j8EokJ7OMRZDBZCLLDOPc8CCq7/CXYkW+iOosDjN6llhSVqXaWFiGif+6nxSrW9TBSFh7qimbboqSR29H2yPUWJc9TyfiQimdYNjG2ncIvUBGKLpffWJm5m7Z6hHTcSXrz+V9AXY="
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
  "Read": "jodV1/M38z5A1n2Wq5elPuy4i2efYgbH5Qx/5lvCs60=",
  "Write": "ZH0Bp111W4gh4nzKYW0ZfaEt/gWK2GrkUO5CpgpUT4E="
}
```
Keys yielded by unlock with certW
```json

{
  "Read": "jodV1/M38z5A1n2Wq5elPuy4i2efYgbH5Qx/5lvCs60=",
  "Write": "ZH0Bp111W4gh4nzKYW0ZfaEt/gWK2GrkUO5CpgpUT4E="
}
```
Keys yielded by unlock with certR
```json

{
  "Read": "jodV1/M38z5A1n2Wq5elPuy4i2efYgbH5Qx/5lvCs60="
}
```

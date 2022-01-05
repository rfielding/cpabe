
CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Write User Cert
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "lM+uVfsocWMdhR4Sufpe7kTx15KP2lsE/SbGfeMJFvk=",
  "exp": 1646596899,
  "shares": {
    "age:adult": "X4/BJdu/sy1GzdOFm0AeO7Km7dpFleRWVu1eXkbQAXI7Tsflq9b6fCa3VXx2m0/LTVd9TupP/PEWNrkTjowjtSNxKErMIKPJAnn0tTopd1F2D270Af21MWp5vSTfzFfRLsr6qIpdVkMYK0IxwnIEn2WtIrf4/6EErEQ59bJP+kg=",
    "citizen:US": "VwRdxQ7Pm65kFJGPdLc+gEWHt5x3T5xrsxVVuMyYPzEHaPuUIR17O4qxgsQ06ZyElA+zKNdnnuSql+5x3h667zbE69/kGLvZvUgH8zIyk2vR84HOg8puaVUXOgawbMZ9Kj0Uo2khR8X/tf9w5V2kyMZcFxHYrAqRebZSZ4S3hpI=",
    "email:r@gmail.com": "NtrXpOeKaUTybNZCuljS1DQ2kh468/T58Y/Abv9GEDUehS31E/sXhB6JPkBh6S5Y8hg2/O4I1pbPQrrp1Gqx4FKtT9hXcEwQ9ia68+C/MOykwaVMfUk6uukLceEMQxRoAti7fvOGhtruqhUb0H3KuNhY62/RjX82p5uegRuoQBM=",
    "not-citizen:PK": "JCQowKFItL8+U/fnx/eGO15RDrGlsFB7BZSlu9U9meoUYy3rgfWBMExQ2NlwqFritAgnucya4/EKfxCm3DF4/AyEZekEQsqNrdEkqh+A8nW/D/C1Gd6m8TzCpFRuS1MzW+045qjT6vP0Rn6M/btQXrxMg2YxXZMgF3p44Rv5Xwg=",
    "not-citizen:SA": "RNXo96UnAmFKP7mzBEiFRkReG9RHUwp9PK8vOAgopSZE5Kie2oLBTU8e01KuiKFNQcTqm8KZiM1Rx6TVRlwcmxQVVz6uBSnRi9nvbz9cORW8oHZ42AALIgffwn6FOtT3Rs2kCzE1mxP7wzrWmYJeTr81WAevneItRU1M4mlA03k="
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
  "Read": "Uv6cw7FK/DVJXx7u01X437Z6KWKcOv1QsVfACCRkjNY=",
  "Write": "BIavPcz4phWkEb8VQMVLcPgR7DkaAO4eokk74eURUd8="
}
```
Keys yielded by unlock with certW
```json

{
  "Read": "Uv6cw7FK/DVJXx7u01X437Z6KWKcOv1QsVfACCRkjNY=",
  "Write": "BIavPcz4phWkEb8VQMVLcPgR7DkaAO4eokk74eURUd8="
}
```
Keys yielded by unlock with certR
```json

{
  "Read": "Uv6cw7FK/DVJXx7u01X437Z6KWKcOv1QsVfACCRkjNY="
}
```

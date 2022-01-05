
CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Cert
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "slQ7lXKtitTZdy7w/+LbGJB6GGnssyJvei3HjfB4xwA=",
  "exp": 1646596017,
  "shares": {
    "age:adult": "C917uptU8Axb3VUlC44ax/7n8Ukksj1MGAcsCv33/HU3Xk8uj/9hWzA98ZrwobNA3hEFwXssunwsLUemNqtuYgBqkNGmtXUX8a2sEJ15u1ZVSKCmuDqb89b9APXDgQFWfnxyJ6lsBvusxrtjKQ14Dizpdd1UqrWX3MqN9as+EWA=",
    "citizen:US": "eBNknaXtlI3yXnigf+FQtwlUUoAEFLCMkS/SPsJftEB+9U4OW17eW63SKschz1y8Gdj9Xo6j1yO8s6xTCCvXySj1dQ5x7304EpY2OjqdZeYI3O/3eZUURJ1dZ2nK93MRQR5cCO/AlNAF/+j4NO0VDqyHeaRpVmRghv2wpOzYxQM=",
    "email:r@gmail.com": "NLHQtWJJJeppCOY8rNAN6E+zU9IC3aHRHU9+4bRRSKxiqVvL+nqvyAkE34noLB/vhIUxDHyo2nkiAKW1CCjUExEpGv4emKw7VLdXdUby/ZYVvmoJTaQtgE7j5Npfv34bholNWtdqEfNatjleup13Wa5Yq61ZjMJYZghD9Pu7b3M=",
    "not-citizen:PK": "IIZjIPwvY8Yud7M0oGOI1lAz3xONkYp1xEyi1Jtff+g4W26FrX/C09Y97Y4C3/3dTFW3ofEXWD2mfi8dF3/mSxAhy8mGbex1Jmwq+hygdttdE3Igz83nFVLwp2aZpteKC2OrW+yJfanypQo5XS1Nr/rvhREsORJB3dpbBJNyLno=",
    "not-citizen:SA": "aooUgiZvjxTiLNlhpxtieE49w65r4Updcy3ZAtNchvks6th7hKwcy1c9s2mDgnYiN/jsVf/Rmf0eWH+6LLH6eSTYRAtYY1uktCTJCSiV/GyNEpEKvo8ZnwW/b+OgA5AkDjA5HUNQZy89hKSBAscgN7BppFfrp7YJ8dAeKzTHuQw="
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
Keys yielded by unlock with cert
```json

{
  "Read": "OO+wzfrsMyOqJZ/fTufL7Cm7JpJFjgBNJ5tUFX+tLlI=",
  "Write": "mJEbwHr8TxvBz4XZHbcSzlapiZZ73f/nVYfdUZ36BbM="
}
```

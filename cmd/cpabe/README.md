
CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Cert
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "dPgivs9HLfIiPYrRUe5hIlTgyBPJQkl0lYtsqkSEs98=",
  "exp": 1646595898,
  "shares": {
    "age:adult": "Cmxs/hd8PeSP4OEdlw4WrB/YTDp0aUSuvjjZdoDLfU4YaWxsRN6fjQkt6EFEe/UIox5z6NfMaMyv/zlc9YAPOx2I9bdIoLFc579mHtveKy+BesJnAx3HzSmqNxMuwgtpcZVK7XYjy1ultMWr3TZtl/LRoTUqv+bS9wSP8widR50=",
    "citizen:US": "h/IIVeO6RiKkyNwRNr3HqjaBPSW0CnM4WJuyx2dHrcp8hir+WlgjP3Ti1B3a78TUwcIO0gywlu1S7tooK6fn9A+uN1zRmWBh6TmuPGGEG0Rpins+62tx4PXTHPw67vL4jPlZPw28pJuHQrIwI2UzXeDKOXHwSZXFdWb8tdx81jU=",
    "email:r@gmail.com": "TVv5YUct/bA03E8trgJkDMLqOtXsmgtY17RibCrzPbtluriRJ99UsVRJAPB09uF3TFF8ByjQcOmydXY644fpLnFD5Eb3OJaF6Im53QJDPPTKDzVyIM8N5W8/wdC1HtctDH2Mx19DsjEI63mOJ6Zl1mMAnbVU1HIrP6/H3KyumoI=",
    "not-citizen:PK": "U6eutm8qaYXMHKJX79c4tGKlHdaxnM9NCyiB3BIdVXwVkYekZzuvaXDftfANEezSQ/3wkhbI5XjqtzINfDqtNmP/qwOiVhV7xjJmIXfJKe0El9vVPxSjnFr6gESIVkIPQOD+b62+MhlxZ9ZwvxyJNK+hJMnA52Xyn/eX6V2Bbyw=",
    "not-citizen:SA": "QXBbIFcKom5Kos+ZHIX1SynBU8wra3/0DAU+gsJAYMV+ZeV+wUg8P49dVnkDi2CTuXQ7w/2qJvyeijoM2gllMSdDJt/m7kNiN5/9N197yIF9eu0zzsQbfZyHDCiSdA7rNY4HhxGsNAg1PxQTkQxPsH9viCuMDyfzsREcYzZo/78="
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
Keys
```json
Keys: {
  "Read": "KV+ZmvwrdEeWB1DzFaxnODg5mYLIuRmsYDYyyQe5vS8=",
  "Write": "UeilkgLFKF0cl1dUqSwhTBFsMnT/Rg432CC2FPnVRYE="
}```

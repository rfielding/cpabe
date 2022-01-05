EC Pairings over bn256
==================

This uses bn256 pairing to generate a cpabe key.  There is a CA, a certificate, and a yaml format for the policies.  What is demonstrated is "monotone" access (`and`, `or`, with negated assertions - but cannot do `not`, because that cannot produce a specific witness.)


This is a definition of a padlock.

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

This is a certificate that unlocks it:

```json
{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "/7o9nIonruHRLRBP50talzZxPmvZiwjJv4BLFLvLib8=",
  "exp": 1646595133,
  "shares": {
    "age:adult": "RGY/Cb4XhdqrkDtYo8e4e4jMljf/MdjoHYFsRhhAnkCBLUs60vuEFh3yA+778dZiE1eDr0Yu9/nwnjJYL3JxN0ahHNvuHoZMBw+2SlRLc1uva/gGEG4jy5eQdBuzT7m1NtLy8cZDFI9mi6ah2zSL5ndZxbXP564nVOrZ2GTzsT8=",
    "citizen:US": "Er9qtCrfHTljdX+77ifwK2KbVTYcCggMYkLAvytAopEcu4vsGMC1SuRn7iFD4aLd+ls3ngN0JxhDZ+YcWs/Zm4eowqNjCrWvZOow0eNMtOpmKQqRwXEPTqrWeinl5oZNLoHPzEpMyrRA3FEUQ9/J/JWOII21Y8x00Vm/HyYaaJQ=",
    "email:r@gmail.com": "eXJxUMGacwudrnkPPmeRGutAsOAhnJ3664gOlY3PKLIkLf7rBM1QaBRBnNYAsV/CKiHdxKfofjQlSw/lu9uVd062dO+kmo5GRSAHA92bWsWe31n/moLXknVMcnQB9Qu+CbK72u8kp4PYbAi07Z3Z/7h0d/lFHsSxH+FDqeS5ON4=",
    "not-citizen:PK": "dyUuh38HALOTvIZMqLzmt4Ezw6te1aSB/OPuKanIMbUOD4G2xSzfjQMVHgeDAZ+ZuODiHyjuXR2Rm5vojWnBh2juDamMZ1vlZ8gyYpDR25Y+5bYr3Ia+vpgoeK/Dd4niG0wv0FkCddZOG4qFqPxroGRV76OnUj0proHaNTiTm1g=",
    "not-citizen:SA": "M4PC4I8GDy2ovjqEl1Olgpnl8QuPUHnHC/gVuuH8nYw0cE6IqIw3wYX0x7NoUxGciMpsMzniR6adfeLjJDUsEDsTvc97Q0yUhTvXxpW72ZvrGlAb1MW8oLNBr4NM0nBEJnL8mibqulCsejVzyFbqFcCNLuv3fjk/JLH5c8+N45U="
  }
}
```

And the CA that issued it:

```
CA:
64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
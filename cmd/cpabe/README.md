
CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Cert
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "DKPWpkomGAOUSfYsTmnVk0aMWysquHuvALnS2KKOUlc=",
  "exp": 1646595980,
  "shares": {
    "age:adult": "GppAOZzPEuXLkQH67sOIrtS6n+OjwPLOFZk944fT+FJOg9ozS/6Etkg4rXezW4zdEDX6ThfIPaMUu7MfTq14dgV52Fxn9tTdNLLPw374iNf8hctSFK6bfubn3QfotUjGDuKwiIIK8JRblRURZG4/d6N9lA6mXjp2owZeJY/ZQuA=",
    "citizen:US": "EFS92Jwx3ioRbo9w1GFGm13uOvGCnoaD7ldqANLJ7QZsV/rYoYjrv8FYvkgb8EaKAE0pcrYLaEDs/7Bu41bvNS4wsjoZw6DwXQs+umBDSXEu/aamcn4tgSLeSbB1nWEeZbgW6oaBrl/HGb0tvPbXltlPgXphtvfU5egURL+XhzE=",
    "email:r@gmail.com": "KHXuMYJLj2U2HK453QSdxFWKyyNDqCiEk0sMCAIrNb6LUMUDZUueztJbI7P0n5sdD2of81TI0s0GDWHcoYK6J3jvqZ2ycg7chqfURSHOnwpfi2LBSkZ43mB9USt9giuFeYv3I8pWfkdCD+As++Of+pWNg8/XXw2JeFwNG9rAfv8=",
    "not-citizen:PK": "Ofs8pD5IRQ9k18UjuTiAqBcJ9bFB87CECqGogPST6G91oxSP/rHriBNjZIsGaLDJqb2lK/VQqRZiQiH+hGB0wiPI715/IDb4vF6Oi3xCCn2LFmQeC77Lnjm9MIPvyMa6GA/17knSOPtFcILW03MnRXa4/+ys+7mFfvBda9RD9Gc=",
    "not-citizen:SA": "fFruyDCWQ0Wg7YMoDzZEBP78JjA8uXcRHZvB494XdOYaAhk39an3xlGavxHHvRyPzlibTLDphXdPBe0xRnLkPUiovSik911hv1wY9rdSjlVTEeYUV9esVgUtTkFbI4S/ZZ/hPs0O3UQNJlN2Y2cZoMPNVoBy3XPqM9DymH5E4fo="
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

{
  "Read": "1vNlgBE8l7pVsBLBIl35URoEmLvzmzGtYlX+mh6+79k=",
  "Write": "+MBdVC8QAHFdBh8X4QV+hyre6Q4DYVPllV66RH2U+Ik="
}
```

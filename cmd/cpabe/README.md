
CA
```

64f8ed8bf1d47380416ca5ea6178837a3baa926c7c08e70f4dd02b95c2680ced26e95e98707dc90e07349b7ef862fea2eb3aaca7f8cfdb7faf1e5634104fbd34
```
Cert
```json

{
  "pubca": "ZPjti/HUc4BBbKXqYXiDejuqkmx8COcPTdArlcJoDO0m6V6YcH3JDgc0m374Yv6i6zqsp/jP23+vHlY0EE+9NA==",
  "nonce": "4NAqaxP3d/B6hIuCjPfCrofgj9aTf+6KXNgiNepr04k=",
  "exp": 1646595951,
  "shares": {
    "age:adult": "Bn80y+6AdGJVkJhWDVDcyyVM7AFFbufUGbWoO/Q31XEfgw8uJOUF134WgUNR6FdzSA42OjqFxXyZAxKuWCCShUG1fx4q07yXOzgA60zPhesMos9Qg3u4Z882WbBrQiPEGGd1rajZ5q8eHvp0AZdWoMn/hMygn5w5kNjqcGvCbqA=",
    "citizen:US": "S9r9Vbwbhd5Ljjr6rJo/bhhcJjIc5fwLhKX1BQFrIFNjYACwyMmAY7fSa6UBa0QhmDq/HGRgmSDC9xQV7x3DzSxQ/xvXKF06nraVfEZZJ7N7uy8gy7sU1hmE/JhhSPubHAimXUXqLuZmm4HRm38u4UfwmaNnZaC2NFgapn4JVIg=",
    "email:r@gmail.com": "C6PJ4Z6LB7BBArLy9fmYxYD6eeKd17h1mCdqPplJTOhLnTCQEYi0BM3RQTnYn9ex582YNaP4I4IAK6L4VK4gLV2ISnH9ExUHG5RPNWc5dnQa8v1/Xg9NHeJwn25dIA0IAXz4fBHjoC2w60YZfft6zCuFpcbLyr74t3rV5u18PIc=",
    "not-citizen:PK": "cNUWjk/dB3f21m62rCrpooHEVgG+fJVIbtJmfeuSEm1oosQ/BGdJpOI28rZ+UC5B1MeYgZMUbGOEQBwH5j/m+wi+U5utwjBhn4jE39VjZpDSkek4kczKYBXR1FmP7IbWJ48k3D1SijFrchrUZ8tDU7ZIxtwpkU3a6WZfLakORRg=",
    "not-citizen:SA": "P1H7xCtgpop6ah7h+SyvYoHXErdvXB6vDogvPwHqvHs9FSrKYwZhp92YZ5W9+FjpZswUEAGNIKPSaJF9SVdnPAC6IXqlSmPAe1owHuL0dIsEba00y8gYgT5h1Dj5kSU5fwW7tRn5piRLvdCS60JOkgDdV2HiqHfm6RcFUXJXsoQ="
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
  "Read": "QrBY2/iwWsuONRjht7995sl0jPeVYrAKfAft1TQIWTk=",
  "Write": "pPOqfjlS99BTghdfbMwmevbKXHBQnetPfpc8UqePmwE="
}```

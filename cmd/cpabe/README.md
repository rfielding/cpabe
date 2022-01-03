

# Input Language

The input language should probably be simplified to fit well with
handling it once it is parsed from yaml.  This means being more careful
when defining requires, such that it's a specialized LISP, but isn't so
difficult to get into or-of-and form, for creating padlocks.

```yaml
policy:
  security: [SECRET//SQUIRREL, red, white]
  unlocks:
    is_legal:
      keys: [Read]
      requirement: {
        and: [
          {every: [age, adult]},
          {some: [citizen, US, NL]},
          {every: [not-citizen, SA, PK}
        ]
      }
    is_owner:
      keys: [Write]
      requirement: {
        and: [
          {require: is_legal},
          {some: [email, r@gmail.com, d@gmail.com]}
        ]
      }
```
The strategy:
- convert `some` to `or`
- convert `every` to `and`
- gather and and or together
- distribute and over or
- distribute or over or 

Result, flattened into `and` cases that can calculate unlock keys:

```yaml
policy:
  security: [SECRET//SQUIRREL, red, white]
  unlocks:
    is_legal:
      keys: [Read]
      requirement: {
        or: [
          {and: [age:adult, citizen:US, not-citizen:SA, not-citizen:PK]},	
          {and: [age:adult, citizen:NL, not-citizen:SA, not-citizen:PK]},	
        ]
      }
    is_owner:
      keys: [Write]
      requirement: {
        or: [
          {and: [age:adult, citizen:US, not-citizen:SA, not-citizen:PK, email:r@gmail.com]},	
          {and: [age:adult, citizen:NL, not-citizen:SA, not-citizen:PK, email:d@gmail.com]},	
          {and: [age:adult, citizen:US, not-citizen:SA, not-citizen:PK, email:r@gmail.com]},	
          {and: [age:adult, citizen:NL, not-citizen:SA, not-citizen:PK, email:d@gmail.com]},	
        ]
      }
```
The Go struct to make this easier to implement:

```go
type Policy struct {
  Security []string // label, background, foreground
  Unlocks map[string]Unlock
}

type Unlock struct {
  Keys []Key
  Requirement Requirement
}

type Key string // name of what was unlocked

// Recursive node type. Blank by default during serialization
type Requirement struct {
  Term string // leaf statement in the form: field:value
  Require Requirement // reference that can be literally pulled in
  And []Requirement
  Or []Requirement // ultimately, everything will be: [or [and ...],[and ...]]
  Some Some // [some field v0 v1] -> [or field:v0 field:v1]
  Every Every // [every field v0 v1] -> [and field:v0 field:v1]
}

type Some []string // [field v0 v1]
type Every []string // [field v0 v1]
```

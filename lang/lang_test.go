package lang_test

import (
	"log"
	"testing"

	"github.com/rfielding/cpabe/lang"
)

// Gah! VSCode tries to indent this with tabs, and always makes it fail to parse.
var statements = []string{`
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
        - not-citizenship
        - SA
        - PK
  is_owner: 
    keys: 
    - Write
    requirement:
      and:
      - require: is_legal
      - some:
        - email
        - r@gmail.com
        - d@gmail.com
`,
}

func TestPolicyLoad(t *testing.T) {
	for _, statement := range statements {
		p, err := lang.Parse(statement)
		if err != nil {
			t.Errorf(
				"Error parsing statement: %s %v",
				lang.AsYaml(statement),
				err,
			)
		}
		log.Printf("\n%s", lang.AsYaml(p))
	}

}

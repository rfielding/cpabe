package lang

import (
	"fmt"
	"log"

	"gopkg.in/yaml.v2"
)

func AsYaml(v interface{}) string {
	y, err := yaml.Marshal(v)
	if err != nil {
		log.Printf("error: %v", err)
	}
	return string(y)
}

type Policy struct {
	Display *Display           `yaml:"display,omitempty"` // label, background, foreground
	Unlocks map[string]*Unlock `yaml:"unlocks,omitempty"`
}

type Display struct {
	Label      string `yaml:"label,omitempty"`
	Background string `yaml:"background,omitempty"`
	Foreground string `yaml:"foreground,omitempty"`
}

type Unlock struct {
	Keys        []Key        `yaml:"keys,omitempty"`
	Requirement *Requirement `yaml:"requirement,omitempty"`
}

type Key string // name of what was unlocked

// Recursive node type. Blank by default during serialization
type Requirement struct {
	Is      string         `yaml:"is,omitempty"`      // leaf statement in the form: field:value
	Require string         `yaml:"require,omitempty"` // reference that can be literally pulled in
	And     []*Requirement `yaml:"and,omitempty"`
	Or      []*Requirement `yaml:"or,omitempty"`    // ultimately, everything will be: [or [and ...],[and ...]]
	Some    Some           `yaml:"some,omitempty"`  // [some field v0 v1] -> [or field:v0 field:v1]
	Every   Every          `yaml:"every,omitempty"` // [every field v0 v1] -> [and field:v0 field:v1]
}

type Some []string  // [field v0 v1]
type Every []string // [field v0 v1]

type ParseError struct {
	Message string
}

func (p *ParseError) Error() string {
	return p.Message
}

func DeepCopy(dst, src *Requirement) {
	if src == nil {
		log.Printf("src is nil in DeepCopy of requirement")
	}
	if dst == nil {
		log.Printf("dst is nil in DeepCopy of requirement")
	}
	var rCopy Requirement
	y := AsYaml(src)
	err := yaml.Unmarshal([]byte(y), &rCopy)
	if err != nil {
		log.Printf("error trying to copy requirement: %v", err)
	}
	dst.Require = src.Require
	dst.Is = src.Is
	dst.And = src.And
	dst.Or = src.Or
	dst.Some = src.Some
	dst.Every = src.Every
	dst.Require = src.Require

}

func ValidateRequirement(r *Requirement, unlocks map[string]*Unlock) (*Requirement, error) {
	// 'and' is recursive - depth first
	if r.And != nil {
		if len(r.And) < 1 {
			return r, &ParseError{
				Message: "'and' must have at least one value",
			}
		}
		for _, and := range r.And {
			r2, err := ValidateRequirement(and, unlocks)
			if err != nil {
				return r2, err
			}
		}
	}
	// 'or' is recursive - depth first
	if r.Or != nil && len(r.Or) < 1 {
		if len(r.Or) < 1 {
			return r, &ParseError{
				Message: "'or' must have at least one value",
			}
		}
		for _, or := range r.Or {
			r2, err := ValidateRequirement(or, unlocks)
			if err != nil {
				return r2, err
			}
		}
	}
	// References deep copy the thing it references
	if r.Require != "" {
		name := r.Require
		if _, ok := unlocks[name]; !ok {
			return r, &ParseError{
				Message: fmt.Sprintf("'require' must be a valid unlock name: %s", name),
			}
		}
		DeepCopy(r, unlocks[name].Requirement)
	}

	// 'some' is a macro for 'or'
	if r.Some != nil {
		if len(r.Some) < 2 {
			return r, &ParseError{
				Message: "'some' must have at least two value, where first is field name",
			}
		}
		for i := 1; i < len(r.Some); i++ {
			rName := &Requirement{Is: fmt.Sprintf("%s:%s", r.Some[0], r.Some[i])}
			r.Or = append(r.Or, rName)
		}
		r.Some = nil
	}
	// 'every' is a macro for 'and'
	if r.Every != nil {
		if len(r.Every) < 2 {
			return r, &ParseError{
				Message: "'every' must have at least two values, where first is field name",
			}
		}
		for i := 1; i < len(r.Every); i++ {
			r.And = append(r.And, &Requirement{Is: fmt.Sprintf("%s:%s", r.Every[0], r.Every[i])})
		}
		r.Every = nil
	}
	// Merge nested 'and'
	if r.And != nil {
		newAnd := make([]*Requirement, 0)
		for _, and := range r.And {
			if and.And != nil {
				newAnd = append(newAnd, and.And...)
			} else {
				newAnd = append(newAnd, and)
			}
		}
		r.And = newAnd
	}
	// Merge nested 'or'
	if r.Or != nil {
		newOr := make([]*Requirement, 0)
		for _, or := range r.Or {
			if or.Or != nil {
				newOr = append(newOr, or.Or...)
			} else {
				newOr = append(newOr, or)
			}
		}
		r.Or = newOr
	}
	// distribute 'and' over 'or'
	if r.And != nil {
		ands := make([]*Requirement, 0)
		ors := make([]*Requirement, 0)
		for _, s := range r.And {
			if s.Or != nil {
				for j := 0; j < len(s.Or); j++ {
					ors = append(
						ors,
						&Requirement{And: []*Requirement{s.Or[j]}},
					)
				}
			} else {
				ands = append(ands, s)
			}
		}
		if len(ors) > 0 && len(ands) > 0 {
			for j := 0; j < len(ors); j++ {
				ors[j].And = append(ors[j].And, ands...)
			}
			r.Or = ors
			r.And = nil
		}
		// now, we can merge `or`s within `and`
	}
	// TODO:
	// "foil" into first entry, as we are left with
	// `and` over `or`
	for len(r.And) > 1 && r.And[0].Or != nil && r.And[1] != nil {
		accumulated := make([]*Requirement, 0)
		for i := 0; i < len(r.And[0].Or); i++ {
			for j := 0; j < len(r.And[1].Or); j++ {
				rCopy := &Requirement{}
				DeepCopy(rCopy, r.And[0].Or[i])
				rCopy.And = append(
					rCopy.And,
					r.And[1].Or[j],
				)
				accumulated = append(accumulated, rCopy)
			}
		}
		r.And[1].Or = accumulated
		r.And = r.And[1:]
	}
	if len(r.And) == 1 && r.And[0].Or != nil {
		r.Or = r.And[0].Or
		r.And = nil
	}
	return r, nil
}

func PostValidate(policy *Policy) error {
	if policy.Display == nil {
		return &ParseError{
			Message: "Display is required",
		}
	}
	if policy.Unlocks == nil {
		return &ParseError{
			Message: "Unlocks is required",
		}
	}
	for _, unlock := range policy.Unlocks {
		if unlock.Keys == nil {
			return &ParseError{
				Message: "Unlock keys is required",
			}
		}
		if unlock.Requirement == nil {
			return &ParseError{
				Message: "Unlock requirement is required",
			}
		}
		_, err := ValidateRequirement(unlock.Requirement, policy.Unlocks)
		if err != nil {
			return err
		}
	}
	return nil
}

func Normalize(requirement *Requirement) (*Requirement, error) {
	return requirement, nil
}

func Parse(statement string) (*Policy, error) {
	var policy Policy
	err := yaml.Unmarshal([]byte(statement), &policy)
	if err != nil {
		return nil, err
	}
	err = PostValidate(&policy)
	if err != nil {
		return &policy, err
	}
	for _, unlock := range policy.Unlocks {
		r, err := Normalize(unlock.Requirement)
		if err != nil {
			return &policy, err
		}
		unlock.Requirement = r
	}
	return &policy, nil
}

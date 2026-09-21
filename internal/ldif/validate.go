package ldif

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Issue is one validation finding for an LDIF record.
type Issue struct {
	Line     int
	DN       string
	Severity string // error | warning
	Msg      string
}

func (i Issue) String() string {
	return fmt.Sprintf("line %d  %-7s %s  (%s)", i.Line, i.Severity, i.Msg, i.DN)
}

var attrNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$|^\d+(\.\d+)+(;[A-Za-z0-9-]+)*$`)

// Validate checks parsed records for problems that would fail (errors) or
// look suspicious (warnings) when applied to a directory. It is purely
// syntactic — it does not consult a server schema.
func Validate(recs []Record) []Issue {
	var out []Issue
	add := func(r Record, sev, msg string) {
		out = append(out, Issue{Line: r.Line, DN: r.DN, Severity: sev, Msg: msg})
	}
	seen := map[string]int{}
	for _, r := range recs {
		parsed, err := ldap.ParseDN(r.DN)
		switch {
		case r.DN == "":
			add(r, "error", "empty DN")
			continue
		case err != nil:
			add(r, "error", "invalid DN syntax: "+err.Error())
			continue
		}
		key := strings.ToLower(parsed.String())
		if r.Change == "add" {
			if prev, dup := seen[key]; dup {
				add(r, "error", fmt.Sprintf("duplicate add of the same DN (first at line %d)", prev))
			}
			seen[key] = r.Line
		}
		switch r.Change {
		case "add":
			hasOC := false
			names := map[string][]byte{}
			for _, a := range r.Attrs {
				if !attrNameRe.MatchString(a.Name) {
					add(r, "error", fmt.Sprintf("invalid attribute name %q", a.Name))
				}
				if strings.EqualFold(a.Name, "objectClass") {
					hasOC = len(a.Values) > 0
				}
				for _, v := range a.Values {
					if len(v) == 0 {
						add(r, "error", fmt.Sprintf("attribute %s has an empty value", a.Name))
					}
				}
				if len(a.Values) > 0 {
					names[strings.ToLower(a.Name)] = a.Values[0]
				}
			}
			if !hasOC {
				add(r, "error", "add record has no objectClass")
			}
			if len(parsed.RDNs) > 0 {
				for _, ra := range parsed.RDNs[0].Attributes {
					found := false
					for _, a := range r.Attrs {
						if strings.EqualFold(a.Name, ra.Type) {
							for _, v := range a.Values {
								if strings.EqualFold(string(v), ra.Value) {
									found = true
								}
							}
						}
					}
					if !found {
						add(r, "warning", fmt.Sprintf("RDN value %s=%s is not among the record's attributes", ra.Type, ra.Value))
					}
				}
			}
		case "modify":
			if len(r.Mods) == 0 {
				add(r, "error", "modify record has no modifications")
			}
			for _, m := range r.Mods {
				if !attrNameRe.MatchString(m.Attr) {
					add(r, "error", fmt.Sprintf("invalid attribute name %q", m.Attr))
				}
				if (m.Op == "add" || m.Op == "replace") && len(m.Values) == 0 && m.Op == "add" {
					add(r, "error", fmt.Sprintf("add: %s has no values", m.Attr))
				}
				if m.Op == "replace" && len(m.Values) == 0 {
					add(r, "warning", fmt.Sprintf("replace: %s with no values removes the attribute", m.Attr))
				}
			}
		case "modrdn":
			if _, err := ldap.ParseDN(r.NewRDN); err != nil {
				add(r, "error", "invalid newrdn: "+err.Error())
			}
			if r.NewSuperior != "" {
				if _, err := ldap.ParseDN(r.NewSuperior); err != nil {
					add(r, "error", "invalid newsuperior: "+err.Error())
				}
			}
		}
	}
	return out
}

// Summary counts records by change type.
func Summary(recs []Record) map[string]int {
	m := map[string]int{}
	for _, r := range recs {
		m[r.Change]++
	}
	return m
}

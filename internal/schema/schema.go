// Package schema parses RFC 4512 schema definitions (objectClasses,
// attributeTypes, ldapSyntaxes, matchingRules) read from a subschema entry.
package schema

import (
	"sort"
	"strings"
)

type ObjectClass struct {
	OID      string
	Names    []string
	Desc     string
	Sup      []string
	Kind     string // ABSTRACT | STRUCTURAL | AUXILIARY
	Must     []string
	May      []string
	Obsolete bool
	Raw      string
}

type AttributeType struct {
	OID         string
	Names       []string
	Desc        string
	Sup         string
	Equality    string
	Ordering    string
	Substr      string
	Syntax      string
	SingleValue bool
	NoUserMod   bool
	Collective  bool
	Obsolete    bool
	Usage       string
	Raw         string
}

type MatchingRule struct {
	OID    string
	Names  []string
	Desc   string
	Syntax string
	Raw    string
}

// Name returns the primary name (or OID when unnamed).
func (o *ObjectClass) Name() string   { return first(o.Names, o.OID) }
func (a *AttributeType) Name() string { return first(a.Names, a.OID) }
func (m *MatchingRule) Name() string  { return first(m.Names, m.OID) }

func first(n []string, def string) string {
	if len(n) > 0 {
		return n[0]
	}
	return def
}

// Schema is an indexed, parsed schema.
type Schema struct {
	Classes   map[string]*ObjectClass
	Attrs     map[string]*AttributeType
	Rules     map[string]*MatchingRule
	Syntaxes  map[string]string // oid -> description
	ClassList []*ObjectClass
	AttrList  []*AttributeType
	RuleList  []*MatchingRule
}

var builtinSyntax = map[string]string{
	"1.3.6.1.4.1.1466.115.121.1.5":  "Binary",
	"1.3.6.1.4.1.1466.115.121.1.7":  "Boolean",
	"1.3.6.1.4.1.1466.115.121.1.8":  "Certificate",
	"1.3.6.1.4.1.1466.115.121.1.12": "DN",
	"1.3.6.1.4.1.1466.115.121.1.15": "Directory String",
	"1.3.6.1.4.1.1466.115.121.1.24": "Generalized Time",
	"1.3.6.1.4.1.1466.115.121.1.26": "IA5 String",
	"1.3.6.1.4.1.1466.115.121.1.27": "Integer",
	"1.3.6.1.4.1.1466.115.121.1.28": "JPEG",
	"1.3.6.1.4.1.1466.115.121.1.36": "Numeric String",
	"1.3.6.1.4.1.1466.115.121.1.38": "OID",
	"1.3.6.1.4.1.1466.115.121.1.39": "Other Mailbox?",
	"1.3.6.1.4.1.1466.115.121.1.40": "Octet String",
	"1.3.6.1.4.1.1466.115.121.1.50": "Telephone Number",
	"1.3.6.1.4.1.1466.115.121.1.58": "Substring Assertion",
	"2.5.5.1":                       "DN (AD)",
	"2.5.5.8":                       "Boolean (AD)",
	"2.5.5.9":                       "Integer (AD)",
	"2.5.5.10":                      "Octet String (AD)",
	"2.5.5.12":                      "Unicode String (AD)",
	"1.2.840.113556.1.4.906":        "Large Integer (AD)",
}

// SyntaxName returns a friendly name for a syntax OID.
func (s *Schema) SyntaxName(oid string) string {
	if d := s.Syntaxes[oid]; d != "" {
		return d
	}
	return builtinSyntax[oid]
}

// Parse builds a Schema from raw definition strings. Malformed definitions
// are skipped.
func Parse(objectClasses, attributeTypes, syntaxes, matchingRules []string) *Schema {
	s := &Schema{Classes: map[string]*ObjectClass{}, Attrs: map[string]*AttributeType{}, Rules: map[string]*MatchingRule{}, Syntaxes: map[string]string{}}
	for _, d := range objectClasses {
		if oc := parseOC(d); oc != nil {
			s.ClassList = append(s.ClassList, oc)
			s.Classes[strings.ToLower(oc.OID)] = oc
			for _, n := range oc.Names {
				s.Classes[strings.ToLower(n)] = oc
			}
		}
	}
	for _, d := range attributeTypes {
		if at := parseAT(d); at != nil {
			s.AttrList = append(s.AttrList, at)
			s.Attrs[strings.ToLower(at.OID)] = at
			for _, n := range at.Names {
				s.Attrs[strings.ToLower(n)] = at
			}
		}
	}
	for _, d := range matchingRules {
		if mr := parseMR(d); mr != nil {
			s.RuleList = append(s.RuleList, mr)
			s.Rules[strings.ToLower(mr.OID)] = mr
			for _, n := range mr.Names {
				s.Rules[strings.ToLower(n)] = mr
			}
		}
	}
	for _, d := range syntaxes {
		t := tokenize(d)
		if len(t) >= 2 && t[0].k == '(' {
			oid := t[1].s
			desc := ""
			for i := 2; i+1 < len(t); i++ {
				if strings.EqualFold(t[i].s, "DESC") && t[i].k == 'w' {
					desc = t[i+1].s
				}
			}
			s.Syntaxes[oid] = desc
		}
	}
	sort.Slice(s.ClassList, func(i, j int) bool {
		return strings.ToLower(s.ClassList[i].Name()) < strings.ToLower(s.ClassList[j].Name())
	})
	sort.Slice(s.AttrList, func(i, j int) bool {
		return strings.ToLower(s.AttrList[i].Name()) < strings.ToLower(s.AttrList[j].Name())
	})
	sort.Slice(s.RuleList, func(i, j int) bool {
		return strings.ToLower(s.RuleList[i].Name()) < strings.ToLower(s.RuleList[j].Name())
	})
	return s
}

// Class looks up an object class by name or OID.
func (s *Schema) Class(n string) *ObjectClass { return s.Classes[strings.ToLower(n)] }

// Attr looks up an attribute type by name or OID.
func (s *Schema) Attr(n string) *AttributeType {
	n = strings.ToLower(n)
	if i := strings.IndexByte(n, ';'); i >= 0 { // strip options (e.g. ;binary)
		n = n[:i]
	}
	return s.Attrs[n]
}

// CanonAttr returns the primary attribute name (or the input when unknown).
func (s *Schema) CanonAttr(n string) string {
	if a := s.Attr(n); a != nil {
		return a.Name()
	}
	return n
}

// Lineage returns the class followed by its superclasses (nearest first).
func (s *Schema) Lineage(name string) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(n string)
	walk = func(n string) {
		oc := s.Class(n)
		if oc == nil || seen[strings.ToLower(oc.OID)] {
			return
		}
		seen[strings.ToLower(oc.OID)] = true
		out = append(out, oc.Name())
		for _, sup := range oc.Sup {
			walk(sup)
		}
	}
	walk(name)
	return out
}

// Resolve returns the union of MUST and MAY attributes of the given classes
// including inherited ones. Names are canonicalised and de-duplicated; MAY
// excludes attributes already in MUST.
func (s *Schema) Resolve(classes []string) (must, may []string) {
	seenM, seenY := map[string]bool{}, map[string]bool{}
	for _, c := range classes {
		for _, ln := range s.Lineage(c) {
			oc := s.Class(ln)
			if oc == nil {
				continue
			}
			for _, a := range oc.Must {
				k := strings.ToLower(s.CanonAttr(a))
				if !seenM[k] {
					seenM[k] = true
					must = append(must, s.CanonAttr(a))
				}
			}
			for _, a := range oc.May {
				k := strings.ToLower(s.CanonAttr(a))
				if !seenY[k] {
					seenY[k] = true
					may = append(may, s.CanonAttr(a))
				}
			}
		}
	}
	filtered := may[:0]
	for _, a := range may {
		if !seenM[strings.ToLower(a)] {
			filtered = append(filtered, a)
		}
	}
	return must, filtered
}

// Effective follows SUP links to resolve inherited syntax/matching rules.
func (s *Schema) Effective(name string) AttributeType {
	at := s.Attr(name)
	if at == nil {
		return AttributeType{}
	}
	out := *at
	cur := at
	for i := 0; i < 16 && cur.Sup != ""; i++ {
		p := s.Attr(cur.Sup)
		if p == nil {
			break
		}
		if out.Syntax == "" {
			out.Syntax = p.Syntax
		}
		if out.Equality == "" {
			out.Equality = p.Equality
		}
		if out.Ordering == "" {
			out.Ordering = p.Ordering
		}
		if out.Substr == "" {
			out.Substr = p.Substr
		}
		cur = p
	}
	return out
}

// UsedBy lists object classes that reference the attribute in MUST/MAY.
func (s *Schema) UsedBy(attr string) (must, may []string) {
	canon := strings.ToLower(s.CanonAttr(attr))
	for _, oc := range s.ClassList {
		for _, a := range oc.Must {
			if strings.ToLower(s.CanonAttr(a)) == canon {
				must = append(must, oc.Name())
			}
		}
		for _, a := range oc.May {
			if strings.ToLower(s.CanonAttr(a)) == canon {
				may = append(may, oc.Name())
			}
		}
	}
	return
}

// ---- tokenizer / parser ----

type tok struct {
	k byte // '(' ')' '$' 'q' quoted, 'w' word
	s string
}

func tokenize(in string) []tok {
	var out []tok
	i := 0
	for i < len(in) {
		c := in[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == '$':
			out = append(out, tok{c, string(c)})
			i++
		case c == '\'':
			j := strings.IndexByte(in[i+1:], '\'')
			if j < 0 {
				out = append(out, tok{'q', in[i+1:]})
				return out
			}
			out = append(out, tok{'q', in[i+1 : i+1+j]})
			i += j + 2
		default:
			j := i
			for j < len(in) && !strings.ContainsRune(" \t\n\r()$'", rune(in[j])) {
				j++
			}
			out = append(out, tok{'w', in[i:j]})
			i = j
		}
	}
	return out
}

type parser struct {
	t []tok
	i int
}

func (p *parser) more() bool { return p.i < len(p.t) }
func (p *parser) peek() tok {
	if p.i < len(p.t) {
		return p.t[p.i]
	}
	return tok{}
}
func (p *parser) next() tok {
	t := p.peek()
	p.i++
	return t
}

// list reads either a single value or a parenthesised list.
func (p *parser) list() []string {
	if p.peek().k == '(' {
		p.next()
		var out []string
		for p.more() && p.peek().k != ')' {
			t := p.next()
			if t.k == 'w' || t.k == 'q' {
				out = append(out, t.s)
			}
		}
		p.next()
		return out
	}
	t := p.next()
	return []string{t.s}
}

func (p *parser) single() string {
	t := p.next()
	return t.s
}

func header(def string) (*parser, string, bool) {
	p := &parser{t: tokenize(def)}
	if p.next().k != '(' {
		return nil, "", false
	}
	oid := p.next().s
	if oid == "" {
		return nil, "", false
	}
	return p, oid, true
}

func parseOC(def string) *ObjectClass {
	p, oid, ok := header(def)
	if !ok {
		return nil
	}
	oc := &ObjectClass{OID: oid, Kind: "STRUCTURAL", Raw: def}
	for p.more() && p.peek().k != ')' {
		kw := strings.ToUpper(p.next().s)
		switch kw {
		case "NAME":
			oc.Names = p.list()
		case "DESC":
			oc.Desc = p.single()
		case "OBSOLETE":
			oc.Obsolete = true
		case "SUP":
			oc.Sup = p.list()
		case "ABSTRACT", "STRUCTURAL", "AUXILIARY":
			oc.Kind = kw
		case "MUST":
			oc.Must = p.list()
		case "MAY":
			oc.May = p.list()
		default:
			if strings.HasPrefix(kw, "X-") {
				p.list()
			}
		}
	}
	return oc
}

func parseAT(def string) *AttributeType {
	p, oid, ok := header(def)
	if !ok {
		return nil
	}
	at := &AttributeType{OID: oid, Raw: def}
	for p.more() && p.peek().k != ')' {
		kw := strings.ToUpper(p.next().s)
		switch kw {
		case "NAME":
			at.Names = p.list()
		case "DESC":
			at.Desc = p.single()
		case "OBSOLETE":
			at.Obsolete = true
		case "SUP":
			at.Sup = p.single()
		case "EQUALITY":
			at.Equality = p.single()
		case "ORDERING":
			at.Ordering = p.single()
		case "SUBSTR":
			at.Substr = p.single()
		case "SYNTAX":
			syn := p.single()
			if i := strings.IndexByte(syn, '{'); i >= 0 {
				syn = syn[:i]
			}
			at.Syntax = syn
		case "SINGLE-VALUE":
			at.SingleValue = true
		case "COLLECTIVE":
			at.Collective = true
		case "NO-USER-MODIFICATION":
			at.NoUserMod = true
		case "USAGE":
			at.Usage = p.single()
		default:
			if strings.HasPrefix(kw, "X-") {
				p.list()
			}
		}
	}
	return at
}

func parseMR(def string) *MatchingRule {
	p, oid, ok := header(def)
	if !ok {
		return nil
	}
	mr := &MatchingRule{OID: oid, Raw: def}
	for p.more() && p.peek().k != ')' {
		switch strings.ToUpper(p.next().s) {
		case "NAME":
			mr.Names = p.list()
		case "DESC":
			mr.Desc = p.single()
		case "SYNTAX":
			mr.Syntax = p.single()
		}
	}
	return mr
}

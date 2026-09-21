// Package filter builds, parses and validates LDAP search filters (RFC 4515).
package filter

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Node kinds.
const (
	And  = "and"
	Or   = "or"
	Not  = "not"
	Cond = "cond"
)

// Node is one element of a filter tree.
type Node struct {
	Kind     string
	Attr     string
	Op       string // =, >=, <=, ~=
	Value    string
	Raw      bool // Value is already escaped (parsed from a raw filter)
	Children []*Node
}

// NewGroup returns an empty AND/OR/NOT node.
func NewGroup(kind string) *Node { return &Node{Kind: kind} }

// NewCond returns a condition node with a plain (unescaped) value.
func NewCond(attr, op, value string) *Node {
	return &Node{Kind: Cond, Attr: attr, Op: op, Value: value}
}

func escapeValue(op, v string) string {
	if op == "=" && strings.Contains(v, "*") {
		parts := strings.Split(v, "*")
		for i := range parts {
			parts[i] = ldap.EscapeFilter(parts[i])
		}
		return strings.Join(parts, "*")
	}
	return ldap.EscapeFilter(v)
}

// String renders the node as an RFC 4515 filter string.
func (n *Node) String() string {
	if n == nil {
		return ""
	}
	switch n.Kind {
	case Cond:
		v := n.Value
		if !n.Raw {
			v = escapeValue(n.Op, v)
		}
		return "(" + n.Attr + n.Op + v + ")"
	case And, Or:
		sym := "&"
		if n.Kind == Or {
			sym = "|"
		}
		var b strings.Builder
		b.WriteString("(" + sym)
		for _, c := range n.Children {
			b.WriteString(c.String())
		}
		b.WriteString(")")
		return b.String()
	case Not:
		if len(n.Children) == 0 {
			return "(!(objectClass=*))"
		}
		if len(n.Children) == 1 {
			return "(!" + n.Children[0].String() + ")"
		}
		return "(!" + (&Node{Kind: And, Children: n.Children}).String() + ")"
	}
	return ""
}

// Add appends a child.
func (n *Node) Add(c *Node) { n.Children = append(n.Children, c) }

// Row is a flattened tree row for rendering.
type Row struct {
	Node   *Node
	Parent *Node
	Depth  int
}

// Flatten returns depth-first rows.
func Flatten(root *Node) []Row {
	var rows []Row
	var walk func(n, p *Node, d int)
	walk = func(n, p *Node, d int) {
		rows = append(rows, Row{n, p, d})
		for _, c := range n.Children {
			walk(c, n, d+1)
		}
	}
	if root != nil {
		walk(root, nil, 0)
	}
	return rows
}

// Remove deletes target from the tree (no-op for the root).
func Remove(root, target *Node) bool {
	for i, c := range root.Children {
		if c == target {
			root.Children = append(root.Children[:i], root.Children[i+1:]...)
			return true
		}
		if Remove(c, target) {
			return true
		}
	}
	return false
}

// Label is a short human description of the node.
func (n *Node) Label() string {
	switch n.Kind {
	case And:
		return "AND"
	case Or:
		return "OR"
	case Not:
		return "NOT"
	}
	if n.Op == "=" && n.Value == "*" {
		return n.Attr + " present"
	}
	return n.Attr + " " + n.Op + " " + n.Value
}

// ParseCondition parses "attr=value", "attr>=v", "attr" (presence), or a
// leading "!" for negation.
func ParseCondition(s string) (*Node, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty condition")
	}
	neg := false
	if strings.HasPrefix(s, "!") {
		neg = true
		s = strings.TrimSpace(s[1:])
	}
	best, bestOp := -1, ""
	for _, op := range []string{">=", "<=", "~=", "="} {
		if i := strings.Index(s, op); i >= 0 && (best < 0 || i < best) {
			best, bestOp = i, op
		}
	}
	var n *Node
	if best < 0 {
		n = NewCond(s, "=", "*")
	} else {
		attr := strings.TrimSpace(s[:best])
		val := strings.TrimSpace(s[best+len(bestOp):])
		if attr == "" {
			return nil, fmt.Errorf("missing attribute name")
		}
		n = NewCond(attr, bestOp, val)
	}
	if neg {
		return &Node{Kind: Not, Children: []*Node{n}}, nil
	}
	return n, nil
}

// Validate reports whether raw compiles as an LDAP filter.
func Validate(raw string) error {
	_, err := ldap.CompileFilter(raw)
	return err
}

// Parse converts a raw filter string into a tree (values kept verbatim).
func Parse(raw string) (*Node, error) {
	p := &parser{s: strings.TrimSpace(raw)}
	n, err := p.filter()
	if err != nil {
		return nil, err
	}
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing characters at %d", p.i)
	}
	return n, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *parser) filter() (*Node, error) {
	if p.peek() != '(' {
		return nil, fmt.Errorf("expected '(' at %d", p.i)
	}
	p.i++
	var n *Node
	switch p.peek() {
	case '&', '|':
		kind := And
		if p.peek() == '|' {
			kind = Or
		}
		p.i++
		n = &Node{Kind: kind}
		for p.peek() == '(' {
			c, err := p.filter()
			if err != nil {
				return nil, err
			}
			n.Add(c)
		}
	case '!':
		p.i++
		c, err := p.filter()
		if err != nil {
			return nil, err
		}
		n = &Node{Kind: Not, Children: []*Node{c}}
	default:
		j := strings.IndexByte(p.s[p.i:], ')')
		if j < 0 {
			return nil, fmt.Errorf("unterminated item at %d", p.i)
		}
		item := p.s[p.i : p.i+j]
		p.i += j
		k := strings.IndexByte(item, '=')
		if k <= 0 {
			return nil, fmt.Errorf("bad filter item %q", item)
		}
		attr, op := item[:k], "="
		if strings.ContainsRune("><~", rune(attr[len(attr)-1])) {
			op = attr[len(attr)-1:] + "="
			attr = attr[:len(attr)-1]
		}
		n = &Node{Kind: Cond, Attr: attr, Op: op, Value: item[k+1:], Raw: true}
	}
	if p.peek() != ')' {
		return nil, fmt.Errorf("expected ')' at %d", p.i)
	}
	p.i++
	return n, nil
}

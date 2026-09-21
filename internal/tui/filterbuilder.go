package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/filter"
)

type filterModel struct {
	root   *filter.Node
	cur    int
	width  int
	height int
	note   string
}

type addCondMsg struct{ expr string }
type editCondMsg struct {
	expr string
}
type setRawFilterMsg struct{ raw string }

func newFilterModel(raw string) filterModel {
	m := filterModel{root: filter.NewGroup(filter.And)}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return m
	}
	n, err := filter.Parse(raw)
	if err != nil {
		m.note = "could not parse current filter (" + err.Error() + ") — starting empty"
		return m
	}
	if n.Kind == filter.Cond || n.Kind == filter.Not {
		m.root.Add(n)
	} else {
		m.root = n
	}
	return m
}

func (m filterModel) rows() []filter.Row { return filter.Flatten(m.root) }

func (m filterModel) selected() (filter.Row, bool) {
	r := m.rows()
	if m.cur < 0 || m.cur >= len(r) {
		return filter.Row{}, false
	}
	return r[m.cur], true
}

// prune returns a copy of n without empty groups (nil when n itself is empty).
func prune(n *filter.Node) *filter.Node {
	if n.Kind == filter.Cond {
		return n
	}
	c := &filter.Node{Kind: n.Kind}
	for _, ch := range n.Children {
		if p := prune(ch); p != nil {
			c.Children = append(c.Children, p)
		}
	}
	if len(c.Children) == 0 {
		return nil
	}
	return c
}

// output renders the filter, dropping empty groups and collapsing trivial
// single-child groups.
func (m filterModel) output() string {
	n := prune(m.root)
	if n == nil {
		return ""
	}
	for (n.Kind == filter.And || n.Kind == filter.Or) && len(n.Children) == 1 {
		n = n.Children[0]
	}
	if (n.Kind == filter.And || n.Kind == filter.Or) && len(n.Children) == 0 {
		return ""
	}
	return n.String()
}

func condExpr(n *filter.Node) string {
	if n.Op == "=" && n.Value == "*" {
		return n.Attr
	}
	return n.Attr + n.Op + n.Value
}

func (m filterModel) target() *filter.Node {
	r, ok := m.selected()
	if !ok {
		return m.root
	}
	if r.Node.Kind != filter.Cond {
		return r.Node
	}
	if r.Parent != nil {
		return r.Parent
	}
	return m.root
}

func (m filterModel) update(msg tea.Msg) (filterModel, tea.Cmd) {
	switch msg := msg.(type) {
	case addCondMsg:
		n, err := filter.ParseCondition(msg.expr)
		if err != nil {
			return m, statusCmd(err.Error(), true)
		}
		m.target().Add(n)
		m.note = ""
		return m, nil
	case editCondMsg:
		n, err := filter.ParseCondition(msg.expr)
		if err != nil {
			return m, statusCmd(err.Error(), true)
		}
		if r, ok := m.selected(); ok && r.Node.Kind == filter.Cond {
			*r.Node = *n
		}
		return m, nil
	case setRawFilterMsg:
		n, err := filter.Parse(msg.raw)
		if err != nil {
			return m, statusCmd("invalid filter: "+err.Error(), true)
		}
		nm := newFilterModel("")
		if n.Kind == filter.Cond || n.Kind == filter.Not {
			nm.root.Add(n)
		} else {
			nm.root = n
		}
		nm.width, nm.height = m.width, m.height
		return nm, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m filterModel) handleKey(k tea.KeyMsg) (filterModel, tea.Cmd) {
	rows := m.rows()
	switch k.String() {
	case "j", "down":
		if m.cur < len(rows)-1 {
			m.cur++
		}
	case "k", "up":
		if m.cur > 0 {
			m.cur--
		}
	case "a":
		return m, openOverlay(newPrompt("add condition", "", "attr=value   attr>=v   attr (presence)   !attr=v (negate)   attr=a*b (substring)   attr:1.2.840.113556.1.4.803:=2",
			func(s string) tea.Cmd { return msgCmd(addCondMsg{expr: s}) }))
	case "A", "O", "N":
		kind := map[string]string{"A": filter.And, "O": filter.Or, "N": filter.Not}[k.String()]
		g := filter.NewGroup(kind)
		m.target().Add(g)
		for i, r := range m.rows() {
			if r.Node == g {
				m.cur = i
			}
		}
	case "t":
		if r, ok := m.selected(); ok {
			switch r.Node.Kind {
			case filter.And:
				r.Node.Kind = filter.Or
			case filter.Or:
				r.Node.Kind = filter.And
			}
		}
	case "d", "x":
		if r, ok := m.selected(); ok && r.Parent != nil {
			filter.Remove(m.root, r.Node)
			if m.cur > 0 {
				m.cur--
			}
		}
	case "e":
		if r, ok := m.selected(); ok && r.Node.Kind == filter.Cond {
			return m, openOverlay(newPrompt("edit condition", condExpr(r.Node), "", func(s string) tea.Cmd { return msgCmd(editCondMsg{expr: s}) }))
		}
	case "r":
		return m, openOverlay(newPrompt("raw filter", m.output(), "replace the whole tree from an RFC 4515 filter", func(s string) tea.Cmd { return msgCmd(setRawFilterMsg{raw: s}) }))
	case "c":
		return m, copyCmd(m.output(), "filter")
	case "enter", "u":
		out := m.output()
		if out == "" {
			return m, statusCmd("filter is empty", true)
		}
		if err := filter.Validate(out); err != nil {
			return m, statusCmd("invalid filter: "+err.Error(), true)
		}
		return m, msgCmd(applyFilterMsg{filter: out})
	case "esc", "q":
		return m, msgCmd(openScreenMsg{screenSearch})
	}
	return m, nil
}

func (m filterModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Filter builder") + "\n\n")
	rows := m.rows()
	for i, r := range rows {
		label := r.Node.Label()
		switch r.Node.Kind {
		case filter.And, filter.Or, filter.Not:
			label = fmt.Sprintf("%s  (%d)", label, len(r.Node.Children))
		}
		line := strings.Repeat("  ", r.Depth) + label
		if i == m.cur {
			line = selectedStyle.Render(line)
		} else if r.Node.Kind != filter.Cond {
			line = attrNameStyle.Render(line)
		}
		b.WriteString("  " + line + "\n")
	}
	out := m.output()
	b.WriteString("\n" + attrNameStyle.Render("Filter") + "\n  ")
	if out == "" {
		b.WriteString(dimStyle.Render("(empty)"))
	} else {
		b.WriteString(out)
		if err := filter.Validate(out); err != nil {
			b.WriteString("\n  " + warnStyle.Render("invalid: "+err.Error()))
		} else {
			b.WriteString("\n  " + okStyle.Render("valid"))
		}
	}
	if m.note != "" {
		b.WriteString("\n\n  " + warnStyle.Render(m.note))
	}
	b.WriteString("\n\n" + dimStyle.Render("a condition  A/O/N add AND/OR/NOT group  t toggle AND/OR  e edit  d delete  r raw  c copy  enter use in search  esc back"))
	b.WriteString("\n" + dimStyle.Render("values are escaped automatically; use * for substring matches"))
	return b.String()
}

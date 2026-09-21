package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zoro/ldapview/internal/schema"
)

type schemaModel struct {
	s      *schema.Schema
	tab    int // 0 object classes, 1 attribute types, 2 matching rules
	filter lineInput
	typing bool
	cur    [3]int
	raw    bool
	width  int
	height int
}

var schemaTabs = []string{"object classes", "attribute types", "matching rules"}

func newSchemaModel(s *schema.Schema, query string) schemaModel {
	m := schemaModel{s: s}
	if query != "" {
		switch {
		case s.Class(query) != nil:
			m.tab = 0
		case s.Attr(query) != nil:
			m.tab = 1
		default:
			m.filter.Set(query)
		}
		names := m.names()
		for i, n := range names {
			if strings.EqualFold(n, query) {
				m.cur[m.tab] = i
			}
		}
	}
	return m
}

func (m schemaModel) all() []string {
	var out []string
	switch m.tab {
	case 0:
		for _, o := range m.s.ClassList {
			out = append(out, o.Name())
		}
	case 1:
		for _, a := range m.s.AttrList {
			out = append(out, a.Name())
		}
	default:
		for _, r := range m.s.RuleList {
			out = append(out, r.Name())
		}
	}
	return out
}

func (m schemaModel) names() []string {
	q := strings.ToLower(m.filter.String())
	if q == "" {
		return m.all()
	}
	var out []string
	for _, n := range m.all() {
		if strings.Contains(strings.ToLower(n), q) {
			out = append(out, n)
		}
	}
	return out
}

func (m schemaModel) selected() string {
	n := m.names()
	if m.cur[m.tab] < len(n) {
		return n[m.cur[m.tab]]
	}
	return ""
}

func (m schemaModel) update(msg tea.Msg) (schemaModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if m.typing {
		switch k.Type {
		case tea.KeyEnter, tea.KeyEsc:
			m.typing = false
		default:
			if m.filter.Handle(k) {
				m.cur[m.tab] = 0
			}
		}
		return m, nil
	}
	n := len(m.names())
	switch k.String() {
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % 3
	case "shift+tab", "left", "h":
		m.tab = (m.tab + 2) % 3
	case "j", "down":
		if m.cur[m.tab] < n-1 {
			m.cur[m.tab]++
		}
	case "k", "up":
		if m.cur[m.tab] > 0 {
			m.cur[m.tab]--
		}
	case "pgdown":
		m.cur[m.tab] = min(m.cur[m.tab]+12, max(n-1, 0))
	case "pgup":
		m.cur[m.tab] = max(m.cur[m.tab]-12, 0)
	case "/":
		m.typing = true
	case "enter":
		m.raw = !m.raw
	case "y":
		lines := m.detail(m.selected())
		return m, copyCmd(strings.Join(lines, "\n"), "definition")
	case "q", "esc":
		return m, msgCmd(backMsg{})
	}
	return m, nil
}

func kv(k, v string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf("%-14s %s", k+":", v)
}

func (m schemaModel) detail(name string) []string {
	if name == "" {
		return nil
	}
	s := m.s
	var out []string
	add := func(l string) {
		if l != "" {
			out = append(out, l)
		}
	}
	switch m.tab {
	case 0:
		oc := s.Class(name)
		if oc == nil {
			return nil
		}
		if m.raw {
			return wrapText(oc.Raw, 70)
		}
		add(kv("Name", strings.Join(oc.Names, ", ")))
		add(kv("OID", oc.OID))
		add(kv("Kind", strings.ToLower(oc.Kind)))
		add(kv("Description", oc.Desc))
		add(kv("Inheritance", strings.Join(s.Lineage(name), " → ")))
		if oc.Obsolete {
			add("OBSOLETE")
		}
		must, may := s.Resolve([]string{name})
		out = append(out, "", "Required (MUST), including inherited:")
		out = append(out, wrapList(must, 68)...)
		out = append(out, "", "Optional (MAY), including inherited:")
		out = append(out, wrapList(may, 68)...)
	case 1:
		at := s.Attr(name)
		if at == nil {
			return nil
		}
		if m.raw {
			return wrapText(at.Raw, 70)
		}
		eff := s.Effective(name)
		add(kv("Name", strings.Join(at.Names, ", ")))
		add(kv("OID", at.OID))
		add(kv("Description", at.Desc))
		add(kv("Superior", at.Sup))
		syn := eff.Syntax
		if n := s.SyntaxName(syn); n != "" {
			syn += "  (" + n + ")"
		}
		add(kv("Syntax", syn))
		add(kv("Equality", eff.Equality))
		add(kv("Ordering", eff.Ordering))
		add(kv("Substring", eff.Substr))
		var fl []string
		if at.SingleValue {
			fl = append(fl, "single-valued")
		} else {
			fl = append(fl, "multi-valued")
		}
		if at.NoUserMod {
			fl = append(fl, "no-user-modification")
		}
		if at.Collective {
			fl = append(fl, "collective")
		}
		if at.Obsolete {
			fl = append(fl, "obsolete")
		}
		add(kv("Flags", strings.Join(fl, ", ")))
		usage := at.Usage
		if usage == "" {
			usage = "userApplications"
		}
		add(kv("Usage", usage))
		must, may := s.UsedBy(name)
		out = append(out, "", "Required by:")
		out = append(out, wrapList(must, 68)...)
		out = append(out, "", "Allowed in:")
		out = append(out, wrapList(may, 68)...)
	default:
		r := s.Rules[strings.ToLower(name)]
		if r == nil {
			return nil
		}
		if m.raw {
			return wrapText(r.Raw, 70)
		}
		add(kv("Name", strings.Join(r.Names, ", ")))
		add(kv("OID", r.OID))
		add(kv("Description", r.Desc))
		syn := r.Syntax
		if n := s.SyntaxName(syn); n != "" {
			syn += "  (" + n + ")"
		}
		add(kv("Syntax", syn))
	}
	return out
}

func wrapList(items []string, w int) []string {
	if len(items) == 0 {
		return []string{"  (none)"}
	}
	var out []string
	line := " "
	for _, it := range items {
		if len(line)+len(it)+2 > w {
			out = append(out, line)
			line = " "
		}
		line += " " + it
	}
	return append(out, line)
}

func wrapText(s string, w int) []string {
	var out []string
	for len(s) > w {
		i := strings.LastIndexByte(s[:w], ' ')
		if i <= 0 {
			i = w
		}
		out = append(out, s[:i])
		s = strings.TrimLeft(s[i:], " ")
	}
	return append(out, s)
}

func (m schemaModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Schema browser") + "  ")
	for i, t := range schemaTabs {
		label := fmt.Sprintf(" %s (%d) ", t, []int{len(m.s.ClassList), len(m.s.AttrList), len(m.s.RuleList)}[i])
		if i == m.tab {
			b.WriteString(selectedStyle.Render(label))
		} else {
			b.WriteString(dimStyle.Render(label))
		}
	}
	b.WriteString("\n")
	flt := "/ filter: " + m.filter.View(m.typing, false, 24)
	b.WriteString(dimStyle.Render(flt) + "\n")

	rows := max(h-7, 5)
	leftW := 34
	names := m.names()
	cur := m.cur[m.tab]
	start := max(cur-rows+1, 0)
	var lb strings.Builder
	for i := start; i < len(names) && i < start+rows; i++ {
		line := truncate(names[i], leftW-2)
		if i == cur {
			line = selectedStyle.Render(line)
		}
		lb.WriteString(line + "\n")
	}
	if len(names) == 0 {
		lb.WriteString(dimStyle.Render("no matches"))
	}
	det := m.detail(m.selected())
	var rb strings.Builder
	for i, l := range det {
		if i >= rows {
			rb.WriteString(dimStyle.Render("…"))
			break
		}
		rb.WriteString(truncate(l, w-leftW-8) + "\n")
	}
	left := paneStyle.Width(leftW).Height(rows).MaxHeight(rows + 2).Render(strings.TrimRight(lb.String(), "\n"))
	right := paneStyle.Width(max(w-leftW-6, 20)).Height(rows).MaxHeight(rows + 2).Render(strings.TrimRight(rb.String(), "\n"))
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, right) + "\n")
	b.WriteString(dimStyle.Render("tab switch  j/k move  / filter  enter raw definition  y copy  q back"))
	return b.String()
}

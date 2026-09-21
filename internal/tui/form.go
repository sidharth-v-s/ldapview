package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type formField struct {
	label   string
	in      lineInput
	mask    bool
	hint    string
	choices []string
	ci      int
}

func (f formField) value() string {
	if len(f.choices) > 0 {
		return f.choices[f.ci]
	}
	return f.in.String()
}

func textField(label, val, hint string) formField {
	return formField{label: label, in: newInput(val), hint: hint}
}

func choiceField(label string, choices []string, cur string) formField {
	f := formField{label: label, choices: choices}
	for i, c := range choices {
		if c == cur {
			f.ci = i
		}
	}
	return f
}

type formModel struct {
	title       string
	fields      []formField
	idx         int
	preview     func(vals []string) string
	previewForm func(m *formModel) string
	submitForm  func(m *formModel) tea.Cmd
	onLeave     func(m *formModel, idx int)
	onEdit      func(m *formModel, idx int)
	submit      func(vals []string) tea.Cmd
	cancel      func() tea.Cmd
	keys        map[string]func(m *formModel) tea.Cmd
	footer      string
	notice      string
	width       int
	height      int
}

type formCancelMsg struct{}

func (m *formModel) doSubmit() tea.Cmd {
	if m.submitForm != nil {
		return m.submitForm(m)
	}
	return m.submit(m.values())
}

func (m formModel) values() []string {
	v := make([]string, len(m.fields))
	for i, f := range m.fields {
		v[i] = f.value()
	}
	return v
}

func (m *formModel) move(d int) {
	if len(m.fields) == 0 {
		return
	}
	old := m.idx
	m.idx = (m.idx + d + len(m.fields)) % len(m.fields)
	if m.onLeave != nil && old != m.idx {
		m.onLeave(m, old)
	}
}

func (m formModel) update(msg tea.Msg) (formModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || len(m.fields) == 0 {
		return m, nil
	}
	if fn, ok := m.keys[k.String()]; ok {
		return m, fn(&m)
	}
	f := &m.fields[m.idx]
	switch k.String() {
	case "esc":
		if m.cancel != nil {
			return m, m.cancel()
		}
		return m, func() tea.Msg { return formCancelMsg{} }
	case "tab", "down":
		m.move(1)
		return m, nil
	case "shift+tab", "up":
		m.move(-1)
		return m, nil
	case "ctrl+s":
		return m, m.doSubmit()
	case "enter":
		if m.idx == len(m.fields)-1 {
			return m, m.doSubmit()
		}
		m.move(1)
		return m, nil
	case "left", "right":
		if len(f.choices) > 0 {
			d := 1
			if k.String() == "left" {
				d = -1
			}
			f.ci = (f.ci + d + len(f.choices)) % len(f.choices)
			if m.onEdit != nil {
				m.onEdit(&m, m.idx)
			}
			return m, nil
		}
	}
	if len(f.choices) == 0 && f.in.Handle(k) && m.onEdit != nil {
		m.onEdit(&m, m.idx)
	}
	return m, nil
}

func (m formModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.title) + "\n\n")
	lw := 0
	for _, f := range m.fields {
		if len(f.label) > lw {
			lw = len(f.label)
		}
	}
	vw := m.width - lw - 8
	for i, f := range m.fields {
		cur := "  "
		if i == m.idx {
			cur = "> "
		}
		var val string
		if len(f.choices) > 0 {
			val = "◀ " + f.value() + " ▶"
			if i == m.idx {
				val = selectedStyle.Render(val)
			}
		} else {
			val = f.in.View(i == m.idx, f.mask, vw)
		}
		lbl := fmt.Sprintf("%-*s", lw, f.label)
		if i == m.idx {
			lbl = attrNameStyle.Render(lbl)
		}
		b.WriteString(cur + lbl + "  " + val + "\n")
	}
	if m.idx < len(m.fields) && m.fields[m.idx].hint != "" {
		b.WriteString("\n" + dimStyle.Render("  "+m.fields[m.idx].hint) + "\n")
	}
	if m.previewForm != nil {
		if p := m.previewForm(&m); p != "" {
			b.WriteString("\n" + p + "\n")
		}
	} else if m.preview != nil {
		if p := m.preview(m.values()); p != "" {
			b.WriteString("\n" + p + "\n")
		}
	}
	if m.notice != "" {
		b.WriteString("\n" + warnStyle.Render("  "+m.notice) + "\n")
	}
	foot := "tab/shift+tab move  ←/→ choices  ctrl+s save  esc cancel"
	if m.footer != "" {
		foot = m.footer
	}
	b.WriteString("\n" + dimStyle.Render(foot))
	return b.String()
}

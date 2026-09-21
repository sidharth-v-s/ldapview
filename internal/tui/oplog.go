package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type opsModel struct {
	sh     *shared
	cur    int
	follow bool
	height int
}

func newOpsModel(sh *shared) opsModel { return opsModel{sh: sh, follow: true} }

func (m opsModel) update(msg tea.Msg) (opsModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.sh.client == nil {
		return m, nil
	}
	ops := m.sh.client.Ops()
	if m.follow {
		m.cur = len(ops) - 1
	}
	switch k.String() {
	case "j", "down":
		if m.cur < len(ops)-1 {
			m.cur++
		}
		m.follow = m.cur == len(ops)-1
	case "k", "up":
		if m.cur > 0 {
			m.cur--
		}
		m.follow = false
	case "G", "end":
		m.follow = true
	case "c":
		m.sh.client.ClearOps()
		m.cur = 0
		return m, statusCmd("operation log cleared", false)
	case "enter":
		if m.cur >= 0 && m.cur < len(ops) {
			o := ops[m.cur]
			lines := []string{
				"Time:    " + o.Time.Format("2006-01-02 15:04:05.000"),
				"Kind:    " + o.Kind,
				"Target:  " + o.Target,
				"Detail:  " + o.Detail,
				fmt.Sprintf("Success: %v", o.OK),
			}
			if o.Err != "" {
				lines = append(lines, "Error:   "+o.Err)
			}
			if o.Raw != "" {
				lines = append(lines, "Raw:     "+o.Raw)
			}
			lines = append(lines, "", "(passwords and secret attribute values are never recorded)")
			return m, showMessage("Operation detail", lines)
		}
	case "q", "esc":
		return m, msgCmd(backMsg{})
	}
	return m, nil
}

func (m opsModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Operation log") + "\n\n")
	if m.sh.client == nil {
		return b.String()
	}
	ops := m.sh.client.Ops()
	cur := m.cur
	if m.follow {
		cur = len(ops) - 1
	}
	rows := max(h-6, 5)
	start := max(cur-rows+1, 0)
	for i := start; i < len(ops) && i < start+rows; i++ {
		o := ops[i]
		status := okStyle.Render("ok ")
		if !o.OK {
			status = missStyle.Render("ERR")
		}
		line := fmt.Sprintf("%s  %-8s %s  %s", o.Time.Format("15:04:05"), o.Kind, status, truncate(o.Target, 40))
		detail := o.Detail
		if !o.OK {
			detail = o.Err
		}
		line = truncateStyled(line+"  "+dimStyle.Render(truncate(detail, max(w-75, 10))), w)
		if i == cur {
			plain := fmt.Sprintf("%s  %-8s %-3s  %s  %s", o.Time.Format("15:04:05"), o.Kind, map[bool]string{true: "ok", false: "ERR"}[o.OK], truncate(o.Target, 40), truncate(detail, max(w-75, 10)))
			line = selectedStyle.Render(truncate(plain, w-1))
		}
		b.WriteString(line + "\n")
	}
	if len(ops) == 0 {
		b.WriteString(dimStyle.Render("  no operations yet") + "\n")
	}
	b.WriteString("\n" + dimStyle.Render(fmt.Sprintf("%d operations   j/k move  enter detail  G follow  c clear  q back", len(ops))))
	return b.String()
}

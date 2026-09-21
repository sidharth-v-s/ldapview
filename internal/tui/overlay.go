package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// overlay is a modal UI element. update returns the next overlay (nil when
// finished) and an optional command.
type overlay interface {
	update(msg tea.Msg) (overlay, tea.Cmd)
	view(w, h int) string
	inline() bool // rendered under the current screen instead of full screen
}

type openOverlayMsg struct{ ov overlay }

func openOverlay(ov overlay) tea.Cmd { return func() tea.Msg { return openOverlayMsg{ov} } }

// ---- prompt ----

type promptOverlay struct {
	title   string
	in      lineInput
	mask    bool
	hint    string
	suggest func(string) []string
	submit  func(string) tea.Cmd
}

func newPrompt(title, initial, hint string, submit func(string) tea.Cmd) *promptOverlay {
	return &promptOverlay{title: title, in: newInput(initial), hint: hint, submit: submit}
}

func (p *promptOverlay) inline() bool { return true }

func (p *promptOverlay) update(msg tea.Msg) (overlay, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch k.Type {
	case tea.KeyEsc:
		return nil, nil
	case tea.KeyEnter:
		return nil, p.submit(p.in.String())
	case tea.KeyTab:
		if p.suggest != nil {
			if s := p.suggest(p.in.String()); len(s) > 0 {
				p.in.Set(s[0] + " ")
			}
		}
		return p, nil
	}
	p.in.Handle(k)
	return p, nil
}

func (p *promptOverlay) view(w, h int) string {
	var b strings.Builder
	b.WriteString(promptTitleStyle.Render(" "+p.title+" ") + " " + p.in.View(true, p.mask, w-len(p.title)-6))
	if p.suggest != nil {
		s := p.suggest(p.in.String())
		if len(s) > 8 {
			s = s[:8]
		}
		if len(s) > 0 {
			b.WriteString("\n" + dimStyle.Render("  "+strings.Join(s, "  ")))
		}
	}
	if p.hint != "" {
		b.WriteString("\n" + dimStyle.Render("  "+p.hint))
	}
	return b.String()
}

// ---- confirm ----

type confirmOverlay struct {
	title  string
	lines  []string
	yes    func() tea.Cmd
	danger bool
}

func (c *confirmOverlay) inline() bool { return false }

func (c *confirmOverlay) update(msg tea.Msg) (overlay, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "y", "Y":
			return nil, c.yes()
		case "n", "N", "esc", "q":
			return nil, statusCmd("cancelled", false)
		}
	}
	return c, nil
}

func (c *confirmOverlay) view(w, h int) string {
	var b strings.Builder
	st := titleStyle
	if c.danger {
		st = dangerTitleStyle
	}
	b.WriteString(st.Render(c.title) + "\n\n")
	max := h - 6
	for i, l := range c.lines {
		if i >= max {
			b.WriteString(dimStyle.Render(fmt.Sprintf("… %d more lines", len(c.lines)-i)) + "\n")
			break
		}
		b.WriteString("  " + truncate(l, w-4) + "\n")
	}
	b.WriteString("\n" + helpKeyStyle.Render("y") + " confirm    " + helpKeyStyle.Render("n/esc") + " cancel")
	return b.String()
}

// ---- message (scrollable text) ----

type messageOverlay struct {
	title  string
	lines  []string
	scroll int
}

func (m *messageOverlay) inline() bool { return false }

func (m *messageOverlay) update(msg tea.Msg) (overlay, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc", "q", "enter":
			return nil, nil
		case "j", "down":
			if m.scroll < len(m.lines)-1 {
				m.scroll++
			}
		case "k", "up":
			if m.scroll > 0 {
				m.scroll--
			}
		case "pgdown", " ":
			m.scroll = min(m.scroll+15, max(len(m.lines)-1, 0))
		case "pgup":
			m.scroll = max(m.scroll-15, 0)
		case "y":
			return m, copyCmd(strings.Join(m.lines, "\n"), "text")
		}
	}
	return m, nil
}

func (m *messageOverlay) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(m.title) + "\n\n")
	n := h - 5
	if n < 3 {
		n = 3
	}
	for i := m.scroll; i < len(m.lines) && i < m.scroll+n; i++ {
		b.WriteString(truncate(m.lines[i], w-1) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("j/k scroll  y copy  q close"))
	return b.String()
}

func showMessage(title string, lines []string) tea.Cmd {
	return openOverlay(&messageOverlay{title: title, lines: lines})
}

// ---- picker ----

type pickItem struct {
	label  string
	detail string
	value  any
}

type pickerOverlay struct {
	title    string
	items    []pickItem
	filter   lineInput
	cur      int
	multi    bool
	sel      map[int]bool
	onSelect func([]pickItem) tea.Cmd
	onDelete func(pickItem) tea.Cmd
}

func newPicker(title string, items []pickItem, onSelect func([]pickItem) tea.Cmd) *pickerOverlay {
	return &pickerOverlay{title: title, items: items, onSelect: onSelect, sel: map[int]bool{}}
}

func (p *pickerOverlay) inline() bool { return false }

func (p *pickerOverlay) visible() []int {
	q := strings.ToLower(p.filter.String())
	var out []int
	for i, it := range p.items {
		if q == "" || strings.Contains(strings.ToLower(it.label+" "+it.detail), q) {
			out = append(out, i)
		}
	}
	return out
}

func (p *pickerOverlay) update(msg tea.Msg) (overlay, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	vis := p.visible()
	switch k.String() {
	case "esc":
		return nil, nil
	case "up", "ctrl+p":
		if p.cur > 0 {
			p.cur--
		}
	case "down", "ctrl+n":
		if p.cur < len(vis)-1 {
			p.cur++
		}
	case "pgup":
		p.cur = max(p.cur-10, 0)
	case "pgdown":
		p.cur = min(p.cur+10, max(len(vis)-1, 0))
	case "tab":
		if p.multi && p.cur < len(vis) {
			p.sel[vis[p.cur]] = !p.sel[vis[p.cur]]
			if p.cur < len(vis)-1 {
				p.cur++
			}
		}
	case "ctrl+d":
		if p.onDelete != nil && p.cur < len(vis) {
			it := p.items[vis[p.cur]]
			p.items = append(p.items[:vis[p.cur]], p.items[vis[p.cur]+1:]...)
			p.sel = map[int]bool{}
			if p.cur > 0 {
				p.cur--
			}
			return p, p.onDelete(it)
		}
	case "enter":
		var chosen []pickItem
		if p.multi {
			for i := range p.items {
				if p.sel[i] {
					chosen = append(chosen, p.items[i])
				}
			}
		}
		if len(chosen) == 0 && p.cur < len(vis) {
			chosen = []pickItem{p.items[vis[p.cur]]}
		}
		if len(chosen) == 0 {
			return nil, nil
		}
		return nil, p.onSelect(chosen)
	default:
		if p.filter.Handle(k) {
			p.cur = 0
		}
	}
	return p, nil
}

func (p *pickerOverlay) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(p.title) + "\n")
	b.WriteString(dimStyle.Render("filter: ") + p.filter.View(true, false, w-12) + "\n\n")
	vis := p.visible()
	rows := h - 8
	if rows < 3 {
		rows = 3
	}
	start := 0
	if p.cur >= rows {
		start = p.cur - rows + 1
	}
	for i := start; i < len(vis) && i < start+rows; i++ {
		it := p.items[vis[i]]
		mark := "  "
		if p.multi {
			mark = "[ ]"
			if p.sel[vis[i]] {
				mark = "[x]"
			}
			mark += " "
		}
		line := mark + it.label
		if it.detail != "" {
			line += dimStyle.Render("  " + it.detail)
		}
		if i == p.cur {
			line = selectedStyle.Render(truncate(mark+it.label+"  "+it.detail, w-2))
		} else {
			line = truncateStyled(line, w-2)
		}
		b.WriteString(line + "\n")
	}
	if len(vis) == 0 {
		b.WriteString(dimStyle.Render("  no matches") + "\n")
	}
	keys := "↑/↓ move  enter select  esc cancel"
	if p.multi {
		keys = "↑/↓ move  tab mark  enter select  esc cancel"
	}
	if p.onDelete != nil {
		keys += "  ctrl+d delete"
	}
	b.WriteString("\n" + dimStyle.Render(keys))
	return b.String()
}

func truncateStyled(s string, w int) string { return s } // styled strings are short; avoid cutting escapes

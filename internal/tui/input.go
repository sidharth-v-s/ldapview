package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// lineInput is a minimal single-line editor with cursor movement.
type lineInput struct {
	r   []rune
	pos int
}

func newInput(s string) lineInput {
	r := []rune(s)
	return lineInput{r: r, pos: len(r)}
}

func (l lineInput) String() string { return string(l.r) }

func (l *lineInput) Set(s string) {
	l.r = []rune(s)
	l.pos = len(l.r)
}

func (l *lineInput) insert(rs []rune) {
	out := make([]rune, 0, len(l.r)+len(rs))
	out = append(out, l.r[:l.pos]...)
	out = append(out, rs...)
	out = append(out, l.r[l.pos:]...)
	l.r = out
	l.pos += len(rs)
}

func (l *lineInput) del(from, to int) {
	if from < 0 {
		from = 0
	}
	if to > len(l.r) {
		to = len(l.r)
	}
	if from >= to {
		return
	}
	l.r = append(append([]rune{}, l.r[:from]...), l.r[to:]...)
	l.pos = from
}

// Handle applies an editing/movement key; it reports whether it consumed it.
func (l *lineInput) Handle(k tea.KeyMsg) bool {
	switch k.Type {
	case tea.KeyRunes:
		if k.Alt {
			return false
		}
		rs := k.Runes
		if k.Paste {
			rs = []rune(strings.NewReplacer("\r", "", "\n", "").Replace(string(rs)))
		}
		l.insert(rs)
	case tea.KeySpace:
		l.insert([]rune{' '})
	case tea.KeyBackspace:
		if l.pos > 0 {
			l.del(l.pos-1, l.pos)
		}
	case tea.KeyDelete:
		l.del(l.pos, l.pos+1)
	case tea.KeyLeft:
		if l.pos > 0 {
			l.pos--
		}
	case tea.KeyRight:
		if l.pos < len(l.r) {
			l.pos++
		}
	case tea.KeyHome, tea.KeyCtrlA:
		l.pos = 0
	case tea.KeyEnd, tea.KeyCtrlE:
		l.pos = len(l.r)
	case tea.KeyCtrlU:
		l.del(0, l.pos)
	case tea.KeyCtrlK:
		l.del(l.pos, len(l.r))
	case tea.KeyCtrlW:
		i := l.pos
		for i > 0 && l.r[i-1] == ' ' {
			i--
		}
		for i > 0 && l.r[i-1] != ' ' {
			i--
		}
		l.del(i, l.pos)
	default:
		return false
	}
	return true
}

// View renders the input windowed to width columns (0 = unlimited).
func (l lineInput) View(focused, mask bool, width int) string {
	rs := l.r
	if mask {
		rs = []rune(strings.Repeat("*", len(l.r)))
	}
	start := 0
	if width > 2 && len(rs)+1 > width {
		if l.pos >= width-1 {
			start = l.pos - width + 2
		}
		end := start + width - 1
		if end > len(rs) {
			end = len(rs)
		}
		rs = rs[start:end]
	}
	pos := l.pos - start
	if !focused {
		return string(rs)
	}
	if pos > len(rs) {
		pos = len(rs)
	}
	cur, after := " ", ""
	if pos < len(rs) {
		cur, after = string(rs[pos]), string(rs[pos+1:])
	}
	return string(rs[:pos]) + cursorStyle.Render(cur) + after
}

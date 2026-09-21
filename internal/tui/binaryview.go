package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldapclient"
)

type binaryViewModel struct {
	name   string
	data   []byte
	mode   string // hex | b64
	scroll int
}

func newBinaryViewModel(name string, data []byte) binaryViewModel {
	return binaryViewModel{name: name, data: data, mode: "hex"}
}

func (m binaryViewModel) rendered() []string {
	var s string
	if m.mode == "hex" {
		s = ldapclient.HexDump(m.data)
	} else {
		s = ldapclient.Base64String(m.data)
		var out []string
		for len(s) > 76 {
			out = append(out, s[:76])
			s = s[76:]
		}
		return append(out, s)
	}
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

func (m binaryViewModel) update(msg tea.Msg) (binaryViewModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "h":
		m.mode, m.scroll = "hex", 0
	case "b":
		m.mode, m.scroll = "b64", 0
	case "j", "down":
		m.scroll++
	case "k", "up":
		if m.scroll > 0 {
			m.scroll--
		}
	case "pgdown":
		m.scroll += 15
	case "pgup":
		m.scroll = max(m.scroll-15, 0)
	case "y":
		return m, copyCmd(ldapclient.Base64String(m.data), "base64")
	case "w":
		fn := strings.ToLower(strings.NewReplacer("/", "_", "\\", "_").Replace(m.name)) + ".bin"
		if err := os.WriteFile(fn, m.data, 0o600); err != nil {
			return m, statusCmd("save failed: "+err.Error(), true)
		}
		return m, statusCmd("saved "+fn, false)
	case "q", "esc":
		return m, msgCmd(backMsg{})
	}
	return m, nil
}

func (m binaryViewModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Binary value: "+m.name) + "\n\n")
	b.WriteString(fmt.Sprintf("Length: %d bytes\n\n", len(m.data)))
	ls := m.rendered()
	n := h - 8
	if n < 3 {
		n = 3
	}
	if m.scroll > len(ls)-1 {
		m.scroll = max(len(ls)-1, 0)
	}
	for i := m.scroll; i < len(ls) && i < m.scroll+n; i++ {
		b.WriteString(ls[i] + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("h hex  b base64  j/k scroll  y copy base64  w save to file  q back"))
	return b.String()
}

package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldapclient"
)

type binaryViewModel struct {
	name string
	data []byte
	mode string // "hex" | "b64"
}

func newBinaryViewModel(name string, data []byte) binaryViewModel {
	return binaryViewModel{name: name, data: data, mode: "hex"}
}

func (m binaryViewModel) update(msg tea.Msg) (binaryViewModel, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "h":
			m.mode = "hex"
		case "b":
			m.mode = "b64"
		case "y":
			return m, copyCmd(ldapclient.Base64String(m.data), "base64")
		case "w":
			fn := strings.ToLower(m.name) + ".bin"
			if err := os.WriteFile(fn, m.data, 0o600); err != nil {
				return m, statusCmd("save failed: "+err.Error(), true)
			}
			return m, statusCmd("saved "+fn, false)
		case "q", "esc":
			return m, func() tea.Msg { return backToBrowserMsg{} }
		}
	}
	return m, nil
}

func (m binaryViewModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Binary value: "+m.name) + "\n\n")
	b.WriteString(fmt.Sprintf("Length: %d bytes\n\n", len(m.data)))
	if m.mode == "hex" {
		b.WriteString(ldapclient.HexDump(m.data))
	} else {
		b.WriteString(ldapclient.Base64String(m.data) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("h hex  b base64  y copy base64  w save to file  q back"))
	return b.String()
}

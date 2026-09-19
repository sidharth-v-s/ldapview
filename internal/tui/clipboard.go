package tui

import (
	"encoding/base64"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// copyCmd copies text to the terminal clipboard via OSC 52, which works
// over SSH in terminals that support it (no xclip/pbcopy needed).
func copyCmd(text, label string) tea.Cmd {
	return func() tea.Msg {
		enc := base64.StdEncoding.EncodeToString([]byte(text))
		fmt.Fprintf(os.Stderr, "\x1b]52;c;%s\x07", enc)
		return statusMsg{text: fmt.Sprintf("copied %s", label)}
	}
}

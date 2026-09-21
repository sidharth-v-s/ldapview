package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/model"
)

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// busy reports whether any asynchronous LDAP work is in flight.
func (a App) busy() bool {
	if a.sh.schemaLoading || a.connecting || a.search.running || a.browser.loading {
		return true
	}
	for _, r := range a.browser.roots {
		if nodeLoading(r) {
			return true
		}
	}
	return false
}

func (a App) spinner() string {
	if !a.busy() {
		return ""
	}
	return spinFrames[a.spin%len(spinFrames)] + " "
}

func nodeLoading(n *model.Node) bool {
	if n.Loading {
		return true
	}
	for _, c := range n.Children {
		if nodeLoading(c) {
			return true
		}
	}
	return false
}

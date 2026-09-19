package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/store"
	"github.com/zoro/ldapview/internal/tui"
)

func main() {
	path, err := store.DefaultPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config path:", err)
		os.Exit(1)
	}
	s, err := store.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load connections:", err)
		os.Exit(1)
	}
	p := tea.NewProgram(tui.NewApp(s), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

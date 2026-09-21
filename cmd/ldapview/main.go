package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/cli"
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

	handled, code, target, password := cli.Run(os.Args[1:], s, os.Stdin, os.Stdout, os.Stderr)
	if handled {
		os.Exit(code)
	}

	app := tui.NewApp(s)
	if target != nil {
		base, filter := "", ""
		if target.URL != nil {
			base, filter = target.URL.Base, target.URL.Filter
		}
		app = app.WithTarget(target.Conn, password, base, filter)
	}
	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

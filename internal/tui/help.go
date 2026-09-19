package tui

import "strings"

type helpModel struct{}

func newHelpModel() helpModel { return helpModel{} }

func (helpModel) view() string {
	rows := [][2]string{
		{"j/k, ↓/↑", "move"},
		{"l/→/enter", "expand / open entry"},
		{"h/←", "collapse / go to parent"},
		{"tab", "switch pane"},
		{"s or /", "LDAP search (base = selected node)"},
		{"r", "refresh node"},
		{"c", "copy DN"},
		{"y", "copy attribute value (entry pane)"},
		{"enter", "on binary value: hex/base64 view"},
		{"R", "Root DSE"},
		{"q", "back / disconnect"},
		{"?", "toggle help"},
		{"ctrl+c", "quit"},
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("ldapview — Help") + "\n\n")
	for _, r := range rows {
		b.WriteString(helpKeyStyle.Render(padRight(r[0], 14)) + r[1] + "\n")
	}
	return b.String()
}

func padRight(s string, n int) string {
	for len([]rune(s)) < n {
		s += " "
	}
	return s
}

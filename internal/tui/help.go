package tui

import "strings"

type helpModel struct{ scroll int }

func newHelpModel() helpModel { return helpModel{} }

var helpSections = []struct {
	title string
	rows  [][2]string
}{
	{"Browser — tree", [][2]string{
		{"j/k ↑/↓", "move"}, {"l/→/enter", "expand + load entry"}, {"h/←", "collapse / parent"},
		{"g", "go to DN"}, {"/  n  N", "quick find in tree, next, previous"}, {"r", "refresh node"},
		{"a", "add entry under node"}, {"d / D", "delete entry"}, {"m", "rename / move (ModifyDN)"},
		{"c", "copy DN"}, {"=", "mark entry; press = on another to diff"}, {"Y", "copy entry as LDIF"}, {"x", "export entry (.ldif/.json)"},
		{"tab", "switch tree ↔ entry pane"},
	}},
	{"Browser — entry pane", [][2]string{
		{"v", "cycle view: attributes → LDIF → raw → relationships → schema → security"},
		{"e", "edit value"}, {"a", "add value"}, {"d / x", "delete value"}, {"y", "copy value / line"},
		{"enter", "binary: hex/base64 view; relationship: jump to DN"}, {"A", "load security descriptor (AD)"},
	}},
	{"Screens", [][2]string{
		{"s", "LDAP search"}, {"R", "Root DSE"}, {"S", "schema browser"}, {"L", "operation log"},
		{"P", "raw protocol viewer"}, {":", "command palette"}, {"?", "this help"}, {"q", "back / disconnect"},
	}},
	{"Search form", [][2]string{
		{"enter/ctrl+s", "run"}, {"ctrl+f", "filter builder"}, {"ctrl+p", "presets"}, {"ctrl+h", "history"},
		{"ctrl+b", "bookmarks"}, {"ctrl+k", "save bookmark"}, {"ctrl+e", "preview BER encoding of the request"},
	}},
	{"Search results", [][2]string{
		{"enter", "open in browser"}, {"i", "details"}, {"c / y", "copy DN / LDIF"}, {"a / A", "copy an attribute: this entry / all rows"}, {"x / X", "export page / all pages (.ldif .json .csv .txt)"},
		{"n / p", "next / previous page"}, {"o", "sort by column"}, {"/", "filter results"}, {"b", "use as base"},
		{"e", "edit search"}, {"r", "re-run"}, {"F", "referrals: follow (anonymous, read-only) or open separately"},
	}},
	{"Palette commands", [][2]string{
		{":goto <dn>", ""}, {":search [filter]", ""}, {":import <file.ldif>", ""}, {":export <file>", ""},
		{":readonly on|off", ""}, {":whoami  :tls  :sasl  :controls  :extops  :server  :secinfo", ""}, {":ldif <file>  :ldif edit [file]", ""}, {":schema [name]", ""},
		{":view attrs|ldif|raw|rel|schema|sec", ""}, {":ops  :proto  :clear [history]", ""}, {":sid <sid>  :guid <guid>  (AD lookups)", ""}, {":diff  :unmark  :reconnect", ""},
	}},
	{"Safety", [][2]string{
		{"", "TLS verification is on by default; passwords are never stored or logged."},
		{"", "Every write asks for confirmation. Use :readonly on to block all modifications."},
	}},
}

func (helpModel) lines() []string {
	var out []string
	for _, s := range helpSections {
		out = append(out, attrNameStyle.Render(s.title))
		for _, r := range s.rows {
			if r[0] == "" {
				out = append(out, "  "+r[1])
			} else {
				out = append(out, "  "+helpKeyStyle.Render(padRight(r[0], 22))+r[1])
			}
		}
		out = append(out, "")
	}
	return out
}

func (m helpModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("ldapview — help") + "\n\n")
	ls := m.lines()
	n := h - 5
	if n < 5 {
		n = 5
	}
	for i := m.scroll; i < len(ls) && i < m.scroll+n; i++ {
		b.WriteString(ls[i] + "\n")
	}
	b.WriteString(dimStyle.Render("j/k scroll  ?/q/esc close"))
	return b.String()
}

func padRight(s string, n int) string {
	for len([]rune(s)) < n {
		s += " "
	}
	return s
}

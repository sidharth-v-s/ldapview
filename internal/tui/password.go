package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/store"
)

type passwordPromptModel struct {
	conn     store.Connection
	password string
}

func newPasswordPromptModel(c store.Connection) passwordPromptModel {
	return passwordPromptModel{conn: c}
}

func (m passwordPromptModel) update(msg tea.Msg) (passwordPromptModel, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch keyMsg.String() {
	case "esc":
		return m, func() tea.Msg { return cancelPromptMsg{} }
	case "enter":
		pw := m.password
		conn := m.conn
		m.password = ""
		return m, func() tea.Msg { return doConnectMsg{conn: conn, password: pw} }
	case "backspace":
		if len(m.password) > 0 {
			m.password = m.password[:len(m.password)-1]
		}
	default:
		if len(keyMsg.Runes) > 0 {
			m.password += string(keyMsg.Runes)
		}
	}
	return m, nil
}

func (m passwordPromptModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Connect: " + m.conn.Name))
	b.WriteString("\n\n")
	b.WriteString(m.conn.URL())
	b.WriteString("\n")
	b.WriteString("TLS: " + string(m.conn.TLSMode))
	if m.conn.SkipVerify {
		b.WriteString("  " + warnStyle.Render("(certificate verification DISABLED)"))
	}
	if m.conn.TLSMode == store.TLSNone && m.conn.BindMethod == store.BindSimple {
		b.WriteString("\n" + warnStyle.Render("WARNING: simple bind over plaintext LDAP sends the password unencrypted"))
	}
	b.WriteString("\n")
	b.WriteString("Bind method: " + string(m.conn.BindMethod))
	b.WriteString("\n")
	if m.conn.BindMethod == store.BindSimple {
		b.WriteString("Bind DN: " + m.conn.BindDN)
		b.WriteString("\n\n")
		b.WriteString("Password: " + strings.Repeat("*", len(m.password)))
		b.WriteString("\n\n")
	} else {
		b.WriteString("\nAnonymous bind — press enter to connect.\n\n")
	}
	b.WriteString(dimStyle.Render("enter connect  esc cancel"))
	return b.String()
}

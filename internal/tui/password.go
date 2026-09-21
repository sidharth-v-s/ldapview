package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/store"
)

type passwordPromptModel struct {
	conn store.Connection
	in   lineInput
	test bool
}

func newPasswordPromptModel(c store.Connection, test bool) passwordPromptModel {
	return passwordPromptModel{conn: c, test: test}
}

func (m passwordPromptModel) needsPassword() bool {
	return m.conn.BindMethod == store.BindSimple || (m.conn.BindMethod == store.BindSASL && m.conn.SASLMech != "EXTERNAL")
}

func (m passwordPromptModel) update(msg tea.Msg) (passwordPromptModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.Type {
	case tea.KeyEsc:
		return m, msgCmd(cancelPromptMsg{})
	case tea.KeyEnter:
		pw := m.in.String()
		m.in = lineInput{}
		return m, msgCmd(doConnectMsg{conn: m.conn, password: pw, test: m.test})
	}
	m.in.Handle(k)
	return m, nil
}

func (m passwordPromptModel) view() string {
	var b strings.Builder
	title := "Connect: " + m.conn.Name
	if m.test {
		title = "Test connection: " + m.conn.Name
	}
	b.WriteString(titleStyle.Render(title) + "\n\n")
	b.WriteString("  Server:   " + m.conn.URL() + "\n")
	tlsLine := "  TLS:      " + string(m.conn.TLSMode)
	if m.conn.TLSMode == "" || m.conn.TLSMode == store.TLSNone {
		tlsLine = "  TLS:      " + warnStyle.Render("none (plaintext)")
	}
	if m.conn.SkipVerify && m.conn.TLSMode != store.TLSNone && m.conn.TLSMode != "" {
		tlsLine += "  " + warnStyle.Render("(certificate verification DISABLED)")
	}
	b.WriteString(tlsLine + "\n")
	bind := string(m.conn.BindMethod)
	if bind == "" {
		bind = "anonymous"
	}
	if m.conn.BindMethod == store.BindSASL {
		bind += " (" + m.conn.SASLMech + ")"
	}
	b.WriteString("  Bind:     " + bind + "\n")
	if m.conn.BindDN != "" {
		b.WriteString("  User:     " + m.conn.BindDN + "\n")
	}
	if m.conn.ReadOnly {
		b.WriteString("  Mode:     read-only\n")
	}
	if (m.conn.TLSMode == "" || m.conn.TLSMode == store.TLSNone) && m.conn.BindMethod == store.BindSimple {
		b.WriteString("\n  " + warnStyle.Render("WARNING: simple bind over plaintext LDAP sends the password unencrypted.") + "\n")
	}
	b.WriteString("\n")
	if m.needsPassword() {
		b.WriteString("  Password: " + m.in.View(true, true, 40) + "\n")
	} else if m.conn.BindMethod == store.BindSASL {
		b.WriteString("  SASL EXTERNAL uses the TLS client certificate — press enter.\n")
	} else {
		b.WriteString("  Anonymous bind — press enter to connect.\n")
	}
	b.WriteString("\n" + dimStyle.Render("enter connect  esc cancel   (password is kept in memory only)"))
	return b.String()
}

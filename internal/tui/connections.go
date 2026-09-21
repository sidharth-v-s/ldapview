package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/store"
)

const (
	cfName = iota
	cfHost
	cfPort
	cfTLS
	cfBind
	cfBindDN
	cfSASL
	cfCA
	cfCert
	cfKey
	cfSkip
	cfRO
	cfTimeout
	cfSize
	cfTime
)

type connectionsModel struct {
	store  *store.Store
	cursor int
	width  int
	height int
	form   *formModel
}

type connFormDoneMsg struct{ name string }
type deleteConnMsg struct{ name string }

func newConnectionsModel(s *store.Store) connectionsModel { return connectionsModel{store: s} }

func (m *connectionsModel) setSize(w, h int) {
	m.width, m.height = w, h
	if m.form != nil {
		m.form.width, m.form.height = w, h
	}
}

func (m connectionsModel) typing() bool { return m.form != nil }

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (m *connectionsModel) openForm(title string, c store.Connection, origName string) {
	if c.Port == 0 {
		c.Port = c.DefaultPort()
	}
	f := &formModel{title: title, width: m.width, height: m.height}
	f.fields = make([]formField, 15)
	f.fields[cfName] = textField("Name", c.Name, "display name for this connection")
	f.fields[cfHost] = textField("Host", c.Host, "hostname or IP address")
	f.fields[cfPort] = textField("Port", strconv.Itoa(c.Port), "389 for ldap/StartTLS, 636 for ldaps (3268/3269 for AD global catalog)")
	tm := string(c.TLSMode)
	if tm == "" {
		tm = string(store.TLSNone)
	}
	f.fields[cfTLS] = choiceField("TLS mode", []string{"none", "starttls", "ldaps"}, tm)
	bm := string(c.BindMethod)
	if bm == "" {
		bm = string(store.BindAnonymous)
	}
	f.fields[cfBind] = choiceField("Bind method", []string{"anonymous", "simple", "sasl"}, bm)
	f.fields[cfBindDN] = textField("Bind DN / user", c.BindDN, "simple: DN.  NTLM: DOMAIN\\user or user@domain")
	f.fields[cfSASL] = choiceField("SASL mechanism", []string{"DIGEST-MD5", "NTLM", "EXTERNAL"}, c.SASLMech)
	f.fields[cfCA] = textField("CA file (PEM)", c.CAFile, "extra trusted CA bundle; preferred over skipping verification")
	f.fields[cfCert] = textField("Client cert (PEM)", c.ClientCert, "for SASL EXTERNAL / mutual TLS")
	f.fields[cfKey] = textField("Client key (PEM)", c.ClientKey, "")
	f.fields[cfSkip] = choiceField("Skip TLS verify", []string{"no", "yes"}, yn(c.SkipVerify))
	f.fields[cfRO] = choiceField("Read-only", []string{"no", "yes"}, yn(c.ReadOnly))
	to, sz, tl := c.TimeoutSec, c.SizeLimit, c.TimeLimit
	if to == 0 {
		to = 10
	}
	if sz == 0 {
		sz = 1000
	}
	if tl == 0 {
		tl = 10
	}
	f.fields[cfTimeout] = textField("Timeout (s)", strconv.Itoa(to), "connect timeout")
	f.fields[cfSize] = textField("Size limit", strconv.Itoa(sz), "default search size limit (0 = server default)")
	f.fields[cfTime] = textField("Time limit (s)", strconv.Itoa(tl), "default search time limit")
	f.footer = "tab move  ←/→ choices  ctrl+s save  esc cancel   (passwords are never saved)"

	refresh := func(fm *formModel) {
		fm.notice = ""
		switch {
		case fm.fields[cfSkip].value() == "yes" && fm.fields[cfTLS].value() != "none":
			fm.notice = "WARNING: certificate verification disabled — vulnerable to man-in-the-middle attacks."
		case fm.fields[cfTLS].value() == "none" && fm.fields[cfBind].value() != "anonymous":
			fm.notice = "WARNING: credentials will be sent unencrypted over plaintext LDAP. Prefer StartTLS or LDAPS."
		}
	}
	refresh(f)
	f.onEdit = func(fm *formModel, idx int) {
		if idx == cfTLS {
			p := strings.TrimSpace(fm.fields[cfPort].in.String())
			if p == "389" || p == "636" || p == "" {
				if fm.fields[cfTLS].value() == "ldaps" {
					fm.fields[cfPort].in.Set("636")
				} else {
					fm.fields[cfPort].in.Set("389")
				}
			}
		}
		refresh(fm)
	}
	store_ := m.store
	f.submit = func(v []string) tea.Cmd {
		name, host := strings.TrimSpace(v[cfName]), strings.TrimSpace(v[cfHost])
		if name == "" || host == "" {
			return statusCmd("name and host are required", true)
		}
		port, err := strconv.Atoi(strings.TrimSpace(v[cfPort]))
		if err != nil || port <= 0 || port > 65535 {
			return statusCmd("invalid port", true)
		}
		atoi := func(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }
		nc := store.Connection{
			Name: name, Host: host, Port: port,
			TLSMode: store.TLSMode(v[cfTLS]), BindMethod: store.BindMethod(v[cfBind]),
			BindDN: strings.TrimSpace(v[cfBindDN]), SASLMech: v[cfSASL],
			CAFile: strings.TrimSpace(v[cfCA]), ClientCert: strings.TrimSpace(v[cfCert]), ClientKey: strings.TrimSpace(v[cfKey]),
			SkipVerify: v[cfSkip] == "yes", ReadOnly: v[cfRO] == "yes",
			TimeoutSec: atoi(v[cfTimeout]), SizeLimit: atoi(v[cfSize]), TimeLimit: atoi(v[cfTime]),
		}
		if nc.BindMethod != store.BindSASL {
			nc.SASLMech = ""
		}
		if origName != "" && origName != name {
			store_.Delete(origName)
		}
		store_.Upsert(nc)
		if err := store_.Save(); err != nil {
			return statusCmd("save failed: "+err.Error(), true)
		}
		return tea.Batch(msgCmd(connFormDoneMsg{name: name}), statusCmd(fmt.Sprintf("saved %q", name), false))
	}
	m.form = f
}

func (m connectionsModel) update(msg tea.Msg) (connectionsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case connFormDoneMsg, formCancelMsg:
		m.form = nil
		if d, ok := msg.(connFormDoneMsg); ok {
			for i, c := range m.store.Connections {
				if c.Name == d.name {
					m.cursor = i
				}
			}
		}
		return m, nil
	case deleteConnMsg:
		m.store.Delete(msg.name)
		_ = m.store.Save()
		if m.cursor >= len(m.store.Connections) && m.cursor > 0 {
			m.cursor--
		}
		return m, statusCmd(fmt.Sprintf("deleted %q", msg.name), false)
	case tea.KeyMsg:
		if m.form != nil {
			f, cmd := m.form.update(msg)
			m.form = &f
			return m, cmd
		}
		return m.handleKey(msg)
	}
	return m, nil
}

func (m connectionsModel) selected() (store.Connection, bool) {
	if m.cursor < 0 || m.cursor >= len(m.store.Connections) {
		return store.Connection{}, false
	}
	return m.store.Connections[m.cursor], true
}

func (m connectionsModel) handleKey(k tea.KeyMsg) (connectionsModel, tea.Cmd) {
	c, has := m.selected()
	switch k.String() {
	case "j", "down":
		if m.cursor < len(m.store.Connections)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "n":
		m.openForm("New connection", store.Connection{Port: 389}, "")
	case "e":
		if has {
			m.openForm("Edit connection: "+c.Name, c, c.Name)
		}
	case "D":
		if has {
			c.Name += " (copy)"
			m.openForm("Duplicate connection", c, "")
		}
	case "d":
		if has {
			name := c.Name
			return m, openOverlay(&confirmOverlay{title: "Delete saved connection", lines: []string{name, c.URL()}, danger: true,
				yes: func() tea.Cmd { return msgCmd(deleteConnMsg{name: name}) }})
		}
	case "t":
		if has {
			return m, msgCmd(connectRequestMsg{conn: c, test: true})
		}
	case "enter":
		if has {
			return m, msgCmd(connectRequestMsg{conn: c})
		}
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m connectionsModel) view() string {
	if m.form != nil {
		return m.form.view()
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("ldapview — connections") + "\n\n")
	if len(m.store.Connections) == 0 {
		b.WriteString(dimStyle.Render("  No saved connections yet. Press n to add one.\n"))
	}
	for i, c := range m.store.Connections {
		tags := []string{string(c.TLSMode)}
		if c.TLSMode == "" || c.TLSMode == store.TLSNone {
			tags = []string{"plaintext"}
		}
		bm := string(c.BindMethod)
		if bm == "" {
			bm = "anonymous"
		}
		if c.BindMethod == store.BindSASL {
			bm += ":" + c.SASLMech
		}
		tags = append(tags, bm)
		if c.SkipVerify {
			tags = append(tags, "no-verify")
		}
		if c.ReadOnly {
			tags = append(tags, "read-only")
		}
		line := fmt.Sprintf("  %-24s %s", truncate(c.Name, 24), c.URL())
		detail := "      " + strings.Join(tags, " · ")
		if c.BindDN != "" {
			detail += " · " + c.BindDN
		}
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(truncate(line, m.width-1)) + "\n")
			b.WriteString(dimStyle.Render(truncate(detail, m.width-1)) + "\n")
		} else {
			b.WriteString(truncate(line, m.width-1) + "\n" + dimStyle.Render(truncate(detail, m.width-1)) + "\n")
		}
	}
	b.WriteString("\n" + dimStyle.Render("enter connect  t test  n new  e edit  D duplicate  d delete  ? help  q quit"))
	return b.String()
}

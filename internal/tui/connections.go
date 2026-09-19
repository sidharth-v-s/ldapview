package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/store"
)

type connFormField int

const (
	fieldName connFormField = iota
	fieldHost
	fieldPort
	fieldTLS
	fieldBindMethod
	fieldBindDN
	fieldCAFile
	fieldSkipVerify
	fieldCount
)

type connectionsModel struct {
	store    *store.Store
	cursor   int
	width    int
	height   int
	editing  bool
	form     [fieldCount]string
	formIdx  connFormField
	editName string // non-empty when editing an existing connection
}

func newConnectionsModel(s *store.Store) connectionsModel {
	return connectionsModel{store: s}
}

func (m *connectionsModel) setSize(w, h int) {
	m.width, m.height = w, h
}

func (m connectionsModel) update(msg tea.Msg) (connectionsModel, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	if m.editing {
		return m.updateForm(keyMsg)
	}

	switch keyMsg.String() {
	case "j", "down":
		if m.cursor < len(m.store.Connections)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "n":
		m.startNew()
	case "e":
		if len(m.store.Connections) > 0 {
			m.startEdit(m.store.Connections[m.cursor])
		}
	case "d":
		if len(m.store.Connections) > 0 {
			name := m.store.Connections[m.cursor].Name
			m.store.Delete(name)
			_ = m.store.Save()
			if m.cursor >= len(m.store.Connections) && m.cursor > 0 {
				m.cursor--
			}
			return m, statusCmd(fmt.Sprintf("deleted %q", name), false)
		}
	case "enter":
		if len(m.store.Connections) > 0 {
			conn := m.store.Connections[m.cursor]
			return m, func() tea.Msg { return connectRequestMsg{conn: conn} }
		}
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

func (m *connectionsModel) startNew() {
	m.editing = true
	m.editName = ""
	m.form = [fieldCount]string{
		fieldPort:       "389",
		fieldTLS:        string(store.TLSNone),
		fieldBindMethod: string(store.BindAnonymous),
		fieldSkipVerify: "no",
	}
	m.formIdx = fieldName
}

func (m *connectionsModel) startEdit(c store.Connection) {
	m.editing = true
	m.editName = c.Name
	m.form = [fieldCount]string{
		fieldName:       c.Name,
		fieldHost:       c.Host,
		fieldPort:       strconv.Itoa(c.DefaultPort()),
		fieldTLS:        string(c.TLSMode),
		fieldBindMethod: string(c.BindMethod),
		fieldBindDN:     c.BindDN,
		fieldCAFile:     c.CAFile,
		fieldSkipVerify: yesNo(c.SkipVerify),
	}
	m.formIdx = fieldName
}

func (m connectionsModel) updateForm(msg tea.KeyMsg) (connectionsModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		return m, nil
	case "tab", "down":
		m.formIdx = (m.formIdx + 1) % fieldCount
	case "shift+tab", "up":
		m.formIdx = (m.formIdx - 1 + fieldCount) % fieldCount
	case "left", "right":
		if m.formIdx == fieldTLS {
			m.form[fieldTLS] = cycleTLS(m.form[fieldTLS], msg.String() == "right")
		} else if m.formIdx == fieldBindMethod {
			m.form[fieldBindMethod] = cycleBind(m.form[fieldBindMethod], msg.String() == "right")
		} else if m.formIdx == fieldSkipVerify {
			m.form[fieldSkipVerify] = yesNo(m.form[fieldSkipVerify] != "yes")
		}
	case "enter":
		return m.submitForm()
	case "backspace":
		f := m.form[m.formIdx]
		if len(f) > 0 {
			m.form[m.formIdx] = f[:len(f)-1]
		}
	default:
		if m.formIdx != fieldTLS && m.formIdx != fieldBindMethod && m.formIdx != fieldSkipVerify && len(msg.Runes) > 0 {
			m.form[m.formIdx] += string(msg.Runes)
		}
	}
	return m, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cycleTLS(cur string, forward bool) string {
	order := []string{string(store.TLSNone), string(store.TLSStartTLS), string(store.TLSImplicit)}
	return cycleStr(order, cur, forward)
}

func cycleBind(cur string, forward bool) string {
	order := []string{string(store.BindAnonymous), string(store.BindSimple), string(store.BindSASL)}
	return cycleStr(order, cur, forward)
}

func cycleStr(order []string, cur string, forward bool) string {
	idx := 0
	for i, v := range order {
		if v == cur {
			idx = i
		}
	}
	if forward {
		idx = (idx + 1) % len(order)
	} else {
		idx = (idx - 1 + len(order)) % len(order)
	}
	return order[idx]
}

func (m connectionsModel) submitForm() (connectionsModel, tea.Cmd) {
	name := strings.TrimSpace(m.form[fieldName])
	host := strings.TrimSpace(m.form[fieldHost])
	if name == "" || host == "" {
		return m, statusCmd("name and host are required", true)
	}
	port, err := strconv.Atoi(strings.TrimSpace(m.form[fieldPort]))
	if err != nil || port <= 0 {
		return m, statusCmd("invalid port", true)
	}
	c := store.Connection{
		Name:       name,
		Host:       host,
		Port:       port,
		TLSMode:    store.TLSMode(m.form[fieldTLS]),
		BindMethod: store.BindMethod(m.form[fieldBindMethod]),
		BindDN:     strings.TrimSpace(m.form[fieldBindDN]),
		CAFile:     strings.TrimSpace(m.form[fieldCAFile]),
		SkipVerify: m.form[fieldSkipVerify] == "yes",
		TimeoutSec: 10,
		SizeLimit:  1000,
		TimeLimit:  10,
	}
	// If renaming, delete the old entry first.
	if m.editName != "" && m.editName != name {
		m.store.Delete(m.editName)
	}
	m.store.Upsert(c)
	if err := m.store.Save(); err != nil {
		return m, statusCmd(fmt.Sprintf("save failed: %s", err), true)
	}
	m.editing = false
	return m, statusCmd(fmt.Sprintf("saved %q", name), false)
}

func (m connectionsModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("ldapview — Connections"))
	b.WriteString("\n\n")

	if m.editing {
		return b.String() + m.formView()
	}

	if len(m.store.Connections) == 0 {
		b.WriteString(dimStyle.Render("No saved connections yet. Press 'n' to add one.\n"))
	}
	for i, c := range m.store.Connections {
		marker := "[ ]"
		line := fmt.Sprintf("%s %s\n    %s", marker, c.Name, c.URL())
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(fmt.Sprintf("%s %s", marker, c.Name)))
			b.WriteString("\n")
			b.WriteString(dimStyle.Render("    " + c.URL()))
			b.WriteString("\n")
		} else {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("n new  e edit  d delete  enter connect  q quit"))
	return b.String()
}

func (m connectionsModel) formView() string {
	labels := []string{"Name", "Host", "Port", "TLS Mode", "Bind Method", "Bind DN", "CA file (PEM)", "Skip TLS verify"}
	var b strings.Builder
	title := "New Connection"
	if m.editName != "" {
		title = "Edit Connection: " + m.editName
	}
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")
	for i := connFormField(0); i < fieldCount; i++ {
		cursor := "  "
		if i == m.formIdx {
			cursor = "> "
		}
		val := m.form[i]
		if i == fieldTLS || i == fieldBindMethod || i == fieldSkipVerify {
			val = "< " + val + " >"
		}
		line := fmt.Sprintf("%s%-16s %s", cursor, labels[i]+":", val)
		if i == m.formIdx {
			b.WriteString(selectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("tab/shift+tab move  left/right cycle  enter save  esc cancel"))
	b.WriteString("\n")
	if m.form[fieldSkipVerify] == "yes" {
		b.WriteString(warnStyle.Render("WARNING: certificate verification disabled — vulnerable to MITM. Prefer a CA file.") + "\n")
	}
	b.WriteString(dimStyle.Render("password is never saved — you'll be prompted each time you connect"))
	return b.String()
}

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/oid"
)

// extOpDetail is a full-screen view of one extended operation: its OID,
// friendly name, and — once sent — the request and response as sent on
// the wire (via the protocol log), never inventing data.
type extOpDetail struct {
	name  string
	oid   string
	sent  bool
	lines []string
}

func newExtOpDetail(o string) extOpDetail {
	return extOpDetail{oid: o, name: oid.Name(o)}
}

type extOpSendMsg struct{ oid string }
type extOpResultMsg struct {
	oid   string
	name  string
	err   error
	authz string
}

func (m extOpDetail) update(msg tea.Msg) (extOpDetail, tea.Cmd) {
	switch msg := msg.(type) {
	case extOpResultMsg:
		if msg.oid != m.oid {
			return m, nil
		}
		m.sent = true
		m.lines = nil
		if msg.err != nil {
			m.lines = append(m.lines, "Result: FAILED", "Error:  "+friendlyErr(msg.err))
		} else {
			m.lines = append(m.lines, "Result: success")
			if msg.oid == oid.WhoAmI {
				id := msg.authz
				if id == "" {
					id = "(anonymous)"
				}
				m.lines = append(m.lines, "Authorization identity: "+id)
			}
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if m.oid == oid.WhoAmI {
				return m, msgCmd(extOpSendMsg{oid: m.oid})
			}
			return m, statusCmd("no built-in request body for this OID — see the raw protocol viewer (P) for exactly what a client would send", false)
		case "y":
			return m, copyCmd(m.oid, "OID")
		case "q", "esc":
			return m, msgCmd(backMsg{})
		}
	}
	return m, nil
}

func sendExtOpCmd(c *ldapclient.Client, o string) tea.Cmd {
	return func() tea.Msg {
		if o != oid.WhoAmI {
			return extOpResultMsg{oid: o, err: fmt.Errorf("not implemented by this client")}
		}
		w, err := c.WhoAmI()
		return extOpResultMsg{oid: o, name: oid.Name(o), err: err, authz: w}
	}
}

func (m extOpDetail) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Extended operation") + "\n\n")
	b.WriteString(kv("Name", firstNonEmpty(m.name, "(unregistered / unknown)")) + "\n")
	b.WriteString(kv("OID", m.oid) + "\n\n")
	if m.oid == oid.WhoAmI {
		b.WriteString(dimStyle.Render("This client implements RFC 4532 \"Who am I?\" (no request value).") + "\n")
		b.WriteString("press enter to send it\n\n")
	} else {
		b.WriteString(dimStyle.Render("This client has no built-in handler for this operation's request value.") + "\n")
		b.WriteString(dimStyle.Render("Open the raw protocol viewer (P) after sending related operations to inspect the wire format.") + "\n\n")
	}
	if m.sent {
		b.WriteString(attrNameStyle.Render("Response") + "\n")
		for _, l := range m.lines {
			b.WriteString("  " + l + "\n")
		}
	}
	b.WriteString("\n" + dimStyle.Render("enter send (where supported)  y copy OID  q back"))
	return b.String()
}

// extOpList shows Root DSE-advertised extensions plus RFC 4532's Who am I?
// as a guaranteed entry (spec §25).
func extOpList(d *ldapclient.RootDSE) []string {
	seen := map[string]bool{oid.WhoAmI: true}
	list := []string{oid.WhoAmI}
	if d != nil {
		for _, o := range d.SupportedExtension {
			if !seen[o] {
				seen[o] = true
				list = append(list, o)
			}
		}
	}
	return list
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

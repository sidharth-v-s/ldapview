package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ad"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/oid"
)

type textLine struct {
	text string
	dn   string
	head bool
}

type rootDSEModel struct {
	lines  []textLine
	cur    int
	scroll int
	height int
}

var dseOrder = []string{"namingContexts", "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
	"schemaNamingContext", "subschemaSubentry", "supportedLDAPVersion", "supportedSASLMechanisms",
	"supportedControl", "supportedExtension", "supportedFeatures", "supportedCapabilities"}

var dnAttrs = map[string]bool{"namingcontexts": true, "defaultnamingcontext": true, "rootdomainnamingcontext": true,
	"configurationnamingcontext": true, "schemanamingcontext": true, "subschemasubentry": true, "servername": true, "dsservicename": true}

var oidAttrs = map[string]bool{"supportedcontrol": true, "supportedextension": true, "supportedfeatures": true, "supportedcapabilities": true}

func newRootDSEModel(d *ldapclient.RootDSE) rootDSEModel {
	m := rootDSEModel{}
	if d == nil {
		m.lines = []textLine{{text: "Root DSE not available"}}
		return m
	}
	done := map[string]bool{}
	now := time.Now()
	emit := func(name string) {
		vals := d.Get(name)
		if len(vals) == 0 || done[strings.ToLower(name)] {
			return
		}
		done[strings.ToLower(name)] = true
		m.lines = append(m.lines, textLine{text: fmt.Sprintf("%s (%d)", name, len(vals)), head: true})
		sorted := append([]string(nil), vals...)
		if oidAttrs[strings.ToLower(name)] {
			sort.Strings(sorted)
		}
		for _, v := range sorted {
			t := v
			if oidAttrs[strings.ToLower(name)] {
				t = oid.Label(v)
			} else if a := ad.Annotate(name, v, now); a != "" {
				t += "   ← " + a
			}
			l := textLine{text: "  " + t}
			if dnAttrs[strings.ToLower(name)] {
				l.dn = v
			}
			m.lines = append(m.lines, l)
		}
	}
	for _, n := range dseOrder {
		emit(n)
	}
	var rest []string
	for k := range d.Attrs {
		if !done[strings.ToLower(k)] {
			rest = append(rest, k)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return strings.ToLower(rest[i]) < strings.ToLower(rest[j]) })
	for _, k := range rest {
		emit(k)
	}
	if ad.IsAD(d.SupportedCapabilities, d.ConfigurationNamingContext) {
		m.lines = append([]textLine{{text: "Active Directory detected (LDAP_CAP_ACTIVE_DIRECTORY_OID advertised)", head: true}, {text: ""}}, m.lines...)
	}
	for i, l := range m.lines {
		if !l.head && l.text != "" {
			m.cur = i
			break
		}
	}
	return m
}

func (m rootDSEModel) update(msg tea.Msg) (rootDSEModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	rows := max(m.height-6, 5)
	move := func(d int) {
		i := m.cur + d
		for i >= 0 && i < len(m.lines) && (m.lines[i].head || m.lines[i].text == "") {
			i += d
		}
		if i >= 0 && i < len(m.lines) {
			m.cur = i
		}
		if m.cur < m.scroll {
			m.scroll = m.cur
		}
		if m.cur >= m.scroll+rows {
			m.scroll = m.cur - rows + 1
		}
	}
	switch k.String() {
	case "j", "down":
		move(1)
	case "k", "up":
		move(-1)
	case "pgdown":
		for i := 0; i < rows; i++ {
			move(1)
		}
	case "pgup":
		for i := 0; i < rows; i++ {
			move(-1)
		}
	case "enter":
		if m.cur < len(m.lines) && m.lines[m.cur].dn != "" {
			return m, msgCmd(gotoMsg{dn: m.lines[m.cur].dn})
		}
	case "y":
		if m.cur < len(m.lines) {
			return m, copyCmd(strings.TrimSpace(m.lines[m.cur].text), "line")
		}
	case "q", "esc":
		return m, msgCmd(backMsg{})
	}
	return m, nil
}

func (m rootDSEModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Root DSE — server capabilities") + "\n\n")
	rows := max(h-6, 5)
	for i := m.scroll; i < len(m.lines) && i < m.scroll+rows; i++ {
		l := m.lines[i]
		txt := truncate(l.text, w-1)
		switch {
		case l.head:
			txt = attrNameStyle.Render(txt)
		case i == m.cur:
			txt = selectedStyle.Render(txt)
		}
		b.WriteString(txt + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("j/k scroll  enter open naming context in browser  y copy  q back"))
	return b.String()
}

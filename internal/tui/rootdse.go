package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldapclient"
)

type rootDSEModel struct {
	dse    *ldapclient.RootDSE
	lines  []string
	scroll int
}

func newRootDSEModel(d *ldapclient.RootDSE) rootDSEModel {
	m := rootDSEModel{dse: d}
	add := func(name string, vals ...string) {
		var nz []string
		for _, v := range vals {
			if v != "" {
				nz = append(nz, v)
			}
		}
		if len(nz) == 0 {
			return
		}
		m.lines = append(m.lines, attrNameStyle.Render(name+":"))
		for _, v := range nz {
			m.lines = append(m.lines, "  "+v)
		}
	}
	add("namingContexts", d.NamingContexts...)
	add("defaultNamingContext", d.DefaultNamingContext)
	add("rootDomainNamingContext", d.RootDomainNamingContext)
	add("configurationNamingContext", d.ConfigurationNamingContext)
	add("schemaNamingContext", d.SchemaNamingContext)
	add("subschemaSubentry", d.SubschemaSubentry)
	add("supportedLDAPVersion", d.SupportedLDAPVersion...)
	add("supportedSASLMechanisms", d.SupportedSASLMechanisms...)
	add("supportedControl", d.SupportedControl...)
	add("supportedExtension", d.SupportedExtension...)
	add("supportedFeatures", d.SupportedFeatures...)
	add("vendorName", d.VendorName)
	add("vendorVersion", d.VendorVersion)
	return m
}

func (m rootDSEModel) update(msg tea.Msg) (rootDSEModel, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "j", "down":
			if m.scroll < len(m.lines)-1 {
				m.scroll++
			}
		case "k", "up":
			if m.scroll > 0 {
				m.scroll--
			}
		case "q", "esc":
			return m, func() tea.Msg { return backToBrowserMsg{} }
		}
	}
	return m, nil
}

func (m rootDSEModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Root DSE") + "\n\n")
	end := m.scroll + 40
	if end > len(m.lines) {
		end = len(m.lines)
	}
	for _, l := range m.lines[m.scroll:end] {
		b.WriteString(l + "\n")
	}
	b.WriteString("\n" + dimStyle.Render(fmt.Sprintf("j/k scroll  q back  (%d lines)", len(m.lines))))
	return b.String()
}

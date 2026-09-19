package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/ldapclient"
)

type searchField int

const (
	sfBase searchField = iota
	sfScope
	sfFilter
	sfAttrs
	sfSize
	sfTime
	sfCount
)

type searchModel struct {
	client  *ldapclient.Client
	width   int
	height  int
	form    [sfCount]string
	idx     searchField
	inForm  bool
	running bool

	results  []ldapclient.Entry
	cur      int
	detail   bool // show selected result's attributes
	limitHit bool
}

type searchDoneMsg struct {
	entries []ldapclient.Entry
	err     error
}

var scopeNames = []string{"base", "one", "sub"}

func newSearchModel(c *ldapclient.Client, base string) searchModel {
	m := searchModel{client: c, inForm: true}
	m.form[sfBase] = base
	m.form[sfScope] = "sub"
	m.form[sfFilter] = "(objectClass=*)"
	m.form[sfAttrs] = "*"
	m.form[sfSize] = "1000"
	m.form[sfTime] = "10"
	m.idx = sfFilter
	return m
}

func (m *searchModel) setSize(w, h int) { m.width, m.height = w, h }

func (m searchModel) scopeValue() int {
	switch m.form[sfScope] {
	case "base":
		return ldap.ScopeBaseObject
	case "one":
		return ldap.ScopeSingleLevel
	}
	return ldap.ScopeWholeSubtree
}

func (m searchModel) runCmd() tea.Cmd {
	client := m.client
	size, _ := strconv.Atoi(m.form[sfSize])
	tl, _ := strconv.Atoi(m.form[sfTime])
	var attrs []string
	for _, a := range strings.Split(m.form[sfAttrs], ",") {
		if a = strings.TrimSpace(a); a != "" {
			attrs = append(attrs, a)
		}
	}
	p := ldapclient.SearchParams{
		Base: m.form[sfBase], Scope: m.scopeValue(), Filter: m.form[sfFilter],
		Attributes: attrs, SizeLimit: size, TimeLimit: tl,
	}
	return func() tea.Msg {
		e, err := client.Search(p)
		return searchDoneMsg{entries: e, err: err}
	}
}

func (m searchModel) update(msg tea.Msg) (searchModel, tea.Cmd) {
	switch msg := msg.(type) {
	case searchDoneMsg:
		m.running = false
		if le, ok := msg.err.(*ldapclient.LimitError); ok {
			m.limitHit = true
			m.results, m.cur, m.inForm = msg.entries, 0, false
			return m, statusCmd(fmt.Sprintf("%s — showing %d partial results", le.Message, len(msg.entries)), true)
		}
		if msg.err != nil {
			return m, statusCmd(friendlyErr(msg.err), true)
		}
		m.limitHit = false
		m.results, m.cur, m.inForm = msg.entries, 0, false
		return m, statusCmd(fmt.Sprintf("%d entries", len(msg.entries)), false)
	case tea.KeyMsg:
		if m.inForm {
			return m.formKey(msg)
		}
		return m.resultKey(msg)
	}
	return m, nil
}

func (m searchModel) formKey(k tea.KeyMsg) (searchModel, tea.Cmd) {
	switch k.String() {
	case "esc":
		return m, func() tea.Msg { return backToBrowserMsg{} }
	case "tab", "down":
		m.idx = (m.idx + 1) % sfCount
	case "shift+tab", "up":
		m.idx = (m.idx - 1 + sfCount) % sfCount
	case "left", "right":
		if m.idx == sfScope {
			m.form[sfScope] = cycleStr(scopeNames, m.form[sfScope], k.String() == "right")
		}
	case "enter":
		m.running = true
		return m, tea.Batch(m.runCmd(), statusCmd("searching…", false))
	case "backspace":
		if s := m.form[m.idx]; len(s) > 0 && m.idx != sfScope {
			m.form[m.idx] = s[:len(s)-1]
		}
	default:
		if m.idx != sfScope && len(k.Runes) > 0 {
			m.form[m.idx] += string(k.Runes)
		}
	}
	return m, nil
}

func (m searchModel) resultKey(k tea.KeyMsg) (searchModel, tea.Cmd) {
	switch k.String() {
	case "j", "down":
		if m.cur < len(m.results)-1 {
			m.cur++
		}
	case "k", "up":
		if m.cur > 0 {
			m.cur--
		}
	case "enter":
		m.detail = !m.detail
	case "c":
		if len(m.results) > 0 {
			return m, copyCmd(m.results[m.cur].DN, "DN")
		}
	case "b":
		// use selected result as new search base
		if len(m.results) > 0 {
			m.form[sfBase] = m.results[m.cur].DN
			m.inForm = true
			m.detail = false
		}
	case "e", "s", "/":
		m.inForm, m.detail = true, false
	case "q", "esc":
		return m, func() tea.Msg { return backToBrowserMsg{} }
	}
	return m, nil
}

func (m searchModel) view() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("LDAP Search") + "\n\n")
	if m.inForm {
		labels := []string{"Base", "Scope", "Filter", "Attributes", "Size limit", "Time limit (s)"}
		for i := searchField(0); i < sfCount; i++ {
			v := m.form[i]
			if i == sfScope {
				v = "< " + v + " >"
			}
			line := fmt.Sprintf("  %-15s %s", labels[i]+":", v)
			if i == m.idx {
				line = selectedStyle.Render(fmt.Sprintf("> %-15s %s", labels[i]+":", v))
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n" + dimStyle.Render("tab move  ←/→ scope  enter search  esc back"))
		if m.running {
			b.WriteString("\n" + dimStyle.Render("searching…"))
		}
		return b.String()
	}

	note := ""
	if m.limitHit {
		note = "  (server/size limit reached)"
	}
	b.WriteString(fmt.Sprintf("Filter: %s\nResults: %d%s\n\n", m.form[sfFilter], len(m.results), note))
	h := m.height - 10
	if h < 5 {
		h = 5
	}
	start := 0
	if m.cur >= h {
		start = m.cur - h + 1
	}
	for i := start; i < len(m.results) && i < start+h; i++ {
		line := truncate(m.results[i].DN, m.width-2)
		if i == m.cur {
			line = selectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	if m.detail && len(m.results) > 0 {
		b.WriteString("\n" + attrNameStyle.Render("Entry") + "\n")
		for _, a := range m.results[m.cur].Attributes {
			if a.Binary {
				b.WriteString(fmt.Sprintf("  %s: %s\n", a.Name, binaryTagStyle.Render(fmt.Sprintf("<binary, %d value(s)>", len(a.RawBytes)))))
				continue
			}
			for _, v := range a.Values {
				b.WriteString(fmt.Sprintf("  %s: %s\n", a.Name, truncate(v, m.width-len(a.Name)-6)))
			}
		}
	}
	b.WriteString("\n" + dimStyle.Render("j/k move  enter details  c copy DN  b use as base  e edit search  q back"))
	return b.String()
}

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/model"
	"github.com/zoro/ldapview/internal/store"
)

type pane int

const (
	paneTree pane = iota
	paneEntry
)

type browserModel struct {
	client *ldapclient.Client
	conf   store.Connection
	width  int
	height int

	roots        []*model.Node
	cursor       int
	focus        pane
	entry        *ldapclient.Entry
	entryCur     int // attribute/value row cursor in entry pane
	entryScroll  int
	loadingEntry bool
	dse          *ldapclient.RootDSE
}

// --- messages ---

type rootsLoadedMsg struct {
	dse   *ldapclient.RootDSE
	roots []string
	err   error
}

type childrenLoadedMsg struct {
	dn       string
	children []ldapclient.Child
	err      error
}

type entryLoadedMsg struct {
	entry *ldapclient.Entry
	err   error
}

func newBrowserModel(c *ldapclient.Client, conf store.Connection) browserModel {
	return browserModel{client: c, conf: conf}
}

func (m *browserModel) setSize(w, h int) { m.width, m.height = w, h }

// loadRootCmd reads the Root DSE then seeds the tree with naming contexts.
func (m browserModel) loadRootCmd() tea.Cmd {
	client := m.client
	return func() tea.Msg {
		dse, err := client.FetchRootDSE()
		if err != nil {
			return rootsLoadedMsg{err: err}
		}
		roots := dse.NamingContexts
		if len(roots) == 0 && dse.DefaultNamingContext != "" {
			roots = []string{dse.DefaultNamingContext}
		}
		return rootsLoadedMsg{dse: dse, roots: roots}
	}
}

func (m browserModel) expandCmd(dn string) tea.Cmd {
	client := m.client
	return func() tea.Msg {
		ch, err := client.ExpandOneLevel(dn)
		return childrenLoadedMsg{dn: dn, children: ch, err: err}
	}
}

func (m browserModel) readEntryCmd(dn string) tea.Cmd {
	client := m.client
	return func() tea.Msg {
		e, err := client.ReadEntry(dn)
		return entryLoadedMsg{entry: e, err: err}
	}
}

// flat returns visible nodes across all roots.
func (m browserModel) flat() []*model.Node {
	var out []*model.Node
	for _, r := range m.roots {
		out = append(out, model.Visible(r)...)
	}
	return out
}

func (m browserModel) current() *model.Node {
	f := m.flat()
	if m.cursor < 0 || m.cursor >= len(f) {
		return nil
	}
	return f[m.cursor]
}

func findNode(roots []*model.Node, dn string) *model.Node {
	var walk func(n *model.Node) *model.Node
	walk = func(n *model.Node) *model.Node {
		if strings.EqualFold(n.DN, dn) {
			return n
		}
		for _, c := range n.Children {
			if r := walk(c); r != nil {
				return r
			}
		}
		return nil
	}
	for _, r := range roots {
		if n := walk(r); n != nil {
			return n
		}
	}
	return nil
}

func (m browserModel) update(msg tea.Msg) (browserModel, tea.Cmd) {
	switch msg := msg.(type) {
	case rootsLoadedMsg:
		if msg.err != nil {
			return m, statusCmd("Root DSE: "+friendlyErr(msg.err), true)
		}
		m.dse = msg.dse
		m.roots = nil
		for _, dn := range msg.roots {
			m.roots = append(m.roots, &model.Node{DN: dn})
		}
		if len(m.roots) == 0 {
			return m, statusCmd("server advertised no naming contexts; use g to go to a DN", true)
		}
		return m, nil

	case childrenLoadedMsg:
		n := findNode(m.roots, msg.dn)
		if n == nil {
			return m, nil
		}
		n.Loading = false
		if msg.err != nil {
			return m, statusCmd(friendlyErr(msg.err), true)
		}
		n.Children = nil
		for _, c := range msg.children {
			n.Children = append(n.Children, &model.Node{DN: c.DN, ObjectClass: c.ObjectClass, Parent: n, KnownLeaf: c.HasSubordinates != nil && !*c.HasSubordinates})
		}
		n.Loaded = true
		n.Expanded = true
		return m, statusCmd(fmt.Sprintf("%d children under %s", len(n.Children), n.DN), false)

	case entryLoadedMsg:
		m.loadingEntry = false
		if msg.err != nil {
			return m, statusCmd(friendlyErr(msg.err), true)
		}
		m.entry = msg.entry
		m.entryCur, m.entryScroll = 0, 0
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m browserModel) handleKey(k tea.KeyMsg) (browserModel, tea.Cmd) {
	switch k.String() {
	case "tab", "shift+tab":
		if m.focus == paneTree {
			m.focus = paneEntry
		} else {
			m.focus = paneTree
		}
		return m, nil
	case "q":
		return m, func() tea.Msg { return disconnectMsg{} }
	case "s", "/":
		base := ""
		if n := m.current(); n != nil {
			base = n.DN
		}
		return m, func() tea.Msg { return openSearchMsg{base: base} }
	case "R":
		if m.dse != nil {
			dse := m.dse
			return m, func() tea.Msg { return openRootDSEMsg{dse: dse} }
		}
	}
	if m.focus == paneTree {
		return m.handleTreeKey(k)
	}
	return m.handleEntryKey(k)
}

func (m browserModel) handleTreeKey(k tea.KeyMsg) (browserModel, tea.Cmd) {
	f := m.flat()
	switch k.String() {
	case "j", "down":
		if m.cursor < len(f)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "l", "right", "enter":
		n := m.current()
		if n == nil {
			return m, nil
		}
		var cmds []tea.Cmd
		if !n.Loaded && !n.Loading {
			n.Loading = true
			cmds = append(cmds, m.expandCmd(n.DN))
		} else if n.Loaded {
			n.Expanded = true
		}
		m.loadingEntry = true
		cmds = append(cmds, m.readEntryCmd(n.DN))
		return m, tea.Batch(cmds...)
	case "h", "left":
		n := m.current()
		if n == nil {
			return m, nil
		}
		if n.Expanded {
			n.Expanded = false
		} else if n.Parent != nil {
			for i, x := range m.flat() {
				if x == n.Parent {
					m.cursor = i
					break
				}
			}
		}
	case "r":
		n := m.current()
		if n == nil {
			return m, nil
		}
		n.Loaded, n.Expanded, n.Children = false, false, nil
		n.Loading = true
		return m, tea.Batch(m.expandCmd(n.DN), m.readEntryCmd(n.DN))
	case "c":
		if n := m.current(); n != nil {
			return m, copyCmd(n.DN, "DN")
		}
	}
	return m, nil
}

type entryRow struct {
	attr  string
	value string
	bin   []byte
	isBin bool
}

func (m browserModel) entryRows() []entryRow {
	if m.entry == nil {
		return nil
	}
	var rows []entryRow
	for _, a := range m.entry.Attributes {
		if a.Binary {
			for _, b := range a.RawBytes {
				rows = append(rows, entryRow{attr: a.Name, value: binarySummary(a.Name, b), bin: b, isBin: true})
			}
			continue
		}
		for _, v := range a.Values {
			rows = append(rows, entryRow{attr: a.Name, value: v})
		}
	}
	return rows
}

// binarySummary decodes well-known AD binary attrs, else shows length.
func binarySummary(name string, b []byte) string {
	switch strings.ToLower(name) {
	case "objectsid":
		if s, err := ldapclient.DecodeObjectSID(b); err == nil {
			return s
		}
	case "objectguid":
		if s, err := ldapclient.DecodeObjectGUID(b); err == nil {
			return s
		}
	}
	return fmt.Sprintf("<binary %d bytes> (enter: hex/base64)", len(b))
}

func (m browserModel) handleEntryKey(k tea.KeyMsg) (browserModel, tea.Cmd) {
	rows := m.entryRows()
	switch k.String() {
	case "j", "down":
		if m.entryCur < len(rows)-1 {
			m.entryCur++
		}
	case "k", "up":
		if m.entryCur > 0 {
			m.entryCur--
		}
	case "enter":
		if m.entryCur < len(rows) && rows[m.entryCur].isBin {
			r := rows[m.entryCur]
			return m, func() tea.Msg { return openBinaryMsg{attrName: r.attr, data: r.bin} }
		}
	case "y":
		if m.entryCur < len(rows) && !rows[m.entryCur].isBin {
			return m, copyCmd(rows[m.entryCur].value, rows[m.entryCur].attr)
		}
	case "c":
		if m.entry != nil {
			return m, copyCmd(m.entry.DN, "DN")
		}
	}
	return m, nil
}

func (m browserModel) view() string {
	h := m.height - 5 // title + top/bottom border + keys + status bar
	if h < 5 {
		h = 5
	}
	leftW := m.width / 3
	if leftW < 30 {
		leftW = 30
	}
	rightW := m.width - leftW - 6
	if rightW < 20 {
		rightW = 20
	}

	// tree
	f := m.flat()
	var tb strings.Builder
	start := 0
	if m.cursor >= h-2 {
		start = m.cursor - (h - 3)
	}
	for i := start; i < len(f) && i < start+h-2; i++ {
		n := f[i]
		marker := "+"
		switch {
		case n.Loading:
			marker = "…"
		case n.IsLeaf():
			marker = " "
		case n.Expanded:
			marker = "-"
		}
		label := treeLabel(n)
		line := strings.Repeat("  ", n.Depth()) + marker + " " + label
		line = truncate(line, leftW-2)
		if i == m.cursor {
			line = selectedStyle.Render(line)
		}
		tb.WriteString(line + "\n")
	}
	if len(f) == 0 {
		tb.WriteString(dimStyle.Render("loading…"))
	}

	// entry
	var eb strings.Builder
	if m.entry == nil {
		eb.WriteString(dimStyle.Render("Enter/l on a tree node to load its entry"))
	} else {
		eb.WriteString(attrNameStyle.Render("DN") + "\n  " + truncate(m.entry.DN, rightW-4) + "\n\n")
		rows := m.entryRows()
		// Render every line (attr headers + values) into a flat list, then
		// window it so the pane never exceeds h rows.
		type line struct {
			text string
			row  int // index into rows, or -1 for attr-name headers
		}
		var lines []line
		last := ""
		for i, r := range rows {
			if r.attr != last {
				lines = append(lines, line{attrNameStyle.Render(r.attr), -1})
				last = r.attr
			}
			txt := "  " + truncate(r.value, rightW-4)
			switch {
			case m.focus == paneEntry && i == m.entryCur:
				txt = selectedStyle.Render(truncate("  "+r.value, rightW-4))
			case r.isBin:
				txt = "  " + binaryTagStyle.Render(truncate(r.value, rightW-4))
			}
			lines = append(lines, line{txt, i})
		}
		avail := h - 3 // DN label + DN + blank
		if avail < 3 {
			avail = 3
		}
		sel := 0
		for i, l := range lines {
			if l.row == m.entryCur {
				sel = i
			}
		}
		start := 0
		if sel >= avail {
			start = sel - avail + 1
		}
		for i := start; i < len(lines) && i < start+avail; i++ {
			eb.WriteString(lines[i].text + "\n")
		}
	}

	lp, rp := paneStyle, paneStyle
	if m.focus == paneTree {
		lp = activePaneStyle
	} else {
		rp = activePaneStyle
	}
	// Height() is only a minimum in lipgloss; trim trailing newlines and
	// clamp with MaxHeight (h + 2 border rows) so both panes end together.
	left := lp.Width(leftW).Height(h).MaxHeight(h + 2).Render(strings.TrimRight(tb.String(), "\n"))
	right := rp.Width(rightW).Height(h).MaxHeight(h + 2).Render(strings.TrimRight(eb.String(), "\n"))
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	keys := dimStyle.Render("j/k move  l/enter open  h back  tab pane  s search  r refresh  c copy DN  y copy value  R rootDSE  ? help  q disconnect")
	return titleStyle.Render("ldapview — "+m.conf.Name) + "\n" + body + "\n" + keys
}

func treeLabel(n *model.Node) string {
	if n.Parent == nil {
		return n.DN
	}
	if i := strings.Index(n.DN, ","); i > 0 {
		return n.DN[:i]
	}
	return n.DN
}

func truncate(s string, w int) string {
	if w <= 1 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	return string(r[:w-1]) + "…"
}

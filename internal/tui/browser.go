package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/dn"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
	"github.com/zoro/ldapview/internal/model"
)

type pane int

const (
	paneTree pane = iota
	paneEntry
)

type entryMode int

const (
	modeAttrs entryMode = iota
	modeLDIF
	modeRaw
	modeRel
	modeSchema
	modeSec
)

var modeNames = []string{"attributes", "LDIF", "raw", "relationships", "schema", "security"}

// eline is one rendered line of the entry pane.
type eline struct {
	text string
	sel  bool
	head bool
	attr string
	val  string
	raw  []byte
	bin  bool
	dn   string
	anno string
}

type relData struct {
	dn      string
	loading bool
	reverse []string
	err     error
}

type browserModel struct {
	sh     *shared
	width  int
	height int

	roots   []*model.Node
	cursor  int
	tscroll int
	focus   pane

	entry   *ldapclient.Entry
	lines   []eline
	ecur    int
	escroll int
	mode    entryMode
	loading bool

	findQ      string
	gotoChain  []string
	gotoTarget string
	pendingSel string
	rel        *relData
	sdLines    []string
	sdFor      string
	marked     *ldapclient.Entry
}

func newBrowserModel(sh *shared) browserModel { return browserModel{sh: sh} }

func (m *browserModel) setSize(w, h int) { m.width, m.height = w, h }

func (m browserModel) paneH() int {
	h := m.height - 5
	if h < 5 {
		h = 5
	}
	return h
}

func (m browserModel) loadRootCmd() tea.Cmd {
	c := m.sh.client
	return func() tea.Msg {
		dse := c.DSE()
		if dse == nil {
			d, err := c.FetchRootDSE()
			if err != nil {
				return rootsLoadedMsg{err: err}
			}
			dse = d
		}
		roots := dse.NamingContexts
		if len(roots) == 0 && dse.DefaultNamingContext != "" {
			roots = []string{dse.DefaultNamingContext}
		}
		return rootsLoadedMsg{dse: dse, roots: roots}
	}
}

func (m browserModel) expandCmd(d string) tea.Cmd {
	c := m.sh.client
	return func() tea.Msg {
		ch, err := c.ExpandOneLevel(d)
		return childrenLoadedMsg{dn: d, children: ch, err: err}
	}
}

func (m browserModel) readEntryCmd(d string) tea.Cmd {
	c := m.sh.client
	return func() tea.Msg {
		e, err := c.ReadEntry(d)
		return entryLoadedMsg{entry: e, err: err}
	}
}

// readEntryFreshCmd bypasses the recently-visited cache (explicit refresh
// and after directory operations).
func (m browserModel) readEntryFreshCmd(d string) tea.Cmd {
	c := m.sh.client
	return func() tea.Msg {
		e, err := c.ReadEntryFresh(d)
		return entryLoadedMsg{entry: e, err: err}
	}
}

func dnEqual(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	pa, e1 := ldap.ParseDN(a)
	pb, e2 := ldap.ParseDN(b)
	if e1 != nil || e2 != nil {
		return false
	}
	return pa.EqualFold(pb)
}

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

func findNode(roots []*model.Node, d string) *model.Node {
	var walk func(n *model.Node) *model.Node
	walk = func(n *model.Node) *model.Node {
		if dnEqual(n.DN, d) {
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

func (m *browserModel) selectNode(n *model.Node) {
	for i, x := range m.flat() {
		if x == n {
			m.cursor = i
			m.snapTree()
			return
		}
	}
}

func (m *browserModel) snapTree() {
	rows := m.paneH() - 2
	if m.cursor < m.tscroll {
		m.tscroll = m.cursor
	}
	if m.cursor >= m.tscroll+rows {
		m.tscroll = m.cursor - rows + 1
	}
	if m.tscroll < 0 {
		m.tscroll = 0
	}
}

func (m *browserModel) snapEntry() {
	rows := m.paneH() - 3
	if m.ecur < m.escroll {
		m.escroll = m.ecur
		// keep the attribute header visible above the selected value
		if m.escroll > 0 && m.lines[m.escroll-1].head {
			m.escroll--
		}
	}
	if m.ecur >= m.escroll+rows {
		m.escroll = m.ecur - rows + 1
	}
	if m.escroll < 0 {
		m.escroll = 0
	}
}

// ---- goto ----

func (m browserModel) rootFor(d string) *model.Node {
	for _, r := range m.roots {
		if dnEqual(d, r.DN) || strings.HasSuffix(strings.ToLower(strings.ReplaceAll(d, ", ", ",")), ","+strings.ToLower(strings.ReplaceAll(r.DN, ", ", ","))) {
			return r
		}
	}
	return nil
}

func (m browserModel) startGoto(target string) (browserModel, tea.Cmd) {
	target = strings.TrimSpace(target)
	if !dn.Valid(target) {
		return m, statusCmd("not a valid DN: "+target, true)
	}
	root := m.rootFor(target)
	if root == nil {
		root = &model.Node{DN: target}
		m.roots = append(m.roots, root)
	}
	chain := []string{target}
	cur := target
	for !dnEqual(cur, root.DN) {
		p, err := dn.Parent(cur)
		if err != nil || p == "" {
			break
		}
		chain = append([]string{p}, chain...)
		cur = p
	}
	m.gotoChain, m.gotoTarget, m.focus = chain, target, paneTree
	return m.advanceGoto()
}

func (m browserModel) advanceGoto() (browserModel, tea.Cmd) {
	for len(m.gotoChain) > 0 {
		head := m.gotoChain[0]
		n := findNode(m.roots, head)
		if n == nil {
			target := m.gotoTarget
			m.gotoChain = nil
			return m, statusCmd("could not reveal "+target+" in the tree (entry may not exist)", true)
		}
		if len(m.gotoChain) == 1 {
			m.gotoChain = nil
			m.selectNode(n)
			m.loading = true
			return m, m.readEntryCmd(n.DN)
		}
		if !n.Loaded {
			if !n.Loading {
				n.Loading = true
				return m, m.expandCmd(n.DN)
			}
			return m, nil
		}
		n.Expanded = true
		m.gotoChain = m.gotoChain[1:]
	}
	return m, nil
}

// ---- update ----

func (m browserModel) update(msg tea.Msg) (browserModel, tea.Cmd) {
	switch msg := msg.(type) {
	case rootsLoadedMsg:
		if msg.err != nil {
			return m, statusCmd("Root DSE: "+friendlyErr(msg.err), true)
		}
		m.roots = nil
		for _, d := range msg.roots {
			m.roots = append(m.roots, &model.Node{DN: d})
		}
		if len(m.roots) == 0 {
			return m, statusCmd("server advertised no naming contexts; press g to go to a DN", true)
		}
		return m, nil

	case childrenLoadedMsg:
		n := findNode(m.roots, msg.dn)
		if n == nil {
			return m, nil
		}
		n.Loading = false
		if msg.err != nil {
			m.gotoChain = nil
			return m, statusCmd(friendlyErr(msg.err), true)
		}
		n.Children = nil
		for _, c := range msg.children {
			n.Children = append(n.Children, &model.Node{DN: c.DN, ObjectClass: c.ObjectClass, Parent: n,
				KnownLeaf: c.HasSubordinates != nil && !*c.HasSubordinates})
		}
		n.Loaded, n.Expanded = true, true
		var cmds []tea.Cmd
		if m.pendingSel != "" {
			if t := findNode(m.roots, m.pendingSel); t != nil {
				m.selectNode(t)
				m.pendingSel = ""
			}
		}
		if len(m.gotoChain) > 0 {
			var c tea.Cmd
			m, c = m.advanceGoto()
			cmds = append(cmds, c)
		} else {
			cmds = append(cmds, statusCmd(fmt.Sprintf("%d children under %s", len(n.Children), n.DN), false))
		}
		return m, tea.Batch(cmds...)

	case entryLoadedMsg:
		m.loading = false
		if msg.err != nil {
			return m, statusCmd(friendlyErr(msg.err), true)
		}
		m.entry = msg.entry
		m.ecur, m.escroll = 0, 0
		m.sdLines, m.sdFor = nil, ""
		m.rel = nil
		m.rebuild()
		return m, m.modeCmd()

	case relLoadedMsg:
		if m.entry != nil && dnEqual(m.entry.DN, msg.dn) {
			m.rel = &relData{dn: msg.dn, reverse: msg.reverse, err: msg.err}
			m.rebuild()
		}
		return m, nil

	case sdLoadedMsg:
		if msg.err != nil {
			return m, statusCmd("security descriptor: "+friendlyErr(msg.err), true)
		}
		m.sdLines, m.sdFor = sdToLines(msg.sd), msg.dn
		m.mode = modeSec
		m.rebuild()
		return m, nil

	case schemaLoadedMsg:
		m.rebuild()
		return m, nil

	case opDoneMsg:
		var cmds []tea.Cmd
		if msg.clearEntry {
			m.entry = nil
			m.lines = nil
		}
		if msg.selectDN != "" {
			m.pendingSel = msg.selectDN
		}
		for _, d := range msg.refreshChildren {
			if n := findNode(m.roots, d); n != nil {
				n.Loaded, n.Expanded, n.Children = false, false, nil
				n.Loading = true
				cmds = append(cmds, m.expandCmd(n.DN))
			}
		}
		if msg.refreshEntry != "" {
			m.loading = true
			cmds = append(cmds, m.readEntryFreshCmd(msg.refreshEntry))
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// modeCmd loads data the current view mode needs.
func (m browserModel) modeCmd() tea.Cmd {
	if m.entry == nil {
		return nil
	}
	switch m.mode {
	case modeRel:
		if m.rel == nil || !dnEqual(m.rel.dn, m.entry.DN) {
			return m.loadRelCmd()
		}
	case modeSchema:
		if m.sh.schema == nil {
			return msgCmd(needSchemaMsg{})
		}
	}
	return nil
}

func (m browserModel) loadRelCmd() tea.Cmd {
	c := m.sh.client
	target := m.entry.DN
	base := ""
	if r := m.rootFor(target); r != nil {
		base = r.DN
	}
	return func() tea.Msg {
		if base == "" {
			return relLoadedMsg{dn: target}
		}
		esc := ldap.EscapeFilter(target)
		f := "(|(member=" + esc + ")(uniqueMember=" + esc + ")(manager=" + esc + ")(owner=" + esc + ")(seeAlso=" + esc + ")(managedBy=" + esc + "))"
		out, err := c.SearchEx(ldapclient.SearchParams{Base: base, Scope: ldap.ScopeWholeSubtree, Filter: f, Attributes: []string{"1.1"}, SizeLimit: 200, TimeLimit: 10})
		if err != nil {
			return relLoadedMsg{dn: target, err: err}
		}
		var dns []string
		for _, e := range out.Entries {
			dns = append(dns, e.DN)
		}
		return relLoadedMsg{dn: target, reverse: dns}
	}
}

func (m browserModel) loadSDCmd() tea.Cmd {
	c := m.sh.client
	d := m.entry.DN
	return func() tea.Msg {
		raw, err := c.ReadSecurityDescriptor(d)
		if err != nil {
			return sdLoadedMsg{dn: d, err: err}
		}
		sd, err := parseSD(raw)
		return sdLoadedMsg{dn: d, sd: sd, err: err}
	}
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
		return m, msgCmd(disconnectMsg{})
	case "s":
		base := ""
		if n := m.current(); n != nil {
			base = n.DN
		}
		return m, msgCmd(openSearchMsg{base: base})
	case "R":
		return m, msgCmd(openRootDSEMsg{})
	case "S":
		q := ""
		if m.entry != nil {
			if oc := m.entry.Get("objectClass"); len(oc) > 0 {
				q = oc[len(oc)-1]
			}
		}
		return m, msgCmd(openSchemaMsg{query: q})
	case "L":
		return m, msgCmd(openScreenMsg{screenOps})
	case "P":
		return m, msgCmd(openScreenMsg{screenProto})
	case "g":
		return m, openOverlay(newPrompt("go to DN", "", "reveals the entry in the tree", func(s string) tea.Cmd { return msgCmd(gotoMsg{dn: s}) }))
	case "v":
		m.mode = (m.mode + 1) % entryMode(len(modeNames))
		m.ecur, m.escroll = 0, 0
		m.rebuild()
		return m, tea.Batch(m.modeCmd(), statusCmd("view: "+modeNames[m.mode], false))
	case "=":
		if m.entry == nil {
			return m, nil
		}
		if m.marked == nil {
			e := *m.entry
			m.marked = &e
			return m, statusCmd("marked "+e.DN+" — load another entry and press = to compare", false)
		}
		return m, msgCmd(diffMsg{})
	case "Y":
		if m.entry != nil {
			return m, copyCmd(ldif.EntryString(toLDIFEntry(*m.entry)), "entry as LDIF")
		}
	case "x":
		if m.entry != nil {
			e := m.entry
			def := defaultExportName(rdnSlug(e.DN), "ldif")
			return m, openOverlay(newPrompt("export entry", def, "extension selects format: .ldif  .json  .txt", func(p string) tea.Cmd {
				return msgCmd(exportEntryMsg{path: strings.TrimSpace(p), entry: e})
			}))
		}
	case "D":
		if m.entry != nil {
			return m, msgCmd(deleteEntryMsg{dn: m.entry.DN})
		}
	case "A":
		if m.entry == nil {
			return m, nil
		}
		if !m.sh.isAD {
			return m, statusCmd("security descriptors are read only on Active Directory servers", true)
		}
		return m, tea.Batch(m.loadSDCmd(), statusCmd("reading nTSecurityDescriptor…", false))
	}
	if m.focus == paneTree {
		return m.handleTreeKey(k)
	}
	return m.handleEntryKey(k)
}

func rdnSlug(d string) string {
	r, err := dn.RDN(d)
	if err != nil {
		return "entry"
	}
	r = strings.Map(func(c rune) rune {
		if c == '=' || c == ',' || c == ' ' || c == '/' || c == '\\' {
			return '_'
		}
		return c
	}, r)
	return r
}

func (m browserModel) handleTreeKey(k tea.KeyMsg) (browserModel, tea.Cmd) {
	f := m.flat()
	switch k.String() {
	case "j", "down":
		if m.cursor < len(f)-1 {
			m.cursor++
			m.snapTree()
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
			m.snapTree()
		}
	case "pgdown":
		m.cursor = min(m.cursor+m.paneH()-2, max(len(f)-1, 0))
		m.snapTree()
	case "pgup":
		m.cursor = max(m.cursor-(m.paneH()-2), 0)
		m.snapTree()
	case "home":
		m.cursor = 0
		m.snapTree()
	case "end":
		m.cursor = max(len(f)-1, 0)
		m.snapTree()
	case "l", "right", "enter":
		n := m.current()
		if n == nil {
			return m, nil
		}
		var cmds []tea.Cmd
		if !n.Loaded && !n.Loading && !n.KnownLeaf {
			n.Loading = true
			cmds = append(cmds, m.expandCmd(n.DN))
		} else if n.Loaded {
			n.Expanded = true
		}
		m.loading = true
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
			m.selectNode(n.Parent)
		}
	case "r":
		n := m.current()
		if n == nil {
			return m, nil
		}
		n.Loaded, n.Expanded, n.Children = false, false, nil
		n.Loading = true
		m.loading = true
		return m, tea.Batch(m.expandCmd(n.DN), m.readEntryFreshCmd(n.DN))
	case "c":
		if n := m.current(); n != nil {
			return m, copyCmd(n.DN, "DN")
		}
	case "/":
		return m, openOverlay(newPrompt("find in tree", m.findQ, "substring of a loaded node's name; n / N repeat", func(s string) tea.Cmd {
			return msgCmd(findMsg{q: s})
		}))
	case "n", "N":
		return m.findNext(k.String() == "n")
	case "a":
		if n := m.current(); n != nil {
			return m, msgCmd(addEntryMsg{parent: n.DN})
		}
	case "d":
		if n := m.current(); n != nil {
			return m, msgCmd(deleteEntryMsg{dn: n.DN})
		}
	case "m":
		if n := m.current(); n != nil {
			return m, msgCmd(modDNMsg{dn: n.DN})
		}
	case "e":
		m.focus = paneEntry
	}
	return m, nil
}

type findMsg struct{ q string }

func (m browserModel) findNext(fwd bool) (browserModel, tea.Cmd) {
	if m.findQ == "" {
		return m, statusCmd("nothing to find — press / first", true)
	}
	f := m.flat()
	q := strings.ToLower(m.findQ)
	for i := 1; i <= len(f); i++ {
		j := (m.cursor + i) % len(f)
		if !fwd {
			j = ((m.cursor-i)%len(f) + len(f)) % len(f)
		}
		if strings.Contains(strings.ToLower(treeLabel(f[j])), q) {
			m.cursor = j
			m.snapTree()
			return m, nil
		}
	}
	return m, statusCmd("no loaded node matches "+m.findQ, true)
}

func (m *browserModel) moveEntry(d int) {
	if len(m.lines) == 0 {
		return
	}
	i := m.ecur + d
	for i >= 0 && i < len(m.lines) && !m.lines[i].sel {
		i += d
	}
	if i >= 0 && i < len(m.lines) {
		m.ecur = i
	}
	m.snapEntry()
}

func (m browserModel) handleEntryKey(k tea.KeyMsg) (browserModel, tea.Cmd) {
	var cur *eline
	if m.ecur >= 0 && m.ecur < len(m.lines) {
		cur = &m.lines[m.ecur]
	}
	switch k.String() {
	case "j", "down":
		m.moveEntry(1)
	case "k", "up":
		m.moveEntry(-1)
	case "pgdown":
		for i := 0; i < m.paneH()-3; i++ {
			m.moveEntry(1)
		}
	case "pgup":
		for i := 0; i < m.paneH()-3; i++ {
			m.moveEntry(-1)
		}
	case "home":
		m.ecur = 0
		m.moveEntry(0)
		m.ecur = firstSel(m.lines)
		m.snapEntry()
	case "end":
		for i := len(m.lines) - 1; i >= 0; i-- {
			if m.lines[i].sel {
				m.ecur = i
				break
			}
		}
		m.snapEntry()
	case "enter":
		if cur == nil {
			return m, nil
		}
		if cur.bin {
			return m, msgCmd(openBinaryMsg{attrName: cur.attr, data: cur.raw})
		}
		if cur.dn != "" {
			return m, msgCmd(gotoMsg{dn: cur.dn})
		}
	case "y":
		if cur != nil && !cur.head {
			v := cur.val
			if v == "" {
				v = cur.text
			}
			if cur.bin {
				v = ldapclient.Base64String(cur.raw)
			}
			return m, copyCmd(v, "value")
		}
	case "c":
		if m.entry != nil {
			return m, copyCmd(m.entry.DN, "DN")
		}
	case "e", "a", "d", "x":
		if m.entry == nil {
			return m, nil
		}
		if m.mode != modeAttrs {
			return m, statusCmd("switch to the attributes view (v) to modify values", true)
		}
		attr := ""
		if cur != nil {
			attr = cur.attr
		}
		switch k.String() {
		case "a":
			return m, msgCmd(addValueMsg{dn: m.entry.DN, attr: attr})
		case "e":
			if cur == nil || cur.bin || cur.attr == "" {
				return m, statusCmd("select a text value to edit", true)
			}
			return m, msgCmd(editValueMsg{dn: m.entry.DN, attr: cur.attr, old: cur.val})
		default:
			if cur == nil || cur.attr == "" {
				return m, statusCmd("select a value to delete", true)
			}
			v := cur.val
			if cur.bin {
				return m, statusCmd("deleting individual binary values is not supported here", true)
			}
			return m, msgCmd(delValueMsg{dn: m.entry.DN, attr: cur.attr, val: v})
		}
	}
	return m, nil
}

func firstSel(ls []eline) int {
	for i, l := range ls {
		if l.sel {
			return i
		}
	}
	return 0
}

// ---- view ----

func (m browserModel) view() string {
	h := m.paneH()
	leftW := m.width / 3
	if leftW < 30 {
		leftW = 30
	}
	rightW := m.width - leftW - 6
	if rightW < 20 {
		rightW = 20
	}

	f := m.flat()
	var tb strings.Builder
	rows := h - 2
	for i := m.tscroll; i < len(f) && i < m.tscroll+rows; i++ {
		n := f[i]
		marker := "+"
		switch {
		case n.Loading:
			marker = "…"
		case n.IsLeaf():
			marker = "·"
		case n.Expanded:
			marker = "-"
		}
		line := strings.Repeat("  ", n.Depth()) + marker + " " + treeLabel(n)
		line = truncate(line, leftW-2)
		if i == m.cursor {
			line = selectedStyle.Render(line)
		}
		tb.WriteString(line + "\n")
	}
	if len(f) == 0 {
		tb.WriteString(dimStyle.Render("loading…"))
	}

	var eb strings.Builder
	if m.entry == nil {
		eb.WriteString(dimStyle.Render("enter / l on a tree node loads its entry\n\ng go to DN   s search   ? help"))
	} else {
		eb.WriteString(attrNameStyle.Render("DN ") + truncate(m.entry.DN, rightW-6) + "\n")
		eb.WriteString(dimStyle.Render("view: ") + roleStyle(modeNames[m.mode]) + dimStyle.Render(fmt.Sprintf("  (v cycles)  %d lines", len(m.lines))) + "\n\n")
		avail := h - 3
		for i := m.escroll; i < len(m.lines) && i < m.escroll+avail; i++ {
			eb.WriteString(m.renderLine(i, rightW-2) + "\n")
		}
	}

	lp, rp := paneStyle, paneStyle
	if m.focus == paneTree {
		lp = activePaneStyle
	} else {
		rp = activePaneStyle
	}
	left := lp.Width(leftW).Height(h).MaxHeight(h + 2).Render(strings.TrimRight(tb.String(), "\n"))
	right := rp.Width(rightW).Height(h).MaxHeight(h + 2).Render(strings.TrimRight(eb.String(), "\n"))
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	keys := "j/k move  l open  tab pane  v view  s search  g goto  / find  a add  e edit  d del  m move  y copy  ? help  : cmd"
	if m.loading {
		keys = "loading…  " + keys
	}
	return titleStyle.Render("ldapview — "+m.sh.conf.Name) + "\n" + body + "\n" + dimStyle.Render(truncate(keys, m.width-1))
}

func roleStyle(s string) string { return attrNameStyle.Render(s) }

func (m browserModel) renderLine(i, w int) string {
	l := m.lines[i]
	selected := m.focus == paneEntry && i == m.ecur
	switch {
	case l.head:
		return attrNameStyle.Render(truncate(l.text, w))
	case !l.sel:
		return truncate(l.text, w)
	}
	txt := "  " + l.text
	if l.attr == "" && !l.bin && l.dn == "" && m.mode != modeAttrs {
		txt = l.text
	}
	if l.dn != "" {
		txt = "  " + l.text
	}
	if selected {
		full := txt
		if l.anno != "" {
			full += "  ← " + l.anno
		}
		return selectedStyle.Render(truncate(full, w))
	}
	txt = truncate(txt, w)
	if l.bin {
		txt = binaryTagStyle.Render(txt)
	}
	if l.anno != "" && len([]rune(txt))+4 < w {
		txt += "  " + annoStyle.Render(truncate("← "+l.anno, w-len([]rune(txt))-2))
	}
	return txt
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

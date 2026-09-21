// Package tui implements the ldapview terminal UI using Bubble Tea.
package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zoro/ldapview/internal/ad"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/schema"
	"github.com/zoro/ldapview/internal/store"
)

type screen int

const (
	screenConnections screen = iota
	screenPassword
	screenBrowser
	screenSearch
	screenFilter
	screenSchema
	screenRootDSE
	screenOps
	screenProto
	screenExtOp
	screenHelp
	screenBinary
	screenForm
)

// shared holds mutable state visible to every screen and to overlay
// callbacks (which must not capture stale copies of App).
type shared struct {
	client    *ldapclient.Client
	conf      store.Connection
	schema    *schema.Schema
	isAD      bool
	readOnly  bool
	history   *store.SearchList
	bookmarks *store.SearchList

	schemaLoading  bool
	wantSchemaView *string // query to open once the schema arrives
}

// App is the root Bubble Tea model.
type App struct {
	sh     *shared
	screen screen
	prev   screen
	width  int
	height int

	status    string
	statusErr bool
	store     *store.Store
	ov        overlay

	connections connectionsModel
	pw          passwordPromptModel
	browser     browserModel
	search      searchModel
	filter      filterModel
	schemaV     schemaModel
	rootDSE     rootDSEModel
	ops         opsModel
	proto       protoModel
	extop       extOpDetail
	help        helpModel
	binary      binaryViewModel
	form        formModel
	formKind    string

	initial    *initialTarget
	connecting bool
	spin       int
}

// initialTarget makes the TUI start at the password prompt for a target
// chosen on the command line (`ldapview connect ...`).
type initialTarget struct {
	conn     store.Connection
	password string
	search   *openSearchMsg
}

// WithTarget configures the app to connect to conn on startup. If password
// is non-empty it is used directly (from env/file/stdin — never from argv).
func (a App) WithTarget(conn store.Connection, password, base, filter string) App {
	t := &initialTarget{conn: conn, password: password}
	if base != "" || (filter != "" && filter != "(objectClass=*)") {
		t.search = &openSearchMsg{base: base, filter: filter}
	}
	a.initial = t
	return a
}

// NewApp constructs the initial application model.
func NewApp(s *store.Store) App {
	sh := &shared{}
	sh.history, _ = store.LoadSearchList("history.yaml", 100)
	sh.bookmarks, _ = store.LoadSearchList("bookmarks.yaml", 0)
	if sh.bookmarks != nil && sh.bookmarks.Fresh {
		sh.bookmarks.Items = store.DefaultBookmarks()
		_ = sh.bookmarks.Save()
	}
	a := App{sh: sh, store: s, screen: screenConnections, connections: newConnectionsModel(s), help: newHelpModel()}
	a.browser = newBrowserModel(sh)
	return a
}

func (a App) Init() tea.Cmd {
	if a.initial == nil {
		return tea.Batch(tickCmd())
	}
	t := a.initial
	if t.password != "" || t.conn.BindMethod == store.BindAnonymous || t.conn.BindMethod == "" {
		return tea.Batch(tickCmd(), msgCmd(doConnectMsg{conn: t.conn, password: t.password}))
	}
	return tea.Batch(tickCmd(), msgCmd(connectRequestMsg{conn: t.conn}))
}

func (a App) typing() bool {
	switch a.screen {
	case screenPassword, screenForm:
		return true
	case screenConnections:
		return a.connections.typing()
	case screenSearch:
		return a.search.typing()
	case screenSchema:
		return a.schemaV.typing
	}
	return false
}

func (a *App) resize() {
	a.connections.setSize(a.width, a.height)
	a.browser.setSize(a.width, a.height)
	a.search.setSize(a.width, a.height)
	a.filter.width, a.filter.height = a.width, a.height
	a.schemaV.width, a.schemaV.height = a.width, a.height
	a.rootDSE.height = a.height
	a.form.width, a.form.height = a.width, a.height
}

func (a *App) closeClient() {
	if a.sh.client != nil {
		a.sh.client.Close()
		a.sh.client = nil
	}
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		a.resize()
		return a, nil

	case openOverlayMsg:
		a.ov = m.ov
		return a, nil

	case tea.KeyMsg:
		// Terminals may coalesce fast keystrokes ("jj") into one message;
		// split them unless the focused element is a text input.
		if m.Type == tea.KeyRunes && len(m.Runes) > 1 && !m.Paste && !m.Alt && !a.typing() && !overlayTakesText(a.ov) {
			cmds := make([]tea.Cmd, 0, len(m.Runes))
			for _, r := range m.Runes {
				r := r
				cmds = append(cmds, func() tea.Msg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} })
			}
			return a, tea.Sequence(cmds...)
		}
		if m.String() == "ctrl+c" {
			a.closeClient()
			return a, tea.Quit
		}
		if a.ov != nil {
			ov, cmd := a.ov.update(msg)
			a.ov = ov
			return a, cmd
		}
		if a.screen == screenHelp {
			switch m.String() {
			case "?", "q", "esc":
				a.screen = a.prev
			case "j", "down":
				a.help.scroll++
			case "k", "up":
				a.help.scroll = max(a.help.scroll-1, 0)
			case "pgdown":
				a.help.scroll += 10
			case "pgup":
				a.help.scroll = max(a.help.scroll-10, 0)
			}
			return a, nil
		}
		if !a.typing() {
			switch m.String() {
			case "?":
				a.prev, a.screen = a.screen, screenHelp
				return a, nil
			case ":":
				return a, a.paletteCmd()
			}
		}
		return a.routeKey(msg)

	case statusMsg:
		a.status, a.statusErr = m.text, m.isErr
		return a, nil

	case cmdMsg:
		return a.runCommand(m.line)

	case tickMsg:
		if a.busy() {
			a.spin++
		}
		return a, tickCmd()
	}
	return a.handleMsg(msg)
}

func (a App) routeKey(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch a.screen {
	case screenConnections:
		a.connections, cmd = a.connections.update(msg)
	case screenPassword:
		a.pw, cmd = a.pw.update(msg)
	case screenBrowser:
		a.browser, cmd = a.browser.update(msg)
	case screenSearch:
		a.search, cmd = a.search.update(msg)
	case screenFilter:
		a.filter, cmd = a.filter.update(msg)
	case screenSchema:
		a.schemaV, cmd = a.schemaV.update(msg)
	case screenRootDSE:
		a.rootDSE, cmd = a.rootDSE.update(msg)
	case screenOps:
		a.ops, cmd = a.ops.update(msg)
	case screenProto:
		a.proto, cmd = a.proto.update(msg)
	case screenExtOp:
		a.extop, cmd = a.extop.update(msg)
	case screenBinary:
		a.binary, cmd = a.binary.update(msg)
	case screenForm:
		a.form, cmd = a.form.update(msg)
	}
	return a, cmd
}

func (a App) connected() bool { return a.sh.client != nil }

func (a App) handleMsg(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m := msg.(type) {
	case connectRequestMsg:
		a.pw = newPasswordPromptModel(m.conn, m.test)
		a.screen = screenPassword
		return a, nil
	case cancelPromptMsg:
		a.screen = screenConnections
		return a, nil
	case doConnectMsg:
		a.status, a.statusErr = "connecting to "+m.conn.URL()+"…", false
		a.connecting = true
		return a, connectCmd(m.conn, m.password, m.test)
	case connectResultMsg:
		return a.onConnectResult(m)
	case disconnectMsg:
		a.closeClient()
		a.sh.schema, a.sh.isAD, a.sh.readOnly = nil, false, false
		a.screen = screenConnections
		a.status, a.statusErr = "disconnected", false
		return a, nil

	case backMsg:
		if a.connected() {
			a.screen = screenBrowser
		} else {
			a.screen = screenConnections
		}
		return a, nil
	case openScreenMsg:
		if !a.connected() && m.s != screenHelp {
			return a, statusCmd("not connected", true)
		}
		switch m.s {
		case screenSearch:
			if a.search.sh == nil {
				a.search = newSearchModel(a.sh, "", "")
				a.search.setSize(a.width, a.height)
			}
		case screenOps:
			a.ops = newOpsModel(a.sh)
			a.ops.height = a.height
		case screenProto:
			a.proto = newProtoModel(a.sh)
			a.proto.height = a.height
		case screenHelp:
			a.prev = a.screen
		}
		a.screen = m.s
		return a, nil

	case gotoMsg:
		if !a.connected() {
			return a, statusCmd("not connected", true)
		}
		a.screen = screenBrowser
		a.browser, cmd = a.browser.startGoto(m.dn)
		return a, cmd
	case findMsg:
		a.browser.findQ = m.q
		a.browser, cmd = a.browser.findNext(true)
		return a, cmd
	case openBinaryMsg:
		a.binary = newBinaryViewModel(m.attrName, m.data)
		a.screen = screenBinary
		return a, nil
	case openRootDSEMsg:
		a.rootDSE = newRootDSEModel(a.sh.client.DSE())
		a.rootDSE.height = a.height
		a.screen = screenRootDSE
		return a, nil
	case openSearchMsg:
		if !a.connected() {
			return a, statusCmd("not connected", true)
		}
		a.search = newSearchModel(a.sh, m.base, m.filter)
		a.search.setSize(a.width, a.height)
		a.screen = screenSearch
		return a, nil
	case openFilterMsg:
		a.filter = newFilterModel(m.raw)
		a.filter.width, a.filter.height = a.width, a.height
		a.screen = screenFilter
		return a, nil
	case applyFilterMsg:
		a.search, cmd = a.search.update(m)
		a.screen = screenSearch
		return a, cmd
	case openReferralMsg:
		return a.openReferral(m.url)

	case openSchemaMsg:
		if a.sh.schema != nil {
			a.schemaV = newSchemaModel(a.sh.schema, m.query)
			a.schemaV.width, a.schemaV.height = a.width, a.height
			a.screen = screenSchema
			return a, nil
		}
		q := m.query
		a.sh.wantSchemaView = &q
		return a, tea.Batch(statusCmd("loading schema…", false), a.loadSchemaCmd())
	case needSchemaMsg:
		return a, a.loadSchemaCmd()
	case schemaLoadedMsg:
		a.sh.schemaLoading = false
		if m.err != nil {
			a.sh.wantSchemaView = nil
			return a, statusCmd("schema: "+friendlyErr(m.err), true)
		}
		a.sh.schema = m.s
		a.browser, _ = a.browser.update(m)
		if a.screen == screenForm && a.formKind == "add" {
			rebuildAddFields(&a.form, a.sh)
		}
		var cmds []tea.Cmd
		if a.sh.wantSchemaView != nil {
			a.schemaV = newSchemaModel(m.s, *a.sh.wantSchemaView)
			a.schemaV.width, a.schemaV.height = a.width, a.height
			a.screen = screenSchema
			a.sh.wantSchemaView = nil
		}
		cmds = append(cmds, statusCmd(fmt.Sprintf("schema loaded: %d object classes, %d attribute types", len(m.s.ClassList), len(m.s.AttrList)), false))
		return a, tea.Batch(cmds...)

	case diffMsg:
		b := a.browser
		switch {
		case b.marked == nil:
			return a, statusCmd("no entry marked — press = on an entry first", true)
		case b.entry == nil:
			return a, statusCmd("load a second entry to compare", true)
		case dnEqual(b.marked.DN, b.entry.DN):
			return a, statusCmd("the marked entry is the one loaded — select another", true)
		}
		return a, showMessage("Entry comparison", diffEntries(*b.marked, *b.entry))

	case openExtOpMsg:
		a.extop = newExtOpDetail(m.oid)
		a.screen = screenExtOp
		return a, nil
	case extOpSendMsg:
		return a, sendExtOpCmd(a.sh.client, m.oid)
	case extOpResultMsg:
		a.extop, cmd = a.extop.update(m)
		return a, cmd
	case ldifViewMsg:
		if m.err != nil {
			return a, statusCmd("ldif: "+m.err.Error(), true)
		}
		return a, showMessage("LDIF: "+m.path, ldifReport(m))
	case ldifEditedMsg:
		if m.temp {
			defer os.Remove(m.path)
		}
		if m.err != nil {
			return a, statusCmd("editor failed: "+m.err.Error(), true)
		}
		recs, issues, err := readAndValidate(m.path)
		if err != nil {
			return a, statusCmd("ldif: "+err.Error(), true)
		}
		if len(recs) == 0 {
			return a, statusCmd("nothing to import — the file has no records", false)
		}
		for _, i := range issues {
			if i.Severity == "error" {
				return a, showMessage("LDIF has errors — nothing was sent", ldifReport(ldifViewMsg{path: m.path, recs: recs, issues: issues}))
			}
		}
		return a.handleWrite(importParsedMsg{recs: recs, path: m.path})
	case openFollowReferralMsg:
		return a.followReferral(m.url)
	case secInfoMsg:
		return a, showMessage("Security-oriented visibility", secInfoLines(m))
	case referralConnectedMsg:
		return a.onReferralConnected(m)

	// data for the browser
	case rootsLoadedMsg, childrenLoadedMsg, entryLoadedMsg, relLoadedMsg, sdLoadedMsg:
		a.browser, cmd = a.browser.update(msg)
		return a, cmd
	case opDoneMsg:
		a.browser, cmd = a.browser.update(msg)
		if m.err != nil {
			what := m.failDesc
			if what == "" {
				what = m.desc
			}
			return a, tea.Batch(cmd, statusCmd(what+" failed: "+friendlyErr(m.err)+"  (L: raw result)", true))
		}
		return a, tea.Batch(cmd, statusCmd(m.desc, false))

	// search screen
	case runSearchMsg, searchDoneMsg, applyPresetMsg, applySavedMsg, saveBookmarkMsg, quickFilterMsg, exportResultsMsg, copyAttrMsg:
		a.search, cmd = a.search.update(msg)
		return a, cmd

	// filter builder
	case addCondMsg, editCondMsg, setRawFilterMsg:
		a.filter, cmd = a.filter.update(msg)
		return a, cmd

	case connFormDoneMsg, deleteConnMsg:
		a.connections, cmd = a.connections.update(msg)
		return a, cmd

	case formCancelMsg:
		switch a.screen {
		case screenForm:
			a.screen = screenBrowser
		case screenConnections:
			a.connections, cmd = a.connections.update(msg)
		case screenSearch:
			a.search, cmd = a.search.update(msg)
		}
		return a, cmd

	// write requests and confirmed operations
	case editValueMsg, addValueMsg, delValueMsg, deleteEntryMsg, addEntryMsg, modDNMsg, exportEntryMsg,
		doModifyMsg, doAddMsg, doDeleteMsg, doModDNMsg, importDoneMsg, importParsedMsg, doImportMsg, pickClassesMsg:
		return a.handleWrite(msg)
	}
	return a, nil
}

func connectCmd(conf store.Connection, password string, test bool) tea.Cmd {
	return func() tea.Msg {
		c, err := ldapclient.Connect(conf)
		if err != nil {
			return connectResultMsg{err: err, conn: conf, test: test}
		}
		var warns []string
		if _, derr := c.FetchRootDSE(); derr == nil && conf.BindMethod == store.BindSASL && !c.AdvertisedSASL(conf.SASLMech) {
			warns = append(warns, fmt.Sprintf("server does not advertise SASL mechanism %s", conf.SASLMech))
		}
		if err := c.Bind(password); err != nil {
			c.Close()
			return connectResultMsg{err: err, conn: conf, test: test}
		}
		if _, derr := c.FetchRootDSE(); derr != nil && c.DSE() == nil {
			warns = append(warns, "Root DSE unreadable: "+friendlyErr(derr))
		}
		return connectResultMsg{client: c, conn: conf, test: test, warns: warns}
	}
}

// onReferralConnected switches the active session to a followed referral
// target. The previous connection is closed; the person can reconnect to
// it again from Connections at any time.
func (a App) onReferralConnected(m referralConnectedMsg) (tea.Model, tea.Cmd) {
	a.closeClient()
	a.sh.client, a.sh.conf = m.client, m.conn
	a.sh.readOnly = true // referral targets are followed read-only by default
	a.sh.schema, a.sh.isAD = nil, false
	if d := m.client.DSE(); d != nil {
		a.sh.isAD = ad.IsAD(d.SupportedCapabilities, d.ConfigurationNamingContext)
	}
	a.browser = newBrowserModel(a.sh)
	a.browser.setSize(a.width, a.height)
	a.search = newSearchModel(a.sh, m.base, m.filter)
	a.search.setSize(a.width, a.height)
	if v := m.scope; v == "one" || v == "sub" || v == "base" {
		setChoice(&a.search.form.fields[sfScope], v)
	}
	a.screen = screenSearch
	a.status, a.statusErr = fmt.Sprintf("followed referral to %s (read-only, anonymous) — press enter to search", m.conn.URL()), false
	return a, a.browser.loadRootCmd()
}

func (a App) onConnectResult(m connectResultMsg) (tea.Model, tea.Cmd) {
	a.connecting = false
	if m.err != nil {
		a.screen = screenConnections
		text := "connect failed: " + friendlyErr(m.err)
		if strings.Contains(m.err.Error(), "certificate") || strings.Contains(m.err.Error(), "x509") {
			text += "  — set a CA file in the connection profile (skipping verification is unsafe)"
		}
		a.status, a.statusErr = text, true
		return a, nil
	}
	if m.test {
		lines := a.testLines(m)
		m.client.Close()
		a.screen = screenConnections
		a.status, a.statusErr = "connection test OK: "+m.conn.Name, false
		return a, showMessage("Connection test: "+m.conn.Name, lines)
	}
	a.closeClient()
	a.sh.client, a.sh.conf = m.client, m.conn
	a.sh.readOnly = m.conn.ReadOnly
	a.sh.schema = nil
	a.sh.isAD = false
	if d := m.client.DSE(); d != nil {
		a.sh.isAD = ad.IsAD(d.SupportedCapabilities, d.ConfigurationNamingContext)
	}
	a.browser = newBrowserModel(a.sh)
	a.browser.setSize(a.width, a.height)
	a.search = searchModel{}
	a.screen = screenBrowser
	a.status, a.statusErr = "connected to "+m.conn.URL(), false
	if len(m.warns) > 0 {
		a.status, a.statusErr = "connected — warning: "+strings.Join(m.warns, "; "), true
	}
	cmds := []tea.Cmd{a.browser.loadRootCmd()}
	if a.initial != nil && a.initial.search != nil {
		cmds = append(cmds, msgCmd(*a.initial.search))
		a.initial.search = nil
	}
	return a, tea.Batch(cmds...)
}

func (a App) testLines(m connectResultMsg) []string {
	c := m.client
	lines := []string{"Server:  " + m.conn.URL(), "Bind:    " + string(m.conn.BindMethod) + " — OK"}
	lines = append(lines, tlsLines(c)...)
	if d := c.DSE(); d != nil {
		if d.VendorName != "" || d.VendorVersion != "" {
			lines = append(lines, "Vendor:  "+strings.TrimSpace(d.VendorName+" "+d.VendorVersion))
		}
		lines = append(lines, "LDAP:    version "+strings.Join(d.SupportedLDAPVersion, ", "))
		lines = append(lines, "Naming contexts: "+strings.Join(d.NamingContexts, ", "))
		if ad.IsAD(d.SupportedCapabilities, d.ConfigurationNamingContext) {
			lines = append(lines, "Type:    Active Directory")
		}
		lines = append(lines, fmt.Sprintf("Controls: %d   Extensions: %d", len(d.SupportedControl), len(d.SupportedExtension)))
	}
	for _, w := range m.warns {
		lines = append(lines, "", "WARNING: "+w)
	}
	return lines
}

func tlsLines(c *ldapclient.Client) []string {
	t := c.TLS()
	if t == nil {
		return []string{"TLS:     none — traffic (including simple-bind passwords) is unencrypted"}
	}
	mode := "LDAPS"
	if t.StartTLS {
		mode = "StartTLS"
	}
	ver := "verified against trusted roots"
	if !t.Verified {
		ver = "NOT VERIFIED (verification disabled)"
	}
	lines := []string{
		fmt.Sprintf("TLS:     %s, %s, %s", mode, t.Version, t.Cipher),
		"Cert:    " + ver,
	}
	if t.Subject != "" {
		lines = append(lines, "Subject: "+t.Subject, "Issuer:  "+t.Issuer)
		if len(t.DNSNames) > 0 {
			lines = append(lines, "SANs:    "+strings.Join(t.DNSNames, ", "))
		}
		lines = append(lines, "Valid:   "+t.NotBefore.Format("2006-01-02")+" → "+t.NotAfter.Format("2006-01-02"))
	}
	return lines
}

func (a App) loadSchemaCmd() tea.Cmd {
	if a.sh.schemaLoading || a.sh.client == nil {
		return nil
	}
	a.sh.schemaLoading = true
	c := a.sh.client
	return func() tea.Msg {
		s, err := c.Schema()
		return schemaLoadedMsg{s: s, err: err}
	}
}

// ---- view ----

func fitLines(s string, n int) string {
	if n < 1 {
		n = 1
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	for len(lines) < n {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (a App) screenView() string {
	w, h := a.width, a.height
	switch a.screen {
	case screenConnections:
		return a.connections.view()
	case screenPassword:
		return a.pw.view()
	case screenBrowser:
		return a.browser.view()
	case screenSearch:
		return a.search.view()
	case screenFilter:
		return a.filter.view()
	case screenSchema:
		return a.schemaV.view(w, h)
	case screenRootDSE:
		return a.rootDSE.view(w, h)
	case screenOps:
		return a.ops.view(w, h)
	case screenProto:
		return a.proto.view(w, h)
	case screenExtOp:
		return a.extop.view(w, h)
	case screenHelp:
		return a.help.view(w, h)
	case screenBinary:
		return a.binary.view(w, h)
	case screenForm:
		return a.form.view()
	}
	return ""
}

func (a App) View() string {
	h := a.height
	if h <= 0 {
		h = 30
	}
	if a.ov != nil && !a.ov.inline() {
		return fitLines(a.ov.view(a.width, h-1), h-1) + "\n" + a.statusBar()
	}
	body := a.screenView()
	if a.ov != nil {
		pv := a.ov.view(a.width, h)
		n := strings.Count(pv, "\n") + 1
		return fitLines(body, h-1-n) + "\n" + pv + "\n" + a.statusBar()
	}
	return fitLines(body, h-1) + "\n" + a.statusBar()
}

func (a App) statusBar() string {
	w := a.width
	if w <= 0 {
		w = 80
	}
	badge, left := "", " ldapview"
	if c := a.sh.client; c != nil {
		if a.sh.readOnly {
			badge = roBadgeStyle.Render("RO")
		} else {
			badge = rwBadgeStyle.Render("RW")
		}
		sec := "PLAINTEXT"
		if t := c.TLS(); t != nil {
			sec = t.Version
			if !t.Verified {
				sec += " (unverified)"
			}
		}
		bind := string(a.sh.conf.BindMethod)
		if bind == "" {
			bind = "anonymous"
		}
		left = fmt.Sprintf(" %s · %s · %s", a.sh.conf.Name, sec, bind)
		if a.sh.isAD {
			left += " · AD"
		}
	}
	msg := a.status
	if msg == "" {
		msg = "? help  : commands"
	}
	msg = a.spinner() + msg
	style := statusBarStyle
	if a.statusErr {
		style = statusBarErrStyle
	}
	rest := left + "  │  " + msg
	avail := w - lipgloss.Width(badge)
	rest = truncate(rest, avail)
	if pad := avail - len([]rune(rest)); pad > 0 {
		rest += strings.Repeat(" ", pad)
	}
	return badge + style.Render(rest)
}

func overlayTakesText(o overlay) bool {
	switch o.(type) {
	case *promptOverlay, *pickerOverlay:
		return true
	}
	return false
}

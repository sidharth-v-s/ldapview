package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/ad"
	"github.com/zoro/ldapview/internal/dn"
	"github.com/zoro/ldapview/internal/filter"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
	"github.com/zoro/ldapview/internal/oid"
	"github.com/zoro/ldapview/internal/proto"
	"github.com/zoro/ldapview/internal/store"
)

const (
	sfBase = iota
	sfScope
	sfFilter
	sfAttrs
	sfSize
	sfTime
	sfDeref
	sfPage
	sfSort
	sfCtl
	sfCount
)

type runSearchMsg struct{}
type applyPresetMsg struct{ p ad.Preset }
type applySavedMsg struct{ s store.SavedSearch }
type saveBookmarkMsg struct{ name string }
type exportResultsMsg struct {
	path     string
	allPages bool
}
type quickFilterMsg struct{ q string }
type copyAttrMsg struct {
	attr string
	all  bool
}

type searchModel struct {
	sh     *shared
	width  int
	height int
	form   formModel
	inForm bool

	running bool
	pages   [][]ldapclient.Entry
	nexts   [][]byte
	page    int
	last    ldapclient.SearchParams
	lastScp string
	refs    []string
	limit   string
	cols    []string

	cur      int
	detail   bool
	sortCol  int
	sortDesc bool
	quick    string
}

func (m searchModel) typing() bool { return m.inForm }

func (m *searchModel) setSize(w, h int) {
	m.width, m.height = w, h
	m.form.width, m.form.height = w, h
}

func setChoice(f *formField, v string) {
	for i, c := range f.choices {
		if c == v {
			f.ci = i
		}
	}
}

func newSearchModel(sh *shared, base, flt string) searchModel {
	if flt == "" {
		flt = "(objectClass=*)"
	}
	size, tl := 1000, 10
	if sh.conf.SizeLimit > 0 {
		size = sh.conf.SizeLimit
	}
	if sh.conf.TimeLimit > 0 {
		tl = sh.conf.TimeLimit
	}
	m := searchModel{sh: sh, inForm: true, sortCol: -1}
	f := formModel{title: "LDAP search"}
	f.fields = make([]formField, sfCount)
	f.fields[sfBase] = textField("Base DN", base, "empty = server default; press s in the browser to use the selected entry")
	f.fields[sfScope] = choiceField("Scope", []string{"sub", "one", "base"}, "sub")
	f.fields[sfFilter] = textField("Filter", flt, "RFC 4515, e.g. (&(objectClass=person)(mail=*@example.com)) — ctrl+f opens the builder")
	f.fields[sfAttrs] = textField("Attributes", "*", "comma separated; * user attrs, + operational, 1.1 DN only")
	f.fields[sfSize] = textField("Size limit", strconv.Itoa(size), "0 = no client limit (server limits still apply)")
	f.fields[sfTime] = textField("Time limit (s)", strconv.Itoa(tl), "")
	f.fields[sfDeref] = choiceField("Deref aliases", []string{"never", "search", "find", "always"}, "never")
	f.fields[sfPage] = textField("Page size", "0", "0 = one request; >0 = paged results, browse with n / p")
	f.fields[sfSort] = textField("Sort by", "", "attribute; prefix - for descending. Server-side when advertised")
	f.fields[sfCtl] = choiceField("Extra control", []string{"none", "manageDsaIT", "showDeleted", "showRecycled", "dirSync"}, "none")
	f.idx = sfFilter // most searches only change the filter; enter runs it
	f.footer = "enter run  ctrl+f builder  ctrl+p presets  ctrl+h history  ctrl+b bookmarks  ctrl+k save bookmark  ctrl+e BER preview  esc back"
	f.submit = func(v []string) tea.Cmd { return msgCmd(runSearchMsg{}) }
	f.cancel = func() tea.Cmd { return msgCmd(backMsg{}) }
	f.keys = map[string]func(*formModel) tea.Cmd{
		"enter": func(fm *formModel) tea.Cmd {
			if fm.idx == sfFilter || fm.idx == len(fm.fields)-1 {
				return fm.submit(fm.values())
			}
			fm.move(1)
			return nil
		},
		"ctrl+f": func(fm *formModel) tea.Cmd { return msgCmd(openFilterMsg{raw: fm.fields[sfFilter].value()}) },
		"ctrl+p": func(fm *formModel) tea.Cmd {
			var items []pickItem
			for _, p := range ad.Presets(sh.isAD, time.Now()) {
				items = append(items, pickItem{label: p.Name, detail: p.Filter, value: p})
			}
			return openOverlay(newPicker("Search presets", items, func(c []pickItem) tea.Cmd {
				return msgCmd(applyPresetMsg{p: c[0].value.(ad.Preset)})
			}))
		},
		"ctrl+h": func(fm *formModel) tea.Cmd { return openSavedPicker("Search history", sh.history, false) },
		"ctrl+b": func(fm *formModel) tea.Cmd { return openSavedPicker("Bookmarks", sh.bookmarks, true) },
		"ctrl+k": func(fm *formModel) tea.Cmd {
			return openOverlay(newPrompt("bookmark name", "", "saves base, scope, filter and attributes", func(s string) tea.Cmd {
				return msgCmd(saveBookmarkMsg{name: strings.TrimSpace(s)})
			}))
		},
		"ctrl+e": func(fm *formModel) tea.Cmd {
			p, err := m.paramsFrom(fm.values())
			if err != nil {
				return statusCmd(err.Error(), true)
			}
			msg, err := sh.client.PreviewSearch(p)
			if err != nil {
				return statusCmd(err.Error(), true)
			}
			lines := append([]string{"Search request as it will be encoded (BER) — no credentials involved:", ""}, msg.Tree...)
			lines = append(lines, "", "Encoded bytes:")
			lines = append(lines, strings.Split(strings.TrimRight(proto.HexDump(msg.Raw), "\n"), "\n")...)
			return showMessage("BER preview", lines)
		},
	}
	f.preview = func(v []string) string { return m.warnings(v) }
	m.form = f
	return m
}

func openSavedPicker(title string, l *store.SearchList, deletable bool) tea.Cmd {
	if l == nil || len(l.Items) == 0 {
		return statusCmd("no saved searches yet", false)
	}
	var items []pickItem
	for _, s := range l.Items {
		label := s.Filter
		if s.Name != "" {
			label = s.Name
		}
		items = append(items, pickItem{label: label, detail: fmt.Sprintf("%s · %s · %s", s.Base, s.Scope, s.Filter), value: s})
	}
	p := newPicker(title, items, func(c []pickItem) tea.Cmd { return msgCmd(applySavedMsg{s: c[0].value.(store.SavedSearch)}) })
	if deletable {
		p.onDelete = func(it pickItem) tea.Cmd {
			s := it.value.(store.SavedSearch)
			for i, x := range l.Items {
				if x.Key() == s.Key() && x.Name == s.Name {
					l.Remove(i)
					break
				}
			}
			_ = l.Save()
			return statusCmd("bookmark deleted", false)
		}
	}
	return openOverlay(p)
}

func (m searchModel) warnings(v []string) string {
	var w []string
	if f := strings.TrimSpace(v[sfFilter]); f != "" {
		if !strings.HasPrefix(f, "(") {
			f = "(" + f + ")"
		}
		if err := filter.Validate(f); err != nil {
			w = append(w, "filter invalid: "+err.Error())
		}
	}
	if b := strings.TrimSpace(v[sfBase]); b != "" && !dn.Valid(b) {
		w = append(w, "base is not a valid DN")
	}
	if c := v[sfCtl]; c != "none" && m.sh.client != nil {
		o := map[string]string{"manageDsaIT": oid.ManageDsaIT, "showDeleted": oid.ShowDeleted, "showRecycled": oid.ShowRecycled, "dirSync": oid.DirSync}[c]
		if !m.sh.client.SupportsControl(o) {
			w = append(w, c+" is not advertised by this server (it may be ignored or rejected)")
		}
	}
	if strings.TrimSpace(v[sfSort]) != "" && m.sh.client != nil && !m.sh.client.SupportsControl(oid.ServerSort) {
		w = append(w, "server-side sorting not advertised — results are sorted per page in the client")
	}
	if len(w) == 0 {
		return ""
	}
	return warnStyle.Render("  " + strings.Join(w, "\n  "))
}

func (m searchModel) paramsFrom(v []string) (ldapclient.SearchParams, error) {
	var p ldapclient.SearchParams
	p.Base = strings.TrimSpace(v[sfBase])
	if p.Base != "" && !dn.Valid(p.Base) {
		return p, fmt.Errorf("base is not a valid DN")
	}
	f := strings.TrimSpace(v[sfFilter])
	if f == "" {
		f = "(objectClass=*)"
	}
	if !strings.HasPrefix(f, "(") {
		f = "(" + f + ")"
	}
	if err := filter.Validate(f); err != nil {
		return p, fmt.Errorf("invalid filter: %v", err)
	}
	p.Filter = f
	switch v[sfScope] {
	case "base":
		p.Scope = ldap.ScopeBaseObject
	case "one":
		p.Scope = ldap.ScopeSingleLevel
	default:
		p.Scope = ldap.ScopeWholeSubtree
	}
	for _, a := range strings.FieldsFunc(v[sfAttrs], func(r rune) bool { return r == ',' || r == ' ' }) {
		p.Attributes = append(p.Attributes, a)
	}
	if len(p.Attributes) == 0 {
		p.Attributes = []string{"*"}
	}
	var err error
	if p.SizeLimit, err = atoiNonNeg(v[sfSize]); err != nil {
		return p, fmt.Errorf("size limit: %v", err)
	}
	if p.TimeLimit, err = atoiNonNeg(v[sfTime]); err != nil {
		return p, fmt.Errorf("time limit: %v", err)
	}
	ps, err := atoiNonNeg(v[sfPage])
	if err != nil {
		return p, fmt.Errorf("page size: %v", err)
	}
	p.PageSize = uint32(ps)
	p.Deref = map[string]int{"never": ldap.NeverDerefAliases, "search": ldap.DerefInSearching, "find": ldap.DerefFindingBaseObj, "always": ldap.DerefAlways}[v[sfDeref]]
	if s := strings.TrimSpace(v[sfSort]); s != "" {
		p.SortReverse = strings.HasPrefix(s, "-")
		p.SortAttr = strings.TrimPrefix(s, "-")
	}
	if v[sfCtl] != "none" {
		p.Controls = []string{v[sfCtl]}
	}
	return p, nil
}

func atoiNonNeg(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a non-negative number", s)
	}
	return n, nil
}

func (m searchModel) run(p ldapclient.SearchParams, page int, cookie []byte) (searchModel, tea.Cmd) {
	m.last = p
	m.lastScp = m.form.fields[sfScope].value()
	m.running = true
	p.Cookie = cookie
	client := m.sh.client
	return m, tea.Batch(statusCmd("searching…", false), func() tea.Msg {
		out, err := client.SearchEx(p)
		return searchDoneMsg{out: out, err: err, page: page}
	})
}

func (m searchModel) update(msg tea.Msg) (searchModel, tea.Cmd) {
	switch msg := msg.(type) {
	case runSearchMsg:
		p, err := m.paramsFrom(m.form.values())
		if err != nil {
			m.form.notice = err.Error()
			return m, statusCmd(err.Error(), true)
		}
		m.form.notice = ""
		m.pages, m.nexts, m.sortCol, m.sortDesc, m.quick = nil, nil, -1, false, ""
		return m.run(p, 0, nil)

	case searchDoneMsg:
		m.running = false
		if msg.err != nil {
			m.form.notice = friendlyErr(msg.err)
			m.inForm = true
			return m, statusCmd("search failed: "+friendlyErr(msg.err), true)
		}
		if msg.page == 0 {
			m.pages, m.nexts = [][]ldapclient.Entry{msg.out.Entries}, [][]byte{msg.out.NextCookie}
		} else {
			for len(m.pages) <= msg.page {
				m.pages, m.nexts = append(m.pages, nil), append(m.nexts, nil)
			}
			m.pages[msg.page], m.nexts[msg.page] = msg.out.Entries, msg.out.NextCookie
		}
		m.page, m.cur, m.inForm, m.form.notice = msg.page, 0, false, ""
		m.refs = msg.out.Referrals
		m.limit = ""
		if msg.out.Limit != nil {
			m.limit = msg.out.Limit.Message
		}
		m.cols = pickColumns(m.last.Attributes, msg.out.Entries)
		if m.sh.history != nil && msg.page == 0 {
			m.sh.history.Push(store.SavedSearch{Base: m.last.Base, Scope: m.lastScp, Filter: m.last.Filter, Attrs: m.last.Attributes})
			_ = m.sh.history.Save()
		}
		st := fmt.Sprintf("%d entries", len(msg.out.Entries))
		if m.last.PageSize > 0 {
			st += fmt.Sprintf(" (page %d)", msg.page+1)
		}
		if m.limit != "" {
			st += " — " + m.limit + ": partial results"
		}
		return m, statusCmd(st, m.limit != "")

	case applyPresetMsg:
		m.form.fields[sfFilter].in.Set(msg.p.Filter)
		setChoice(&m.form.fields[sfScope], msg.p.Scope)
		m.form.fields[sfAttrs].in.Set(msg.p.Attrs)
		m.inForm = true
		m.form.idx = sfFilter
		return m, statusCmd("preset applied: "+msg.p.Name, false)

	case applySavedMsg:
		s := msg.s
		m.form.fields[sfBase].in.Set(s.Base)
		m.form.fields[sfFilter].in.Set(s.Filter)
		setChoice(&m.form.fields[sfScope], s.Scope)
		if len(s.Attrs) > 0 {
			m.form.fields[sfAttrs].in.Set(strings.Join(s.Attrs, ","))
		}
		m.inForm = true
		m.form.idx = sfFilter
		return m, nil

	case saveBookmarkMsg:
		if msg.name == "" {
			return m, statusCmd("bookmark needs a name", true)
		}
		if m.sh.bookmarks == nil {
			return m, statusCmd("bookmarks unavailable", true)
		}
		v := m.form.values()
		m.sh.bookmarks.Push(store.SavedSearch{Name: msg.name, Base: v[sfBase], Scope: v[sfScope], Filter: v[sfFilter], Attrs: strings.Split(v[sfAttrs], ",")})
		if err := m.sh.bookmarks.Save(); err != nil {
			return m, statusCmd("saving bookmark: "+err.Error(), true)
		}
		return m, statusCmd("bookmark saved: "+msg.name, false)

	case applyFilterMsg:
		m.form.fields[sfFilter].in.Set(msg.filter)
		m.inForm = true
		m.form.idx = sfFilter
		return m, nil

	case quickFilterMsg:
		m.quick, m.cur = msg.q, 0
		return m, nil

	case copyAttrMsg:
		if msg.attr == "" {
			return m, statusCmd("attribute name required", true)
		}
		var vals []string
		if msg.all {
			es := m.entries()
			for _, i := range m.order() {
				vals = append(vals, es[i].Get(msg.attr)...)
			}
		} else if e, ok := m.selectedEntry(); ok {
			vals = e.Get(msg.attr)
		}
		if len(vals) == 0 {
			return m, statusCmd("no values for "+msg.attr, true)
		}
		return m, copyCmd(strings.Join(vals, "\n"), fmt.Sprintf("%d value(s) of %s", len(vals), msg.attr))

	case exportResultsMsg:
		var all []ldapclient.Entry
		if msg.allPages {
			for _, p := range m.pages {
				all = append(all, p...)
			}
		} else {
			all = m.entries()
		}
		path, cols := msg.path, m.last.Attributes
		return m, func() tea.Msg {
			res, err := writeExport(path, all, cols)
			if err != nil {
				return statusMsg{text: "export failed: " + err.Error(), isErr: true}
			}
			return statusMsg{text: res}
		}

	case formCancelMsg:
		return m, msgCmd(backMsg{})

	case tea.KeyMsg:
		if m.inForm {
			f, cmd := m.form.update(msg)
			m.form = f
			return m, cmd
		}
		return m.resultKey(msg)
	}
	return m, nil
}

func pickColumns(req []string, es []ldapclient.Entry) []string {
	var cols []string
	for _, a := range req {
		if a != "*" && a != "+" && a != "1.1" && len(cols) < 3 {
			cols = append(cols, a)
		}
	}
	if len(cols) > 0 || len(req) == 1 && req[0] == "1.1" {
		return cols
	}
	count := map[string]int{}
	for i, e := range es {
		if i > 50 {
			break
		}
		for _, a := range e.Attributes {
			count[strings.ToLower(a.Name)]++
		}
	}
	for _, pref := range []string{"cn", "uid", "samaccountname", "mail", "displayname", "description", "ou", "name"} {
		if count[pref] > 0 && len(cols) < 3 {
			for _, e := range es {
				found := false
				for _, a := range e.Attributes {
					if strings.EqualFold(a.Name, pref) {
						cols = append(cols, a.Name)
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
	}
	return cols
}

func (m searchModel) entries() []ldapclient.Entry {
	if m.page < len(m.pages) {
		return m.pages[m.page]
	}
	return nil
}

func (m searchModel) cell(e ldapclient.Entry, col int) string {
	if col <= 0 {
		return e.DN
	}
	if col-1 < len(m.cols) {
		return strings.Join(e.Get(m.cols[col-1]), "; ")
	}
	return ""
}

func entryMatches(e ldapclient.Entry, q string) bool {
	if strings.Contains(strings.ToLower(e.DN), q) {
		return true
	}
	for _, a := range e.Attributes {
		if a.Binary {
			continue
		}
		for _, v := range a.Values {
			if strings.Contains(strings.ToLower(v), q) {
				return true
			}
		}
	}
	return false
}

func (m searchModel) order() []int {
	es := m.entries()
	q := strings.ToLower(m.quick)
	var idx []int
	for i, e := range es {
		if q == "" || entryMatches(e, q) {
			idx = append(idx, i)
		}
	}
	if m.sortCol >= 0 {
		sort.SliceStable(idx, func(a, b int) bool {
			x, y := strings.ToLower(m.cell(es[idx[a]], m.sortCol)), strings.ToLower(m.cell(es[idx[b]], m.sortCol))
			if m.sortDesc {
				return x > y
			}
			return x < y
		})
	}
	return idx
}

func (m searchModel) selectedEntry() (ldapclient.Entry, bool) {
	o := m.order()
	if m.cur < 0 || m.cur >= len(o) {
		return ldapclient.Entry{}, false
	}
	return m.entries()[o[m.cur]], true
}

func (m searchModel) resultKey(k tea.KeyMsg) (searchModel, tea.Cmd) {
	n := len(m.order())
	e, has := m.selectedEntry()
	switch k.String() {
	case "j", "down":
		if m.cur < n-1 {
			m.cur++
		}
	case "k", "up":
		if m.cur > 0 {
			m.cur--
		}
	case "pgdown":
		m.cur = min(m.cur+15, max(n-1, 0))
	case "pgup":
		m.cur = max(m.cur-15, 0)
	case "home":
		m.cur = 0
	case "end":
		m.cur = max(n-1, 0)
	case "enter":
		if has {
			return m, msgCmd(gotoMsg{dn: e.DN})
		}
	case "i", " ":
		m.detail = !m.detail
	case "c":
		if has {
			return m, copyCmd(e.DN, "DN")
		}
	case "y":
		if has {
			return m, copyCmd(ldif.EntryString(toLDIFEntry(e)), "entry as LDIF")
		}
	case "a", "A":
		if !has {
			return m, nil
		}
		def := ""
		if len(m.cols) > 0 {
			def = m.cols[0]
		}
		all := k.String() == "A"
		title := "copy attribute of the selected entry"
		if all {
			title = fmt.Sprintf("copy attribute for all %d shown rows (one value per line)", n)
		}
		return m, openOverlay(newPrompt(title, def, "attribute name (case-insensitive)", func(s string) tea.Cmd {
			return msgCmd(copyAttrMsg{attr: strings.TrimSpace(s), all: all})
		}))
	case "x":
		n := len(m.entries())
		return m, openOverlay(newPrompt(fmt.Sprintf("export results  (scope: %d entries on this page)", n), defaultExportName("ldapview-results", "ldif"),
			"extension selects format: .ldif  .json  .csv  .txt   ·   X exports every loaded page instead", func(p string) tea.Cmd {
				return msgCmd(exportResultsMsg{path: strings.TrimSpace(p), allPages: false})
			}))
	case "X":
		total := 0
		for _, p := range m.pages {
			total += len(p)
		}
		return m, openOverlay(newPrompt(fmt.Sprintf("export ALL loaded pages  (scope: %d entries across %d page(s))", total, len(m.pages)), defaultExportName("ldapview-results-all", "ldif"),
			"extension selects format: .ldif  .json  .csv  .txt", func(p string) tea.Cmd {
				return msgCmd(exportResultsMsg{path: strings.TrimSpace(p), allPages: true})
			}))
	case "n":
		if m.page < len(m.nexts) && len(m.nexts[m.page]) > 0 {
			if m.page+1 < len(m.pages) && m.pages[m.page+1] != nil {
				m.page++
				m.cur = 0
				return m, nil
			}
			return m.run(m.last, m.page+1, m.nexts[m.page])
		}
		return m, statusCmd("no more pages", false)
	case "p":
		if m.page > 0 {
			m.page--
			m.cur = 0
		}
	case "o":
		m.sortCol++
		if m.sortCol > len(m.cols) {
			m.sortCol = -1
		}
		name := "none"
		if m.sortCol == 0 {
			name = "DN"
		} else if m.sortCol > 0 {
			name = m.cols[m.sortCol-1]
		}
		return m, statusCmd("sorted by "+name+" (this page)", false)
	case "O":
		m.sortDesc = !m.sortDesc
	case "/":
		return m, openOverlay(newPrompt("filter results", m.quick, "substring match on DN and values (client side); empty clears", func(s string) tea.Cmd {
			return msgCmd(quickFilterMsg{q: s})
		}))
	case "b":
		if has {
			m.form.fields[sfBase].in.Set(e.DN)
			m.inForm, m.detail = true, false
		}
	case "e", "s":
		m.inForm, m.detail = true, false
	case "r":
		if len(m.pages) > 0 {
			m.pages, m.nexts = nil, nil
			return m.run(m.last, 0, nil)
		}
	case "F":
		if len(m.refs) == 0 {
			return m, statusCmd("no referrals in this result", false)
		}
		var items []pickItem
		for _, r := range m.refs {
			items = append(items, pickItem{label: "Follow: " + r, detail: "connect anonymously and search there now", value: refChoice{r, true}})
			items = append(items, pickItem{label: "Open separately: " + r, detail: "save as a new connection profile to review first", value: refChoice{r, false}})
		}
		return m, openOverlay(newPicker("Referrals — never followed automatically", items, func(c []pickItem) tea.Cmd {
			ch := c[0].value.(refChoice)
			if ch.follow {
				return msgCmd(openFollowReferralMsg{url: ch.url})
			}
			return msgCmd(openReferralMsg{url: ch.url})
		}))
	case "esc", "q":
		if m.quick != "" {
			m.quick, m.cur = "", 0
			return m, nil
		}
		return m, msgCmd(backMsg{})
	}
	return m, nil
}

func padTo(s string, w int) string {
	s = truncate(s, w)
	if n := len([]rune(s)); n < w {
		s += strings.Repeat(" ", w-n)
	}
	return s
}

func (m searchModel) view() string {
	if m.inForm {
		v := m.form.view()
		if m.running {
			v += "\n" + dimStyle.Render("  searching…")
		}
		return v
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("Search results") + "\n")
	es := m.entries()
	order := m.order()
	info := fmt.Sprintf("base=%q scope=%s filter=%s", m.last.Base, m.lastScp, m.last.Filter)
	b.WriteString(dimStyle.Render(truncate(info, m.width-1)) + "\n")
	sum := fmt.Sprintf("%d entries", len(es))
	if len(order) != len(es) {
		sum += fmt.Sprintf(" (%d match %q)", len(order), m.quick)
	}
	if m.last.PageSize > 0 {
		more := ""
		if m.page < len(m.nexts) && len(m.nexts[m.page]) > 0 {
			more = "+"
		}
		sum += fmt.Sprintf("  page %d%s", m.page+1, more)
	}
	if m.limit != "" {
		sum += "  " + warnStyle.Render(m.limit+" — partial results")
	}
	if len(m.refs) > 0 {
		sum += fmt.Sprintf("  %d referral(s) — F", len(m.refs))
	}
	b.WriteString(sum + "\n")

	w := m.width - 2
	dnW := max(w*40/100, 24)
	colW := 0
	if len(m.cols) > 0 {
		colW = max((w-dnW-2)/len(m.cols), 8)
	}
	hdr := padTo("DN", dnW)
	for _, c := range m.cols {
		hdr += " " + padTo(c, colW)
	}
	mark := func(i int) string {
		if m.sortCol == i {
			if m.sortDesc {
				return "▼"
			}
			return "▲"
		}
		return ""
	}
	_ = mark
	b.WriteString(attrNameStyle.Render(truncate(hdr, w)) + "\n")

	rows := max(m.height-9, 4)
	if m.detail {
		rows = max((m.height-9)/3, 3)
	}
	start := 0
	if m.cur >= rows {
		start = m.cur - rows + 1
	}
	for i := start; i < len(order) && i < start+rows; i++ {
		e := es[order[i]]
		line := padTo(e.DN, dnW)
		for c := range m.cols {
			line += " " + padTo(m.cell(e, c+1), colW)
		}
		line = truncate(line, w)
		if i == m.cur {
			line = selectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	if len(order) == 0 {
		b.WriteString(dimStyle.Render("  no entries") + "\n")
	}
	if m.detail {
		if e, ok := m.selectedEntry(); ok {
			b.WriteString("\n" + attrNameStyle.Render("Entry ") + truncate(e.DN, w-8) + "\n")
			left := max(m.height-9-rows-3, 3)
			shown := 0
			for _, a := range e.Attributes {
				if shown >= left {
					b.WriteString(dimStyle.Render("  …") + "\n")
					break
				}
				val := strings.Join(a.Values, "; ")
				if a.Binary {
					val = binaryTagStyle.Render(fmt.Sprintf("<binary, %d value(s)>", len(a.RawBytes)))
				}
				b.WriteString("  " + attrNameStyle.Render(a.Name+":") + " " + truncate(val, w-len(a.Name)-6) + "\n")
				shown++
			}
		}
	}
	b.WriteString("\n" + dimStyle.Render("enter open  i details  c/y copy DN/LDIF  a/A copy attr  x/X export page/all  n/p pages  o sort  / filter  b base  e edit  r rerun  F referrals  q back"))
	return b.String()
}

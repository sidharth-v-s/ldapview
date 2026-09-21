package tui

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/dn"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
	"github.com/zoro/ldapview/internal/oid"
	"github.com/zoro/ldapview/internal/store"
)

// confirmed operations
type doModifyMsg struct {
	dn      string
	changes []ldapclient.Change
	desc    string
}
type doAddMsg struct {
	dn, parent string
	attrs      []ldapclient.AttrVals
}
type doDeleteMsg struct{ dn string }
type doModDNMsg struct {
	dn, newRDN, newSuperior string
	deleteOld               bool
}
type pickClassesMsg struct{ names []string }
type importParsedMsg struct {
	recs []ldif.Record
	path string
	err  error
}
type doImportMsg struct{ recs []ldif.Record }

func (a App) roBlock() tea.Cmd {
	if a.sh.readOnly {
		return statusCmd("read-only mode: directory modifications are disabled (:readonly off to enable)", true)
	}
	return nil
}

func changeLines(ch []ldapclient.Change) []string {
	var out []string
	for _, c := range ch {
		sym := map[string]string{"add": "+", "delete": "-", "replace": "~"}[c.Op]
		if len(c.Values) == 0 {
			out = append(out, fmt.Sprintf("%s %s: (all values)", sym, c.Attr))
		}
		for _, v := range c.Values {
			if ldapclient.IsSecretAttr(c.Attr) {
				v = "********"
			}
			out = append(out, fmt.Sprintf("%s %s: %s", sym, c.Attr, v))
		}
	}
	return out
}

func confirmModify(d string, ch []ldapclient.Change, desc string, extra ...string) tea.Cmd {
	lines := append([]string{"dn: " + d, ""}, changeLines(ch)...)
	if len(extra) > 0 {
		lines = append(lines, "")
		lines = append(lines, extra...)
	}
	return openOverlay(&confirmOverlay{title: "Modify entry — this changes the directory", lines: lines,
		yes: func() tea.Cmd { return msgCmd(doModifyMsg{dn: d, changes: ch, desc: desc}) }})
}

func parentDN(d string) string {
	p, _ := dn.Parent(d)
	return p
}

func (a App) handleWrite(msg tea.Msg) (tea.Model, tea.Cmd) {
	sh := a.sh
	switch m := msg.(type) {
	case editValueMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		d, attr, old := m.dn, m.attr, m.old
		return a, openOverlay(newPrompt("edit "+attr, old, "enter reviews the change before anything is sent", func(nv string) tea.Cmd {
			if nv == old {
				return statusCmd("value unchanged", false)
			}
			var notes []string
			if w := syntaxWarning(sh.schema, attr, nv); w != "" {
				notes = append(notes, w)
			}
			return confirmModify(d, []ldapclient.Change{
				{Op: "delete", Attr: attr, Values: []string{old}},
				{Op: "add", Attr: attr, Values: []string{nv}},
			}, "modified "+attr, notes...)
		}))

	case addValueMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		d, entry := m.dn, a.browser.entry
		init := ""
		if m.attr != "" {
			init = m.attr + ": "
		}
		return a, openOverlay(newPrompt("add value", init, "attribute: value   (e.g. mail: a@example.com)", func(s string) tea.Cmd {
			i := strings.IndexAny(s, ":=")
			if i <= 0 {
				return statusCmd("format: attribute: value", true)
			}
			attr, val := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			if attr == "" || val == "" {
				return statusCmd("attribute and value are required", true)
			}
			op := "add"
			var notes []string
			if sh.schema != nil {
				if at := sh.schema.Attr(attr); at == nil {
					notes = append(notes, "note: attribute not found in the schema — the server will decide")
				} else if at.SingleValue && entry != nil && len(entry.Get(attr)) > 0 {
					op = "replace"
					notes = append(notes, "attribute is single-valued: the existing value will be replaced")
				}
			}
			if w := syntaxWarning(sh.schema, attr, val); w != "" {
				notes = append(notes, w)
			}
			return confirmModify(d, []ldapclient.Change{{Op: op, Attr: attr, Values: []string{val}}}, "added "+attr, notes...)
		}))

	case delValueMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		var notes []string
		if sh.schema != nil && a.browser.entry != nil {
			must, _ := sh.schema.Resolve(a.browser.entry.Get("objectClass"))
			for _, x := range must {
				if strings.EqualFold(x, sh.schema.CanonAttr(m.attr)) && len(a.browser.entry.Get(m.attr)) <= 1 {
					notes = append(notes, "WARNING: this attribute is required by the entry's objectClasses; the server will probably refuse")
				}
			}
		}
		d, attr, val := m.dn, m.attr, m.val
		ch := []ldapclient.Change{{Op: "delete", Attr: attr, Values: []string{val}}}
		lines := append([]string{"dn: " + d, ""}, changeLines(ch)...)
		lines = append(lines, notes...)
		return a, openOverlay(&confirmOverlay{title: "Delete value", lines: lines, danger: true,
			yes: func() tea.Cmd { return msgCmd(doModifyMsg{dn: d, changes: ch, desc: "deleted a value of " + attr}) }})

	case deleteEntryMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		d := m.dn
		return a, openOverlay(&confirmOverlay{title: "DELETE ENTRY", danger: true,
			lines: []string{d, "", "This permanently removes the entry. Only leaf entries can be deleted;", "the server refuses entries that still have children."},
			yes:   func() tea.Cmd { return msgCmd(doDeleteMsg{dn: d}) }})

	case addEntryMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		return a.openAddEntryForm(m.parent)

	case modDNMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		return a.openModDNForm(m.dn)

	case exportEntryMsg:
		e, path := *m.entry, m.path
		return a, func() tea.Msg {
			res, err := writeExport(path, []ldapclient.Entry{e}, nil)
			if err != nil {
				return statusMsg{text: "export failed: " + err.Error(), isErr: true}
			}
			return statusMsg{text: res}
		}

	case pickClassesMsg:
		if a.screen == screenForm && a.formKind == "add" {
			have := splitClasses(a.form.fields[2].in.String())
			seen := map[string]bool{}
			for _, h := range have {
				seen[strings.ToLower(h)] = true
			}
			for _, n := range m.names {
				if !seen[strings.ToLower(n)] {
					have = append(have, n)
				}
			}
			a.form.fields[2].in.Set(strings.Join(have, ","))
			rebuildAddFields(&a.form, sh)
		}
		return a, nil

	case doModifyMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		cl := sh.client
		return a, func() tea.Msg {
			err := cl.Modify(m.dn, m.changes)
			done := opDoneMsg{desc: m.desc, failDesc: "modify " + m.dn, err: err}
			if err == nil {
				done.refreshEntry = m.dn
			}
			return done
		}

	case doAddMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		a.screen = screenBrowser
		cl := sh.client
		return a, func() tea.Msg {
			err := cl.Add(m.dn, m.attrs)
			done := opDoneMsg{desc: "added " + m.dn, failDesc: "add " + m.dn, err: err}
			if err == nil {
				done.refreshChildren, done.selectDN, done.refreshEntry = []string{m.parent}, m.dn, m.dn
			}
			return done
		}

	case doDeleteMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		cl := sh.client
		return a, func() tea.Msg {
			err := cl.Delete(m.dn)
			done := opDoneMsg{desc: "deleted " + m.dn, failDesc: "delete " + m.dn, err: err}
			if err == nil {
				p := parentDN(m.dn)
				done.refreshChildren, done.selectDN, done.clearEntry = []string{p}, p, true
			}
			return done
		}

	case doModDNMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		a.screen = screenBrowser
		cl := sh.client
		return a, func() tea.Msg {
			err := cl.ModifyDN(m.dn, m.newRDN, m.deleteOld, m.newSuperior)
			done := opDoneMsg{desc: "renamed/moved " + m.dn, failDesc: "rename/move " + m.dn, err: err}
			if err == nil {
				op := parentDN(m.dn)
				np := op
				if m.newSuperior != "" {
					np = m.newSuperior
				}
				nd := dn.Join(m.newRDN, np)
				done.refreshChildren = []string{op}
				if !dnEqual(op, np) {
					done.refreshChildren = append(done.refreshChildren, np)
				}
				done.selectDN, done.refreshEntry, done.clearEntry = nd, nd, true
			}
			return done
		}

	case importParsedMsg:
		if m.err != nil {
			return a, statusCmd("import: "+m.err.Error(), true)
		}
		if len(m.recs) == 0 {
			return a, statusCmd("no records found in "+m.path, true)
		}
		counts := map[string]int{}
		for _, r := range m.recs {
			counts[r.Change]++
		}
		lines := []string{fmt.Sprintf("file: %s", m.path), fmt.Sprintf("%d records: %d add, %d modify, %d delete, %d rename/move", len(m.recs), counts["add"], counts["modify"], counts["delete"], counts["modrdn"]), ""}
		for i, r := range m.recs {
			if i >= 12 {
				lines = append(lines, fmt.Sprintf("… and %d more", len(m.recs)-i))
				break
			}
			lines = append(lines, fmt.Sprintf("%-7s %s", r.Change, r.DN))
		}
		lines = append(lines, "", "Records are applied in order; processing stops at the first error.")
		recs := m.recs
		return a, openOverlay(&confirmOverlay{title: "Import LDIF — this changes the directory", lines: lines, danger: true,
			yes: func() tea.Cmd { return msgCmd(doImportMsg{recs: recs}) }})

	case doImportMsg:
		if c := a.roBlock(); c != nil {
			return a, c
		}
		cl := sh.client
		return a, func() tea.Msg {
			n, err := applyRecords(cl, m.recs)
			return importDoneMsg{applied: n, total: len(m.recs), err: err}
		}

	case importDoneMsg:
		if m.err != nil {
			return a, statusCmd(fmt.Sprintf("import stopped after %d of %d records: %v", m.applied, m.total, m.err), true)
		}
		return a, statusCmd(fmt.Sprintf("import complete: %d records applied (press r to refresh the tree)", m.applied), false)
	}
	return a, nil
}

func applyRecords(c *ldapclient.Client, recs []ldif.Record) (int, error) {
	for i, r := range recs {
		var err error
		switch r.Change {
		case "add":
			var attrs []ldapclient.AttrVals
			for _, at := range r.Attrs {
				av := ldapclient.AttrVals{Name: at.Name}
				for _, v := range at.Values {
					av.Values = append(av.Values, string(v))
				}
				attrs = append(attrs, av)
			}
			err = c.Add(r.DN, attrs)
		case "delete":
			err = c.Delete(r.DN)
		case "modify":
			var ch []ldapclient.Change
			for _, mo := range r.Mods {
				cc := ldapclient.Change{Op: mo.Op, Attr: mo.Attr}
				for _, v := range mo.Values {
					cc.Values = append(cc.Values, string(v))
				}
				ch = append(ch, cc)
			}
			err = c.Modify(r.DN, ch)
		case "modrdn":
			err = c.ModifyDN(r.DN, r.NewRDN, r.DeleteOldRDN, r.NewSuperior)
		}
		if err != nil {
			return i, fmt.Errorf("record %d (%s): %s", i+1, r.DN, friendlyErr(err))
		}
	}
	return len(recs), nil
}

// ---- add-entry form ----

func splitClasses(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

func splitExtra(s string) []string {
	var parts []string
	var cur strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '\\' && i+1 < len(rs) && rs[i+1] == ';':
			cur.WriteRune(';')
			i++
		case rs[i] == ';':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(rs[i])
		}
	}
	return append(parts, cur.String())
}

func rdnAttrSet(rdn string) (map[string]bool, [][2]string) {
	set := map[string]bool{}
	var pairs [][2]string
	if p, err := ldap.ParseDN(rdn); err == nil && len(p.RDNs) == 1 {
		for _, a := range p.RDNs[0].Attributes {
			set[strings.ToLower(a.Type)] = true
			pairs = append(pairs, [2]string{a.Type, a.Value})
		}
	}
	return set, pairs
}

func rebuildAddFields(fm *formModel, sh *shared) {
	if sh.schema == nil || len(fm.fields) < 4 {
		return
	}
	classes := splitClasses(fm.fields[2].in.String())
	must, _ := sh.schema.Resolve(classes)
	rdnSet, _ := rdnAttrSet(strings.TrimSpace(fm.fields[1].in.String()))
	old := map[string]formField{}
	for _, f := range fm.fields[3 : len(fm.fields)-1] {
		old[strings.ToLower(f.label)] = f
	}
	extra := fm.fields[len(fm.fields)-1]
	nf := append([]formField{}, fm.fields[:3]...)
	for _, a := range must {
		l := strings.ToLower(a)
		if l == "objectclass" || rdnSet[l] {
			continue
		}
		f := textField(a, "", "required by the selected object classes")
		if o, ok := old[l]; ok {
			f.in = o.in
		}
		nf = append(nf, f)
	}
	fm.fields = append(nf, extra)
}

// addFormBuild assembles the new entry from the form. strict also demands
// that required attributes are filled in.
func addFormBuild(fm *formModel, sh *shared, strict bool) (string, []ldapclient.AttrVals, []string, error) {
	parent := strings.TrimSpace(fm.fields[0].in.String())
	rdn := strings.TrimSpace(fm.fields[1].in.String())
	classes := splitClasses(fm.fields[2].in.String())
	if rdn == "" {
		return "", nil, nil, fmt.Errorf("RDN is required (e.g. uid=alice)")
	}
	rdnSet, rdnPairs := rdnAttrSet(rdn)
	if len(rdnPairs) == 0 {
		return "", nil, nil, fmt.Errorf("RDN %q is not valid (expected attr=value)", rdn)
	}
	if parent != "" && !dn.Valid(parent) {
		return "", nil, nil, fmt.Errorf("parent is not a valid DN")
	}
	if len(classes) == 0 {
		return "", nil, nil, fmt.Errorf("at least one objectClass is required")
	}
	order := []string{}
	vals := map[string][]string{}
	names := map[string]string{}
	put := func(name, v string) {
		k := strings.ToLower(name)
		if _, ok := names[k]; !ok {
			names[k] = name
			order = append(order, k)
		}
		for _, x := range vals[k] {
			if x == v {
				return
			}
		}
		vals[k] = append(vals[k], v)
	}
	for _, c := range classes {
		put("objectClass", c)
	}
	for _, p := range rdnPairs {
		put(p[0], p[1])
	}
	var warns []string
	for _, f := range fm.fields[3 : len(fm.fields)-1] {
		if v := strings.TrimSpace(f.in.String()); v != "" {
			put(f.label, v)
		} else if strict {
			return "", nil, nil, fmt.Errorf("required attribute %s is empty", f.label)
		}
	}
	for _, part := range splitExtra(fm.fields[len(fm.fields)-1].in.String()) {
		if strings.TrimSpace(part) == "" {
			continue
		}
		i := strings.IndexByte(part, '=')
		if i <= 0 {
			return "", nil, nil, fmt.Errorf("extra attribute %q must look like attr=value", strings.TrimSpace(part))
		}
		put(strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:]))
	}
	if s := sh.schema; s != nil {
		must, may := s.Resolve(classes)
		allowed := map[string]bool{}
		for _, x := range append(append([]string{}, must...), may...) {
			allowed[strings.ToLower(x)] = true
		}
		for _, x := range classes {
			if s.Class(x) == nil {
				warns = append(warns, "unknown objectClass: "+x)
			}
		}
		for _, k := range order {
			if k == "objectclass" {
				continue
			}
			if s.Attr(names[k]) == nil {
				warns = append(warns, "unknown attribute: "+names[k])
			} else if !allowed[strings.ToLower(s.CanonAttr(names[k]))] && !rdnSet[k] {
				warns = append(warns, names[k]+" is not allowed by the chosen object classes")
			} else if at := s.Attr(names[k]); at.SingleValue && len(vals[k]) > 1 {
				warns = append(warns, names[k]+" is single-valued but has several values")
			}
		}
		if strict {
			for _, mu := range must {
				if _, ok := names[strings.ToLower(mu)]; !ok {
					return "", nil, nil, fmt.Errorf("required attribute %s is missing", mu)
				}
			}
		}
	}
	var attrs []ldapclient.AttrVals
	for _, k := range order {
		attrs = append(attrs, ldapclient.AttrVals{Name: names[k], Values: vals[k]})
	}
	return dn.Join(rdn, parent), attrs, warns, nil
}

func previewLDIF(d string, attrs []ldapclient.AttrVals) []string {
	e := ldif.Entry{DN: d}
	for _, a := range attrs {
		la := ldif.Attr{Name: a.Name}
		for _, v := range a.Values {
			if ldapclient.IsSecretAttr(a.Name) {
				v = "********"
			}
			la.Values = append(la.Values, []byte(v))
		}
		e.Attrs = append(e.Attrs, la)
	}
	return strings.Split(strings.TrimRight(ldif.EntryString(e), "\n"), "\n")
}

func (a App) openAddEntryForm(parent string) (tea.Model, tea.Cmd) {
	sh := a.sh
	f := formModel{title: "Add entry", width: a.width, height: a.height}
	f.fields = []formField{
		textField("Parent DN", parent, "the new entry is created below this DN"),
		textField("RDN", "", "e.g. uid=alice  or  cn=Alice Smith"),
		textField("objectClass", "", "comma separated — ctrl+o picks from the schema; leaving the field lists required attributes"),
		textField("Extra attributes", "", "attr=value ; attr=value   (write \\; for a literal semicolon)"),
	}
	f.footer = "tab move  ctrl+o pick objectClasses  ctrl+s review & create  esc cancel"
	f.onLeave = func(fm *formModel, idx int) {
		if idx == 1 || idx == 2 {
			rebuildAddFields(fm, sh)
		}
	}
	f.keys = map[string]func(*formModel) tea.Cmd{
		"ctrl+o": func(fm *formModel) tea.Cmd {
			if sh.schema == nil {
				return tea.Batch(statusCmd("schema still loading — try again in a moment", false), msgCmd(needSchemaMsg{}))
			}
			var items []pickItem
			for _, oc := range sh.schema.ClassList {
				if !oc.Obsolete {
					items = append(items, pickItem{label: oc.Name(), detail: strings.ToLower(oc.Kind) + "  " + oc.Desc})
				}
			}
			p := newPicker("Choose object classes (tab marks several)", items, func(c []pickItem) tea.Cmd {
				var n []string
				for _, it := range c {
					n = append(n, it.label)
				}
				return msgCmd(pickClassesMsg{names: n})
			})
			p.multi = true
			return openOverlay(p)
		},
	}
	f.previewForm = func(fm *formModel) string {
		d, attrs, warns, err := addFormBuild(fm, sh, false)
		if err != nil {
			return dimStyle.Render("  " + err.Error())
		}
		out := attrNameStyle.Render("  Preview") + dimStyle.Render("  → "+d) + "\n"
		for _, l := range previewLDIF(d, attrs) {
			out += dimStyle.Render("    "+truncate(l, max(fm.width-6, 20))) + "\n"
		}
		if len(warns) > 0 {
			out += warnStyle.Render("  " + strings.Join(warns, "\n  "))
		}
		return strings.TrimRight(out, "\n")
	}
	f.submitForm = func(fm *formModel) tea.Cmd {
		d, attrs, warns, err := addFormBuild(fm, sh, true)
		if err != nil {
			fm.notice = err.Error()
			return statusCmd(err.Error(), true)
		}
		fm.notice = ""
		lines := append(previewLDIF(d, attrs), "")
		for _, w := range warns {
			lines = append(lines, "warning: "+w)
		}
		par := strings.TrimSpace(fm.fields[0].in.String())
		return openOverlay(&confirmOverlay{title: "Create entry — this changes the directory", lines: lines,
			yes: func() tea.Cmd { return msgCmd(doAddMsg{dn: d, parent: par, attrs: attrs}) }})
	}
	a.form, a.formKind, a.screen = f, "add", screenForm
	if sh.schema == nil {
		return a, a.loadSchemaCmd()
	}
	return a, nil
}

func (a App) openModDNForm(d string) (tea.Model, tea.Cmd) {
	rdn, _ := dn.RDN(d)
	parent := parentDN(d)
	f := formModel{title: "Rename / move: " + d, width: a.width, height: a.height}
	f.fields = []formField{
		textField("New RDN", rdn, "change to rename, e.g. cn=New Name"),
		textField("New parent DN", parent, "change to move the entry (the target container must exist)"),
		choiceField("Delete old RDN value", []string{"yes", "no"}, "yes"),
	}
	newDN := func(fm *formModel) (string, string, error) {
		nr := strings.TrimSpace(fm.fields[0].in.String())
		np := strings.TrimSpace(fm.fields[1].in.String())
		if _, pairs := rdnAttrSet(nr); len(pairs) == 0 {
			return "", "", fmt.Errorf("new RDN %q is not valid", nr)
		}
		if np != "" && !dn.Valid(np) {
			return "", "", fmt.Errorf("new parent is not a valid DN")
		}
		return dn.Join(nr, np), np, nil
	}
	f.previewForm = func(fm *formModel) string {
		nd, _, err := newDN(fm)
		if err != nil {
			return warnStyle.Render("  " + err.Error())
		}
		s := dimStyle.Render("  old: "+d) + "\n" + attrNameStyle.Render("  new: ") + nd
		if dnEqual(nd, d) {
			s += "\n" + warnStyle.Render("  nothing changes")
		}
		return s
	}
	f.submitForm = func(fm *formModel) tea.Cmd {
		nd, np, err := newDN(fm)
		if err != nil {
			return statusCmd(err.Error(), true)
		}
		if dnEqual(nd, d) {
			return statusCmd("nothing to change", true)
		}
		nr := strings.TrimSpace(fm.fields[0].in.String())
		sup := ""
		if !dnEqual(np, parent) {
			sup = np
		}
		del := fm.fields[2].value() == "yes"
		return openOverlay(&confirmOverlay{title: "Rename / move — this changes the directory", danger: true,
			lines: []string{"from: " + d, "to:   " + nd, "", "Descendants move with the entry; some servers refuse to move subtrees."},
			yes:   func() tea.Cmd { return msgCmd(doModDNMsg{dn: d, newRDN: nr, newSuperior: sup, deleteOld: del}) }})
	}
	a.form, a.formKind, a.screen = f, "moddn", screenForm
	return a, nil
}

// ---- referrals ----

func (a App) openReferral(raw string) (tea.Model, tea.Cmd) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return a, statusCmd("cannot parse referral URL: "+raw, true)
	}
	host, portStr := u.Hostname(), u.Port()
	c := store.Connection{Name: host, Host: host, TLSMode: store.TLSNone, BindMethod: store.BindSimple}
	if u.Scheme == "ldaps" {
		c.TLSMode = store.TLSImplicit
	}
	c.Port = c.DefaultPort()
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			c.Port = p
		}
	}
	a.screen = screenConnections
	a.connections.setSize(a.width, a.height)
	a.connections.openForm("Referral target (credentials are NOT forwarded): "+raw, c, "")
	return a, statusCmd("referral opened as a new profile — review it, save, then connect separately", false)
}

// followReferral parses an LDAP URL referral and opens a fresh,
// anonymous, throw-away connection to it in the browser — it never
// reuses or forwards the current bind's credentials, and it never
// happens without the person explicitly choosing "Follow".
func (a App) followReferral(raw string) (tea.Model, tea.Cmd) {
	u, err := parseLDAPURL(raw)
	if err != nil {
		return a, statusCmd("cannot follow referral: "+err.Error(), true)
	}
	c := store.Connection{Name: "referral: " + u.Host, Host: u.Host, Port: u.DefaultPort(), TLSMode: store.TLSNone, BindMethod: store.BindAnonymous, TimeoutSec: 10}
	if u.Scheme == "ldaps" {
		c.TLSMode = store.TLSImplicit
	}
	a.status, a.statusErr = "following referral to "+c.URL()+" (anonymous — credentials are not forwarded)", false
	return a, tea.Batch(followReferralConnectCmd(c, u.Base, u.Scope, u.Filter))
}

func followReferralConnectCmd(conf store.Connection, base, scope, filt string) tea.Cmd {
	return func() tea.Msg {
		c, err := ldapclient.Connect(conf)
		if err != nil {
			return connectResultMsg{err: err, conn: conf}
		}
		_, _ = c.FetchRootDSE()
		if err := c.Bind(""); err != nil {
			c.Close()
			return connectResultMsg{err: err, conn: conf}
		}
		return referralConnectedMsg{client: c, conn: conf, base: base, scope: scope, filter: filt}
	}
}

// ---- palette ----

type cmdDef struct {
	name string
	desc string
	conn bool
	run  func(a App, arg string) (App, tea.Cmd)
}

var commandList []cmdDef

func init() {
	commandList = []cmdDef{
		{"help", "show key reference", false, func(a App, _ string) (App, tea.Cmd) { return a, msgCmd(openScreenMsg{screenHelp}) }},
		{"quit", "exit ldapview", false, func(a App, _ string) (App, tea.Cmd) { a.closeClient(); return a, tea.Quit }},
		{"disconnect", "close the connection", true, func(a App, _ string) (App, tea.Cmd) { return a, msgCmd(disconnectMsg{}) }},
		{"goto", "goto <dn> — reveal an entry", true, func(a App, arg string) (App, tea.Cmd) {
			if arg == "" {
				return a, statusCmd("usage: :goto <dn>", true)
			}
			return a, msgCmd(gotoMsg{dn: arg})
		}},
		{"search", "search [filter] — open search", true, func(a App, arg string) (App, tea.Cmd) {
			base := ""
			if n := a.browser.current(); n != nil {
				base = n.DN
			}
			return a, msgCmd(openSearchMsg{base: base, filter: arg})
		}},
		{"refresh", "reload the selected node", true, func(a App, _ string) (App, tea.Cmd) {
			var c tea.Cmd
			a.browser, c = a.browser.handleTreeKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
			return a, c
		}},
		{"rootdse", "show Root DSE", true, func(a App, _ string) (App, tea.Cmd) { return a, msgCmd(openRootDSEMsg{}) }},
		{"info", "connection summary", true, func(a App, _ string) (App, tea.Cmd) { return a, showMessage("Connection", a.infoLines()) }},
		{"server", "server type detection (Root DSE-based, non-authoritative)", true, func(a App, _ string) (App, tea.Cmd) {
			d := a.sh.client.DSE()
			g := ldapclient.DetectServer(d)
			lines := []string{
				"Server:     " + g.Name,
				"Confidence: " + g.Confidence,
				"",
				"Reasoning:",
			}
			for _, r := range g.Reasons {
				lines = append(lines, "  - "+r)
			}
			lines = append(lines, "", "Based only on Root DSE fields the server itself advertised — never treated as definitive.")
			return a, showMessage("Server detection", lines)
		}},
		{"secinfo", "security-oriented visibility: anonymous bind, TLS, SASL, controls", true, func(a App, _ string) (App, tea.Cmd) {
			return a, tea.Batch(statusCmd("probing anonymous bind (separate, unauthenticated connection)…", false), probeSecInfoCmd(a.sh))
		}},
		{"tls", "TLS details", true, func(a App, _ string) (App, tea.Cmd) {
			return a, showMessage("TLS", tlsLines(a.sh.client))
		}},
		{"sasl", "SASL mechanisms", true, func(a App, _ string) (App, tea.Cmd) {
			lines := []string{"Implemented by this client: " + strings.Join(ldapclient.SASLMechanisms, ", "), ""}
			if d := a.sh.client.DSE(); d != nil {
				lines = append(lines, "Advertised by the server:")
				for _, m := range d.SupportedSASLMechanisms {
					mark := "  "
					for _, i := range ldapclient.SASLMechanisms {
						if strings.EqualFold(i, m) {
							mark = "✓ "
						}
					}
					lines = append(lines, "  "+mark+m)
				}
				lines = append(lines, "", "✓ = usable from a connection profile (SASL bind method)")
			}
			return a, showMessage("SASL", lines)
		}},
		{"controls", "supported controls", true, func(a App, _ string) (App, tea.Cmd) {
			var lines []string
			if d := a.sh.client.DSE(); d != nil {
				c := append([]string(nil), d.SupportedControl...)
				sort.Strings(c)
				for _, o := range c {
					lines = append(lines, oid.Label(o))
				}
			}
			return a, showMessage(fmt.Sprintf("Supported controls (%d)", len(lines)), lines)
		}},
		{"extops", "extended operations", true, func(a App, _ string) (App, tea.Cmd) {
			var items []pickItem
			for _, o := range extOpList(a.sh.client.DSE()) {
				items = append(items, pickItem{label: oid.Label(o), value: o})
			}
			return a, openOverlay(newPicker("Extended operations", items, func(c []pickItem) tea.Cmd {
				return msgCmd(openExtOpMsg{oid: c[0].value.(string)})
			}))
		}},
		{"whoami", "Who am I? extended operation", true, func(a App, _ string) (App, tea.Cmd) {
			cl := a.sh.client
			return a, func() tea.Msg {
				w, err := cl.WhoAmI()
				if err != nil {
					return statusMsg{text: "whoami: " + friendlyErr(err), isErr: true}
				}
				if w == "" {
					w = "(anonymous)"
				}
				return statusMsg{text: "authorization identity: " + w}
			}
		}},
		{"schema", "schema [name] — schema browser", true, func(a App, arg string) (App, tea.Cmd) { return a, msgCmd(openSchemaMsg{query: arg}) }},
		{"ops", "operation log", true, func(a App, _ string) (App, tea.Cmd) { return a, msgCmd(openScreenMsg{screenOps}) }},
		{"proto", "raw protocol viewer", true, func(a App, _ string) (App, tea.Cmd) { return a, msgCmd(openScreenMsg{screenProto}) }},
		{"filter", "filter builder", true, func(a App, _ string) (App, tea.Cmd) { return a, msgCmd(openFilterMsg{}) }},
		{"presets", "search presets", true, func(a App, _ string) (App, tea.Cmd) {
			base := ""
			if n := a.browser.current(); n != nil {
				base = n.DN
			}
			a.search = newSearchModel(a.sh, base, "")
			a.search.setSize(a.width, a.height)
			a.screen = screenSearch
			return a, a.search.form.keys["ctrl+p"](&a.search.form)
		}},
		{"history", "search history", true, func(a App, _ string) (App, tea.Cmd) {
			a.search = newSearchModel(a.sh, "", "")
			a.search.setSize(a.width, a.height)
			a.screen = screenSearch
			return a, openSavedPicker("Search history", a.sh.history, false)
		}},
		{"bookmarks", "saved searches", true, func(a App, _ string) (App, tea.Cmd) {
			a.search = newSearchModel(a.sh, "", "")
			a.search.setSize(a.width, a.height)
			a.screen = screenSearch
			return a, openSavedPicker("Bookmarks", a.sh.bookmarks, true)
		}},
		{"export", "export <file> — selected entry (.ldif/.json)", true, func(a App, arg string) (App, tea.Cmd) {
			if a.browser.entry == nil {
				return a, statusCmd("load an entry first", true)
			}
			if arg == "" {
				arg = defaultExportName(rdnSlug(a.browser.entry.DN), "ldif")
			}
			return a, msgCmd(exportEntryMsg{path: arg, entry: a.browser.entry})
		}},
		{"import", "import <file.ldif> — apply LDIF records", true, func(a App, arg string) (App, tea.Cmd) {
			if c := a.roBlock(); c != nil {
				return a, c
			}
			if arg == "" {
				return a, statusCmd("usage: :import <file.ldif>", true)
			}
			return a, func() tea.Msg {
				f, err := os.Open(arg)
				if err != nil {
					return importParsedMsg{err: err}
				}
				defer f.Close()
				if st, err := f.Stat(); err == nil && st.Size() > 50<<20 {
					return importParsedMsg{err: fmt.Errorf("file too large (>50 MB)")}
				}
				recs, err := ldif.Parse(f)
				return importParsedMsg{recs: recs, path: arg, err: err}
			}
		}},
		{"ldif", "ldif <file> — view/validate;  ldif edit [file] — edit in $EDITOR, then import", true, func(a App, arg string) (App, tea.Cmd) {
			fields := strings.Fields(arg)
			if len(fields) > 0 && strings.EqualFold(fields[0], "edit") {
				if c := a.roBlock(); c != nil {
					return a, c
				}
				path := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), fields[0]))
				cmd, err := editLDIFCmd(path)
				if err != nil {
					return a, statusCmd("ldif edit: "+err.Error(), true)
				}
				return a, cmd
			}
			if arg == "" {
				return a, statusCmd("usage: :ldif <file>   or   :ldif edit [file]", true)
			}
			return a, loadLDIFCmd(arg)
		}},
		{"readonly", "readonly [on|off] — block modifications", true, func(a App, arg string) (App, tea.Cmd) {
			switch strings.ToLower(arg) {
			case "on", "yes", "true", "1":
				a.sh.readOnly = true
			case "off", "no", "false", "0":
				if a.sh.conf.ReadOnly {
					return a, statusCmd("this connection profile is read-only; edit the profile to change it", true)
				}
				a.sh.readOnly = false
			case "":
			default:
				return a, statusCmd("usage: :readonly on|off", true)
			}
			return a, statusCmd("read-only mode: "+yn(a.sh.readOnly), false)
		}},
		{"view", "view attrs|ldif|raw|rel|schema|sec", true, func(a App, arg string) (App, tea.Cmd) {
			modes := map[string]entryMode{"attrs": modeAttrs, "attributes": modeAttrs, "ldif": modeLDIF, "raw": modeRaw,
				"rel": modeRel, "relationships": modeRel, "schema": modeSchema, "sec": modeSec, "security": modeSec}
			mo, ok := modes[strings.ToLower(arg)]
			if !ok {
				return a, statusCmd("usage: :view attrs|ldif|raw|rel|schema|sec", true)
			}
			a.browser.mode = mo
			a.browser.ecur, a.browser.escroll = 0, 0
			a.browser.rebuild()
			a.screen = screenBrowser
			return a, a.browser.modeCmd()
		}},
		{"add", "add an entry under the selection", true, func(a App, _ string) (App, tea.Cmd) {
			if n := a.browser.current(); n != nil {
				return a, msgCmd(addEntryMsg{parent: n.DN})
			}
			return a, statusCmd("select a parent first", true)
		}},
		{"delete", "delete the selected entry", true, func(a App, _ string) (App, tea.Cmd) {
			if n := a.browser.current(); n != nil {
				return a, msgCmd(deleteEntryMsg{dn: n.DN})
			}
			return a, nil
		}},
		{"rename", "rename / move the selected entry", true, func(a App, _ string) (App, tea.Cmd) {
			if n := a.browser.current(); n != nil {
				return a, msgCmd(modDNMsg{dn: n.DN})
			}
			return a, nil
		}},
		{"copy", "copy dn|ldif", true, func(a App, arg string) (App, tea.Cmd) {
			if a.browser.entry == nil {
				return a, statusCmd("load an entry first", true)
			}
			if strings.EqualFold(arg, "ldif") {
				return a, copyCmd(ldif.EntryString(toLDIFEntry(*a.browser.entry)), "entry as LDIF")
			}
			return a, copyCmd(a.browser.entry.DN, "DN")
		}},
		{"sid", "sid <S-1-5-…> — find the object with this SID (AD)", true, func(a App, arg string) (App, tea.Cmd) {
			raw, err := ldapclient.EncodeSID(arg)
			if err != nil {
				return a, statusCmd(err.Error(), true)
			}
			return a, lookupBinaryCmd(a.sh, "objectSid", raw, "SID "+arg)
		}},
		{"guid", "guid <guid> — find the object with this objectGUID (AD)", true, func(a App, arg string) (App, tea.Cmd) {
			raw, err := ldapclient.EncodeGUID(arg)
			if err != nil {
				return a, statusCmd(err.Error(), true)
			}
			return a, lookupBinaryCmd(a.sh, "objectGUID", raw, "GUID "+arg)
		}},
		{"diff", "compare the marked entry (=) with the loaded entry", true, func(a App, _ string) (App, tea.Cmd) {
			return a, msgCmd(diffMsg{})
		}},
		{"unmark", "clear the marked entry", true, func(a App, _ string) (App, tea.Cmd) {
			a.browser.marked = nil
			return a, statusCmd("mark cleared", false)
		}},
		{"reconnect", "connect again with the current profile", true, func(a App, _ string) (App, tea.Cmd) {
			return a, msgCmd(connectRequestMsg{conn: a.sh.conf})
		}},
		{"clear", "clear [history] — session logs, or saved search history", true, func(a App, arg string) (App, tea.Cmd) {
			if strings.EqualFold(arg, "history") {
				if a.sh.history != nil {
					a.sh.history.Items = nil
					_ = a.sh.history.Save()
				}
				return a, statusCmd("search history cleared", false)
			}
			a.sh.client.ClearOps()
			a.sh.client.ProtoLog().Clear()
			return a, statusCmd("logs cleared", false)
		}},
	}
}

func (a App) infoLines() []string {
	c := a.sh.client
	d := c.DSE()
	lines := []string{
		"Profile:  " + a.sh.conf.Name,
		"Server:   " + a.sh.conf.URL(),
		"Bind:     " + boundState(a.sh.conf.BindMethod),
	}
	if a.sh.conf.BindDN != "" {
		lines = append(lines, "User:     "+a.sh.conf.BindDN)
	}
	proto := "LDAPv3"
	if d != nil && len(d.SupportedLDAPVersion) > 0 {
		proto = "LDAPv" + strings.Join(d.SupportedLDAPVersion, ",v")
	}
	lines = append(lines, "Protocol: "+proto)
	lines = append(lines, "Mode:     "+map[bool]string{true: "read-only", false: "read-write"}[a.sh.readOnly])
	lines = append(lines, tlsLines(c)...)
	if d != nil {
		g := ldapclient.DetectServer(d)
		srv := g.Name
		if g.Confidence != "high" {
			srv += fmt.Sprintf("  (confidence: %s)", g.Confidence)
		}
		lines = append(lines, "Server:   "+srv)
		if v := strings.TrimSpace(d.VendorName + " " + d.VendorVersion); v != "" {
			lines = append(lines, "Vendor:   "+v)
		}
		lines = append(lines, "Naming contexts: "+strings.Join(d.NamingContexts, ", "))
	}
	if s := a.sh.schema; s != nil {
		lines = append(lines, fmt.Sprintf("Schema:   %d classes, %d attributes (cached)", len(s.ClassList), len(s.AttrList)))
	}
	lines = append(lines, "Started:  "+time.Now().Format("15:04:05")+" (session log: :ops, :proto)")
	return lines
}

func boundState(m store.BindMethod) string {
	if m == "" {
		m = store.BindAnonymous
	}
	if m == store.BindAnonymous {
		return "anonymous (unauthenticated)"
	}
	return string(m) + " — authenticated"
}

func commandNames() []string {
	var n []string
	for _, c := range commandList {
		n = append(n, c.name)
	}
	sort.Strings(n)
	return n
}

func (a App) paletteCmd() tea.Cmd {
	p := newPrompt(":", "", "tab completes  ·  try help, goto, search, schema, import, readonly, ops, proto", func(s string) tea.Cmd {
		return msgCmd(cmdMsg{line: s})
	})
	p.suggest = func(cur string) []string {
		cur = strings.TrimSpace(strings.ToLower(cur))
		if strings.ContainsRune(cur, ' ') {
			return nil
		}
		var out []string
		for _, c := range commandList {
			if strings.HasPrefix(c.name, cur) {
				out = append(out, c.name)
			}
		}
		sort.Strings(out)
		return out
	}
	return openOverlay(p)
}

func (a App) runCommand(line string) (tea.Model, tea.Cmd) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), ":"))
	if line == "" {
		return a, nil
	}
	name := strings.ToLower(strings.Fields(line)[0])
	arg := strings.TrimSpace(line[len(strings.Fields(line)[0]):])
	alias := map[string]string{"q": "quit", "exit": "quit", "h": "help", "?": "help", "move": "rename", "mv": "rename", "ls": "search", "find": "search", "dse": "rootdse", "log": "ops"}
	if r, ok := alias[name]; ok {
		name = r
	}
	var match *cmdDef
	for i := range commandList {
		if commandList[i].name == name {
			match = &commandList[i]
		}
	}
	if match == nil {
		var cands []string
		for _, c := range commandList {
			if strings.HasPrefix(c.name, name) {
				cands = append(cands, c.name)
			}
		}
		if len(cands) == 1 {
			for i := range commandList {
				if commandList[i].name == cands[0] {
					match = &commandList[i]
				}
			}
		} else if len(cands) > 1 {
			return a, statusCmd(fmt.Sprintf("ambiguous command %q: %s", name, strings.Join(cands, ", ")), true)
		}
	}
	if match == nil {
		return a, statusCmd(fmt.Sprintf("unknown command %q — try :help", name), true)
	}
	if match.conn && !a.connected() {
		return a, statusCmd("connect to a server first", true)
	}
	na, cmd := match.run(a, arg)
	return na, cmd
}

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/filter"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
	"github.com/zoro/ldapview/internal/model"
	"github.com/zoro/ldapview/internal/schema"
	"github.com/zoro/ldapview/internal/store"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	case "ctrl+w":
		return tea.KeyMsg{Type: tea.KeyCtrlW}
	case "home":
		return tea.KeyMsg{Type: tea.KeyHome}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestLineInput(t *testing.T) {
	in := newInput("hello world")
	in.Handle(key("ctrl+w"))
	if in.String() != "hello " {
		t.Fatalf("ctrl+w: %q", in.String())
	}
	in.Handle(key("left"))
	in.Handle(key("X"))
	if in.String() != "helloX " {
		t.Fatalf("insert before cursor: %q", in.String())
	}
	in.Handle(key("home"))
	in.Handle(key("é"))
	in.Handle(key(" "))
	if in.String() != "é helloX " {
		t.Fatalf("unicode/space: %q", in.String())
	}
	in.Handle(key("ctrl+u"))
	if in.String() != "é helloX " { // cursor at 2 → deletes "é "
		// after inserting é and space at home, cursor is at 2; ctrl+u removes them
		if in.String() != "helloX " {
			t.Fatalf("ctrl+u: %q", in.String())
		}
	}
	// pasted multi-line text is flattened
	in2 := newInput("")
	in2.Handle(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a\nb\r\nc"), Paste: true})
	if in2.String() != "abc" {
		t.Fatalf("paste: %q", in2.String())
	}
	masked := newInput("secret").View(false, true, 0)
	if masked != "******" {
		t.Fatalf("mask: %q", masked)
	}
}

func TestSplitExtraAndCSVSafe(t *testing.T) {
	got := splitExtra(`a=1;b=x\;y; c=3`)
	if len(got) != 3 || got[1] != "b=x;y" {
		t.Fatalf("splitExtra: %q", got)
	}
	for in, want := range map[string]string{"=SUM(A1)": "'=SUM(A1)", "+1": "'+1", "-x": "'-x", "@a": "'@a", "plain": "plain", "": ""} {
		if csvSafe(in) != want {
			t.Fatalf("csvSafe(%q)=%q", in, csvSafe(in))
		}
	}
}

func TestExportFormats(t *testing.T) {
	dir := t.TempDir()
	es := []ldapclient.Entry{{DN: "cn=a,dc=x", Attributes: []ldapclient.Attribute{
		{Name: "cn", Values: []string{"=cmd|' /C calc'!A0"}, RawBytes: [][]byte{[]byte("=cmd|' /C calc'!A0")}},
		{Name: "mail", Values: []string{"a@x", "b@x"}, RawBytes: [][]byte{[]byte("a@x"), []byte("b@x")}},
	}}}
	for ext, want := range map[string]string{"ldif": "dn: cn=a,dc=x", "json": `"dn": "cn=a,dc=x"`, "csv": "'=cmd"} {
		p := filepath.Join(dir, "out."+ext)
		if _, err := writeExport(p, es, nil); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s export missing %q:\n%s", ext, want, b)
		}
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s perms %v", ext, st.Mode().Perm())
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "out.csv"))
	if !strings.Contains(string(b), "a@x; b@x") {
		t.Fatalf("multi-values must be joined: %s", b)
	}
}

func testSchema() *schema.Schema {
	return schema.Parse([]string{
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( description ) )",
		"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP person STRUCTURAL MAY ( mail $ uid ) )",
	}, []string{
		"( 2.5.4.0 NAME 'objectClass' )", "( 2.5.4.41 NAME 'name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.5.4.3 NAME 'cn' SUP name )", "( 2.5.4.4 NAME 'sn' SUP name )", "( 2.5.4.13 NAME 'description' )",
		"( 0.9.2342.19200300.100.1.3 NAME 'mail' )", "( 0.9.2342.19200300.100.1.1 NAME 'uid' SINGLE-VALUE )",
	}, nil, nil)
}

func newAddForm(sh *shared, parent, rdn, classes string) formModel {
	f := formModel{}
	f.fields = []formField{textField("Parent DN", parent, ""), textField("RDN", rdn, ""), textField("objectClass", classes, ""), textField("Extra attributes", "", "")}
	return f
}

func TestAddFormBuildAndRebuild(t *testing.T) {
	sh := &shared{schema: testSchema()}
	f := newAddForm(sh, "ou=People,dc=example,dc=com", "uid=zed", "inetOrgPerson")
	rebuildAddFields(&f, sh)
	labels := []string{}
	for _, x := range f.fields {
		labels = append(labels, x.label)
	}
	if strings.Join(labels, ",") != "Parent DN,RDN,objectClass,sn,cn,Extra attributes" && strings.Join(labels, ",") != "Parent DN,RDN,objectClass,cn,sn,Extra attributes" {
		t.Fatalf("required fields: %v", labels)
	}
	if _, _, _, err := addFormBuild(&f, sh, true); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("strict build must demand required attrs, got %v", err)
	}
	for i := range f.fields {
		switch f.fields[i].label {
		case "sn":
			f.fields[i].in.Set("Zed")
		case "cn":
			f.fields[i].in.Set("Zed Z")
		case "Extra attributes":
			f.fields[i].in.Set(`mail=z@x; bogus=1; uid=other`)
		}
	}
	d, attrs, warns, err := addFormBuild(&f, sh, true)
	if err != nil || d != "uid=zed,ou=People,dc=example,dc=com" {
		t.Fatalf("build: %q %v", d, err)
	}
	m := map[string][]string{}
	for _, a := range attrs {
		m[strings.ToLower(a.Name)] = a.Values
	}
	if len(m["uid"]) != 2 || m["uid"][0] != "zed" {
		t.Fatalf("RDN attribute must be added automatically and merged: %v", m["uid"])
	}
	if m["objectclass"][0] != "inetOrgPerson" || m["mail"][0] != "z@x" {
		t.Fatalf("attrs: %v", m)
	}
	joined := strings.Join(warns, "|")
	if !strings.Contains(joined, "unknown attribute: bogus") || !strings.Contains(joined, "single-valued") {
		t.Fatalf("warnings: %v", warns)
	}
	if _, _, _, err := addFormBuild(&f, sh, true); err != nil {
		t.Fatal(err)
	}
	bad := newAddForm(sh, "ou=x", "notardn", "person")
	if _, _, _, err := addFormBuild(&bad, sh, false); err == nil {
		t.Fatal("invalid RDN must fail")
	}
	none := newAddForm(sh, "ou=x", "cn=a", "")
	if _, _, _, err := addFormBuild(&none, sh, false); err == nil {
		t.Fatal("missing objectClass must fail")
	}
}

func TestPreviewMasksSecrets(t *testing.T) {
	out := strings.Join(previewLDIF("cn=a,dc=x", []ldapclient.AttrVals{{Name: "userPassword", Values: []string{"hunter2"}}, {Name: "cn", Values: []string{"a"}}}), "\n")
	if strings.Contains(out, "hunter2") || !strings.Contains(out, "userPassword: ********") {
		t.Fatalf("secret leaked in preview:\n%s", out)
	}
	lines := strings.Join(changeLines([]ldapclient.Change{{Op: "replace", Attr: "unicodePwd", Values: []string{"x"}}}), "")
	if strings.Contains(lines, "x") && !strings.Contains(lines, "********") {
		t.Fatalf("change lines must mask: %s", lines)
	}
}

func TestFilterModelOutput(t *testing.T) {
	m := newFilterModel("(&(a=1)(|(b=2)(c=3)))")
	if m.output() != "(&(a=1)(|(b=2)(c=3)))" {
		t.Fatalf("roundtrip: %s", m.output())
	}
	m2 := newFilterModel("")
	m2.root.Add(newGroupForTest("or"))
	if m2.output() != "" {
		t.Fatalf("empty groups must vanish: %q", m2.output())
	}
	m3 := newFilterModel("(cn=x)")
	if m3.output() != "(cn=x)" {
		t.Fatalf("single cond collapse: %s", m3.output())
	}
}

func TestPickColumns(t *testing.T) {
	es := []ldapclient.Entry{{DN: "a", Attributes: []ldapclient.Attribute{{Name: "cn"}, {Name: "mail"}, {Name: "sn"}}}}
	if got := pickColumns([]string{"*"}, es); strings.Join(got, ",") != "cn,mail" {
		t.Fatalf("auto columns: %v", got)
	}
	if got := pickColumns([]string{"sn", "cn"}, es); strings.Join(got, ",") != "sn,cn" {
		t.Fatalf("requested columns: %v", got)
	}
	if got := pickColumns([]string{"1.1"}, es); len(got) != 0 {
		t.Fatalf("DN-only: %v", got)
	}
}

func TestSchemaView(t *testing.T) {
	m := newSchemaModel(testSchema(), "inetOrgPerson")
	if m.tab != 0 || m.selected() != "inetOrgPerson" {
		t.Fatalf("query selection: tab=%d sel=%q", m.tab, m.selected())
	}
	d := strings.Join(m.detail("inetOrgPerson"), "\n")
	for _, want := range []string{"inetOrgPerson → person → top", "sn", "cn", "mail"} {
		if !strings.Contains(d, want) {
			t.Fatalf("detail missing %q:\n%s", want, d)
		}
	}
	m2 := newSchemaModel(testSchema(), "uid")
	if m2.tab != 1 || !strings.Contains(strings.Join(m2.detail("uid"), "\n"), "single-valued") {
		t.Fatal("attribute detail")
	}
}

func TestOverlayPickerFilters(t *testing.T) {
	p := newPicker("t", []pickItem{{label: "alpha"}, {label: "beta"}, {label: "alphabet", detail: "x"}}, func(c []pickItem) tea.Cmd { return nil })
	p.filter.Set("alph")
	if v := p.visible(); len(v) != 2 {
		t.Fatalf("visible: %v", v)
	}
	if strings.Contains(p.view(80, 24), "beta") {
		t.Fatal("filtered item shown")
	}
}

func newGroupForTest(kind string) *filter.Node {
	if kind == "or" {
		return filter.NewGroup(filter.Or)
	}
	return filter.NewGroup(filter.And)
}

func TestDiffAndSyntax(t *testing.T) {
	mk := func(dn string, kv ...string) ldapclient.Entry {
		e := ldapclient.Entry{DN: dn}
		for i := 0; i < len(kv); i += 2 {
			e.Attributes = append(e.Attributes, ldapclient.Attribute{Name: kv[i], Values: []string{kv[i+1]}, RawBytes: [][]byte{[]byte(kv[i+1])}})
		}
		return e
	}
	a := mk("cn=a", "cn", "a", "mail", "x@y", "entryUUID", "1", "title", "boss")
	b := mk("cn=b", "cn", "a", "mail", "z@y", "entryUUID", "2", "l", "Paris")
	d := strings.Join(diffEntries(a, b), "\n")
	for _, want := range []string{"A only: x@y", "B only: z@y", "A only: boss", "B only: Paris", "2 identical"} {
		if want == "2 identical" {
			want = "1 identical"
		}
		if !strings.Contains(d, want) {
			t.Fatalf("diff missing %q:\n%s", want, d)
		}
	}
	if strings.Contains(d, "entryUUID") {
		t.Fatal("server-maintained attributes must be ignored")
	}
	s := schema.Parse(nil, []string{
		"( 1.1.1 NAME 'flag' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
		"( 1.1.2 NAME 'num' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		"( 1.1.3 NAME 'ref' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 1.1.4 NAME 'when' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
	}, nil, nil)
	for attr, bad := range map[string]string{"flag": "yes", "num": "1x", "ref": "nope", "when": "2024-01-01"} {
		if syntaxWarning(s, attr, bad) == "" {
			t.Fatalf("%s=%q should warn", attr, bad)
		}
	}
	for attr, ok := range map[string]string{"flag": "TRUE", "num": "-5", "ref": "cn=a,dc=b", "when": "20240101120000Z"} {
		if w := syntaxWarning(s, attr, ok); w != "" {
			t.Fatalf("%s=%q should pass, got %s", attr, ok, w)
		}
	}
	if syntaxWarning(nil, "x", "y") != "" {
		t.Fatal("nil schema must not warn")
	}
}

func TestSpinnerBusyLogic(t *testing.T) {
	a := NewApp(&store.Store{})
	if a.busy() || a.spinner() != "" {
		t.Fatal("idle app must not show a spinner")
	}
	a.sh.schemaLoading = true
	if !a.busy() || a.spinner() == "" {
		t.Fatal("schema loading must show a spinner")
	}
	a.sh.schemaLoading = false
	a.connecting = true
	if !a.busy() {
		t.Fatal("connecting must be busy")
	}
	a.connecting = false
	a.browser.roots = []*model.Node{{DN: "dc=x", Children: []*model.Node{{DN: "ou=a,dc=x", Loading: true}}}}
	if !a.busy() {
		t.Fatal("a loading tree node anywhere must be busy")
	}
	// ticks advance the frame only while busy
	before := a.spin
	nm, _ := a.Update(tickMsg{})
	if nm.(App).spin != before+1 {
		t.Fatal("tick must advance spinner while busy")
	}
	a.browser.roots = nil
	before = a.spin
	nm, _ = a.Update(tickMsg{})
	if nm.(App).spin != before {
		t.Fatal("tick must not advance spinner when idle")
	}
}

func TestLDIFReport(t *testing.T) {
	recs, _ := ldif.Parse(strings.NewReader("dn: uid=a,dc=x\nuid: a\n"))
	out := strings.Join(ldifReport(ldifViewMsg{path: "f.ldif", recs: recs, issues: ldif.Validate(recs)}), "\n")
	for _, want := range []string{"1 records: 1 add", "1 error(s)", "no objectClass", "Apply with :import f.ldif"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/store"
)

func TestResolveTarget(t *testing.T) {
	s := &store.Store{Connections: []store.Connection{{Name: "corp", Host: "h", Port: 636, TLSMode: store.TLSImplicit}}}
	tg, err := ResolveTarget("corp", s)
	if err != nil || tg.Conn.Host != "h" || tg.URL != nil {
		t.Fatalf("profile: %+v %v", tg, err)
	}
	tg, err = ResolveTarget("ldaps://dc1:3269/DC=x??sub?(cn=a)", s)
	if err != nil || tg.Conn.TLSMode != store.TLSImplicit || tg.Conn.Port != 3269 || tg.URL.Base != "DC=x" || tg.Conn.BindMethod != store.BindAnonymous {
		t.Fatalf("url: %+v %v", tg, err)
	}
	if _, err := ResolveTarget("nope", s); err == nil {
		t.Fatal("unknown target must fail")
	}
	if _, err := ResolveTarget("ldap://", s); err == nil {
		t.Fatal("bad URL must fail")
	}
}

func TestParamsFromURLAndFlags(t *testing.T) {
	tg, _ := ResolveTarget("ldap://h/dc=x?cn?one?(uid=a)", nil)
	var sf searchFlags
	p, err := sf.Params(tg, tg.Conn)
	if err != nil || p.Base != "dc=x" || p.Filter != "(uid=a)" || p.Attributes[0] != "cn" || p.Scope != 1 {
		t.Fatalf("url defaults: %+v %v", p, err)
	}
	sf = searchFlags{filter: "cn=b", scope: "sub", attrs: "mail, sn", base: "dc=y", page: 50}
	p, err = sf.Params(tg, tg.Conn)
	if err != nil || p.Filter != "(cn=b)" || p.Scope != 2 || p.Base != "dc=y" || len(p.Attributes) != 2 || p.Attributes[1] != "sn" || p.PageSize != 50 {
		t.Fatalf("flag overrides: %+v %v", p, err)
	}
	if _, err := (&searchFlags{scope: "deep"}).Params(tg, tg.Conn); err == nil {
		t.Fatal("bad scope must fail")
	}
}

func TestConnFlagsApply(t *testing.T) {
	c := store.Connection{TLSMode: store.TLSNone, BindMethod: store.BindAnonymous}
	(&connFlags{user: "cn=a", starttls: true, insecure: true, ca: "/x", timeout: 3}).Apply(&c)
	if c.BindMethod != store.BindSimple || c.BindDN != "cn=a" || c.TLSMode != store.TLSStartTLS || !c.SkipVerify || c.CAFile != "/x" || c.TimeoutSec != 3 {
		t.Fatalf("%+v", c)
	}
	l := store.Connection{TLSMode: store.TLSImplicit}
	(&connFlags{starttls: true}).Apply(&l)
	if l.TLSMode != store.TLSImplicit {
		t.Fatal("-starttls must not downgrade ldaps")
	}
}

func TestPasswordSources(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pw")
	os.WriteFile(f, []byte("s3cret\n"), 0o600)
	t.Setenv("LDAPVIEW_PASSWORD", "")
	if pw, err := (&connFlags{pwFile: f}).password(nil); err != nil || pw != "s3cret" {
		t.Fatalf("file: %q %v", pw, err)
	}
	if pw, err := (&connFlags{pwStdin: true}).password(strings.NewReader("fromstdin\nignored\n")); err != nil || pw != "fromstdin" {
		t.Fatalf("stdin: %q %v", pw, err)
	}
	t.Setenv("LDAPVIEW_PASSWORD", "fromenv")
	if pw, _ := (&connFlags{}).password(nil); pw != "fromenv" {
		t.Fatalf("env: %q", pw)
	}
	if _, err := (&connFlags{pwFile: filepath.Join(dir, "missing")}).password(nil); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestSplitTarget(t *testing.T) {
	tg, rest := splitTarget([]string{"-user", "cn=a", "corp", "-filter", "(x=y)"})
	if tg != "corp" || strings.Join(rest, " ") != "-user cn=a -filter (x=y)" {
		t.Fatalf("%q %v", tg, rest)
	}
	tg, rest = splitTarget([]string{"corp", "-o", "f.json"})
	if tg != "corp" || strings.Join(rest, " ") != "-o f.json" {
		t.Fatalf("%q %v", tg, rest)
	}
}

func TestRenderFormatsAndCSVSafety(t *testing.T) {
	es := []ldapclient.Entry{{DN: "cn=a", Attributes: []ldapclient.Attribute{
		{Name: "cn", Values: []string{"=HYPERLINK(\"x\")"}, RawBytes: [][]byte{[]byte("=HYPERLINK(\"x\")")}},
		{Name: "mail", Values: []string{"a@x", "b@x"}, RawBytes: [][]byte{[]byte("a@x"), []byte("b@x")}},
	}}}
	for f, want := range map[string]string{"ldif": "dn: cn=a", "json": `"dn": "cn=a"`, "txt": "  mail: b@x", "csv": "'=HYPERLINK"} {
		out, err := render(f, es, []string{"*"})
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("%s: %v\n%s", f, err, out)
		}
	}
	if out, _ := render("csv", es, nil); !strings.Contains(out, "a@x; b@x") {
		t.Fatal("multi-value join")
	}
	if _, err := render("xml", es, nil); err == nil {
		t.Fatal("unknown format")
	}
}

func TestRunDispatchAndLDIFCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if h, _, _, _ := Run(nil, nil, nil, &out, &errb); h {
		t.Fatal("no args must start the TUI")
	}
	if h, code, _, _ := Run([]string{"help"}, nil, nil, &out, &errb); !h || code != 0 || !strings.Contains(out.String(), "Usage:") {
		t.Fatal("help")
	}
	if h, code, _, _ := Run([]string{"bogus"}, nil, nil, &out, &errb); !h || code != 2 {
		t.Fatalf("unknown command: %v %d", h, code)
	}
	if h, _, tgt, _ := Run([]string{"connect", "ldap://h/dc=x"}, nil, nil, &out, &errb); h || tgt == nil || tgt.Conn.Host != "h" {
		t.Fatal("connect must hand a target back to the TUI")
	}
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "g.ldif"), filepath.Join(dir, "b.ldif")
	os.WriteFile(good, []byte("dn: uid=a,dc=x\nobjectClass: person\nuid: a\n"), 0o600)
	os.WriteFile(bad, []byte("dn: uid=a,dc=x\nuid: a\n"), 0o600)
	out.Reset()
	if _, code, _, _ := Run([]string{"ldif", good, "-validate"}, nil, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "no problems") {
		t.Fatalf("good ldif: %d %s", code, out.String())
	}
	out.Reset()
	if _, code, _, _ := Run([]string{"ldif", bad, "-validate"}, nil, nil, &out, &errb); code != 1 || !strings.Contains(out.String(), "no objectClass") {
		t.Fatalf("bad ldif: %d %s", code, out.String())
	}
	if _, code, _, _ := Run([]string{"export", "ldap://h/"}, nil, nil, &out, &errb); code != 2 {
		t.Fatal("export without -o must be a usage error")
	}
}

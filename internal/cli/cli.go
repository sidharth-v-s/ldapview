// Package cli implements ldapview's small non-interactive commands
// (search, export, ldif, connect). It keeps the tool scriptable without
// turning it into a scanner: every command performs exactly one search or
// file operation the user asked for.
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldapurl"
	"github.com/zoro/ldapview/internal/ldif"
	"github.com/zoro/ldapview/internal/store"
)

// Usage is printed by `ldapview help`.
const Usage = `ldapview — terminal LDAP browser

Usage:
  ldapview                                   interactive TUI (saved connections)
  ldapview connect <profile|ldap-url> [flags]  interactive TUI, connected to a target
  ldapview search  <profile|ldap-url> [flags]  run one search, print results
  ldapview export  <profile|ldap-url> -o FILE  run one search, write FILE (.ldif .json .csv .txt)
  ldapview ldif    <file.ldif> [flags]         offline LDIF viewer / validator / converter
  ldapview help

Targets:
  a saved profile name, or an LDAP URL:
    ldap://host[:port]/base?attrs?scope?filter

Connection flags (connect, search, export):
  -user DN            simple bind DN (default: anonymous bind)
  -starttls           upgrade ldap:// with StartTLS
  -ca FILE            extra trusted CA bundle (PEM)
  -insecure           skip TLS certificate verification (unsafe)
  -timeout SECONDS    connect timeout (default 10)

Passwords are NEVER accepted as arguments (they leak via the process list).
Provide one via: environment LDAPVIEW_PASSWORD, -password-file FILE, or -password-stdin.

Search flags (search, export):
  -base DN  -scope base|one|sub  -filter F  -attrs a,b,c  -limit N  -page N
  -format ldif|json|csv|txt   (search only; default ldif)
  -o FILE                     (export; file created with mode 0600)

ldif flags:
  -validate           only validate; exit 1 on errors
  -format ldif|json|txt   convert and print (default: summary + validation)
`

// Target is what a connect/search/export invocation points at.
type Target struct {
	Conn store.Connection
	URL  *ldapurl.URL
}

// ResolveTarget resolves a profile name or an LDAP URL into a connection.
func ResolveTarget(arg string, s *store.Store) (Target, error) {
	if ldapurl.Is(arg) {
		u, err := ldapurl.Parse(arg)
		if err != nil {
			return Target{}, err
		}
		c := store.Connection{Name: u.Host, Host: u.Host, Port: u.DefaultPort(), TLSMode: store.TLSNone, BindMethod: store.BindAnonymous, TimeoutSec: 10}
		if u.Scheme == "ldaps" {
			c.TLSMode = store.TLSImplicit
		}
		return Target{Conn: c, URL: &u}, nil
	}
	if s != nil {
		for _, c := range s.Connections {
			if c.Name == arg {
				return Target{Conn: c}, nil
			}
		}
	}
	return Target{}, fmt.Errorf("no saved connection or LDAP URL matches %q", arg)
}

// connFlags are shared by connect/search/export.
type connFlags struct {
	user, ca, pwFile   string
	starttls, insecure bool
	pwStdin            bool
	timeout            int
}

func (cf *connFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&cf.user, "user", "", "simple bind DN")
	fs.StringVar(&cf.ca, "ca", "", "CA bundle (PEM)")
	fs.BoolVar(&cf.starttls, "starttls", false, "use StartTLS")
	fs.BoolVar(&cf.insecure, "insecure", false, "skip TLS verification (unsafe)")
	fs.StringVar(&cf.pwFile, "password-file", "", "read the bind password from FILE")
	fs.BoolVar(&cf.pwStdin, "password-stdin", false, "read the bind password from stdin")
	fs.IntVar(&cf.timeout, "timeout", 0, "connect timeout in seconds")
}

// Apply overlays flag values onto a resolved target's connection.
func (cf *connFlags) Apply(c *store.Connection) {
	if cf.user != "" {
		c.BindMethod, c.BindDN = store.BindSimple, cf.user
	}
	if cf.starttls && c.TLSMode == store.TLSNone {
		c.TLSMode = store.TLSStartTLS
	}
	if cf.ca != "" {
		c.CAFile = cf.ca
	}
	if cf.insecure {
		c.SkipVerify = true
	}
	if cf.timeout > 0 {
		c.TimeoutSec = cf.timeout
	}
}

func (cf *connFlags) password(stdin io.Reader) (string, error) {
	n := 0
	for _, b := range []bool{cf.pwFile != "", cf.pwStdin, os.Getenv("LDAPVIEW_PASSWORD") != ""} {
		if b {
			n++
		}
	}
	switch {
	case cf.pwFile != "":
		st, err := os.Stat(cf.pwFile)
		if err != nil {
			return "", err
		}
		if st.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "warning: %s is readable by other users (mode %o); chmod 600 it\n", cf.pwFile, st.Mode().Perm())
		}
		b, err := os.ReadFile(cf.pwFile)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	case cf.pwStdin:
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading password from stdin: %v", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	default:
		return os.Getenv("LDAPVIEW_PASSWORD"), nil
	}
}

// Dial connects and binds according to the resolved connection.
func Dial(c store.Connection, password string, stderr io.Writer) (*ldapclient.Client, error) {
	if c.TLSMode == store.TLSNone && c.BindMethod != store.BindAnonymous {
		fmt.Fprintln(stderr, "warning: simple bind over plaintext LDAP sends the password unencrypted (use ldaps:// or -starttls)")
	}
	if c.SkipVerify {
		fmt.Fprintln(stderr, "warning: TLS certificate verification is disabled")
	}
	cl, err := ldapclient.Connect(c)
	if err != nil {
		return nil, err
	}
	if c.BindMethod != store.BindAnonymous && password == "" && c.BindMethod == store.BindSimple {
		cl.Close()
		return nil, fmt.Errorf("a bind password is required: set LDAPVIEW_PASSWORD, or use -password-file / -password-stdin")
	}
	if err := cl.Bind(password); err != nil {
		cl.Close()
		return nil, fmt.Errorf("bind: %s", friendly(err))
	}
	_, _ = cl.FetchRootDSE()
	return cl, nil
}

func friendly(err error) string {
	if fe, ok := err.(*ldapclient.FriendlyError); ok {
		return fe.Message
	}
	return err.Error()
}

// searchFlags are shared by search/export.
type searchFlags struct {
	base, scope, filter, attrs string
	limit, page                int
	format, out                string
}

func (sf *searchFlags) register(fs *flag.FlagSet, export bool) {
	fs.StringVar(&sf.base, "base", "", "search base DN")
	fs.StringVar(&sf.scope, "scope", "", "base|one|sub")
	fs.StringVar(&sf.filter, "filter", "", "LDAP filter")
	fs.StringVar(&sf.attrs, "attrs", "", "comma separated attributes")
	fs.IntVar(&sf.limit, "limit", 0, "maximum entries to return (0 = all)")
	fs.IntVar(&sf.page, "page", 500, "page size for paged results")
	if export {
		fs.StringVar(&sf.out, "o", "", "output file (.ldif .json .csv .txt)")
	} else {
		fs.StringVar(&sf.format, "format", "ldif", "ldif|json|csv|txt")
	}
}

// Params builds search parameters, with URL fields as defaults.
func (sf *searchFlags) Params(t Target, conf store.Connection) (ldapclient.SearchParams, error) {
	p := ldapclient.SearchParams{Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)", Attributes: []string{"*"}, TimeLimit: conf.TimeLimit}
	scope := "sub"
	if t.URL != nil {
		p.Base, p.Filter, scope = t.URL.Base, t.URL.Filter, t.URL.Scope
		if len(t.URL.Attrs) > 0 {
			p.Attributes = t.URL.Attrs
		}
	}
	if sf.base != "" {
		p.Base = sf.base
	}
	if sf.filter != "" {
		p.Filter = sf.filter
	}
	if sf.scope != "" {
		scope = sf.scope
	}
	if sf.attrs != "" {
		p.Attributes = nil
		for _, a := range strings.Split(sf.attrs, ",") {
			if a = strings.TrimSpace(a); a != "" {
				p.Attributes = append(p.Attributes, a)
			}
		}
	}
	switch scope {
	case "base":
		p.Scope = ldap.ScopeBaseObject
	case "one":
		p.Scope = ldap.ScopeSingleLevel
	case "sub":
		p.Scope = ldap.ScopeWholeSubtree
	default:
		return p, fmt.Errorf("bad scope %q (want base, one or sub)", scope)
	}
	if !strings.HasPrefix(p.Filter, "(") {
		p.Filter = "(" + p.Filter + ")"
	}
	if sf.page > 0 {
		p.PageSize = uint32(sf.page)
	}
	return p, nil
}

// Collect runs the search, following paging cookies until exhausted or the
// limit is reached. A size/time limit yields partial results plus a note.
func Collect(cl *ldapclient.Client, p ldapclient.SearchParams, limit int, stderr io.Writer) ([]ldapclient.Entry, error) {
	var all []ldapclient.Entry
	for {
		out, err := cl.SearchEx(p)
		if err != nil {
			return all, err
		}
		all = append(all, out.Entries...)
		if out.Limit != nil {
			fmt.Fprintf(stderr, "note: %s — results are partial\n", out.Limit.Message)
			return all, nil
		}
		if len(out.Referrals) > 0 {
			fmt.Fprintf(stderr, "note: %d referral(s) not followed (never followed automatically)\n", len(out.Referrals))
		}
		if limit > 0 && len(all) >= limit {
			return all[:limit], nil
		}
		if len(out.NextCookie) == 0 {
			return all, nil
		}
		p.Cookie = out.NextCookie
	}
}

// Run executes a CLI command. handled=false means "no subcommand — start
// the interactive TUI normally". For "connect", handled=false and target is
// returned so the caller can start the TUI pre-connected.
func Run(args []string, s *store.Store, stdin io.Reader, stdout, stderr io.Writer) (handled bool, exit int, target *Target, password string) {
	if len(args) == 0 {
		return false, 0, nil, ""
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, Usage)
		return true, 0, nil, ""
	case "ldif":
		return true, runLDIF(rest, stdout, stderr), nil, ""
	case "search", "export":
		return true, runSearch(cmd, rest, s, stdin, stdout, stderr), nil, ""
	case "connect":
		t, pw, code := parseConnect(rest, s, stdin, stderr)
		if code != 0 {
			return true, code, nil, ""
		}
		return false, 0, t, pw
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, Usage)
	return true, 2, nil, ""
}

func splitTarget(args []string) (string, []string) {
	// allow the target before or after flags
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			// but not the value of a preceding flag that takes one
			if i > 0 && flagTakesValue(args[i-1]) {
				continue
			}
			return a, append(append([]string{}, args[:i]...), args[i+1:]...)
		}
	}
	return "", args
}

func flagTakesValue(a string) bool {
	if strings.Contains(a, "=") {
		return false
	}
	switch strings.TrimLeft(a, "-") {
	case "user", "ca", "password-file", "timeout", "base", "scope", "filter", "attrs", "limit", "page", "format", "o":
		return true
	}
	return false
}

func parseConnect(args []string, s *store.Store, stdin io.Reader, stderr io.Writer) (*Target, string, int) {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf connFlags
	cf.register(fs)
	tgt, rest := splitTarget(args)
	if err := fs.Parse(rest); err != nil {
		return nil, "", 2
	}
	if tgt == "" {
		fmt.Fprintln(stderr, "connect: missing target (profile name or LDAP URL)")
		return nil, "", 2
	}
	t, err := ResolveTarget(tgt, s)
	if err != nil {
		fmt.Fprintln(stderr, "connect:", err)
		return nil, "", 2
	}
	cf.Apply(&t.Conn)
	pw := ""
	if cf.pwFile != "" || cf.pwStdin || os.Getenv("LDAPVIEW_PASSWORD") != "" {
		if pw, err = cf.password(stdin); err != nil {
			fmt.Fprintln(stderr, "connect:", err)
			return nil, "", 1
		}
	}
	return &t, pw, 0
}

func runSearch(cmd string, args []string, s *store.Store, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf connFlags
	var sf searchFlags
	cf.register(fs)
	sf.register(fs, cmd == "export")
	tgt, rest := splitTarget(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if tgt == "" {
		fmt.Fprintf(stderr, "%s: missing target (profile name or LDAP URL)\n", cmd)
		return 2
	}
	t, err := ResolveTarget(tgt, s)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 2
	}
	cf.Apply(&t.Conn)
	if cmd == "export" && sf.out == "" {
		fmt.Fprintln(stderr, "export: -o FILE is required")
		return 2
	}
	params, err := sf.Params(t, t.Conn)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 2
	}
	pw := ""
	if t.Conn.BindMethod != store.BindAnonymous || cf.pwFile != "" || cf.pwStdin {
		if pw, err = cf.password(stdin); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
			return 1
		}
	}
	cl, err := Dial(t.Conn, pw, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return 1
	}
	defer cl.Close()
	start := time.Now()
	entries, err := Collect(cl, params, sf.limit, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s: search failed: %s\n", cmd, friendly(err))
		return 1
	}
	if cmd == "export" {
		msg, err := writeFile(sf.out, entries, params.Attributes)
		if err != nil {
			fmt.Fprintf(stderr, "export: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "%s (%.1fs)\n", msg, time.Since(start).Seconds())
		return 0
	}
	data, err := render(sf.format, entries, params.Attributes)
	if err != nil {
		fmt.Fprintf(stderr, "search: %v\n", err)
		return 2
	}
	fmt.Fprint(stdout, data)
	fmt.Fprintf(stderr, "%d entries (%.1fs)\n", len(entries), time.Since(start).Seconds())
	return 0
}

func runLDIF(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ldif", flag.ContinueOnError)
	fs.SetOutput(stderr)
	validate := fs.Bool("validate", false, "only validate")
	format := fs.String("format", "", "ldif|json|txt")
	file, rest := splitTarget(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if file == "" {
		fmt.Fprintln(stderr, "ldif: missing file")
		return 2
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(stderr, "ldif:", err)
		return 1
	}
	defer f.Close()
	recs, err := ldif.Parse(f)
	if err != nil {
		fmt.Fprintln(stderr, "ldif: parse error:", err)
		return 1
	}
	issues := ldif.Validate(recs)
	errs := 0
	for _, i := range issues {
		if i.Severity == "error" {
			errs++
		}
	}
	if *format != "" && !*validate {
		return printRecords(*format, recs, stdout, stderr, errs)
	}
	sum := ldif.Summary(recs)
	fmt.Fprintf(stdout, "%s: %d records — %d add, %d modify, %d delete, %d rename/move\n", file, len(recs), sum["add"], sum["modify"], sum["delete"], sum["modrdn"])
	for _, i := range issues {
		fmt.Fprintln(stdout, "  "+i.String())
	}
	if len(issues) == 0 {
		fmt.Fprintln(stdout, "  no problems found")
	}
	if errs > 0 {
		fmt.Fprintf(stdout, "%d error(s), %d warning(s)\n", errs, len(issues)-errs)
		return 1
	}
	return 0
}

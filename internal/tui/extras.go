package tui

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/dn"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/schema"
)

var volatileAttrs = map[string]bool{
	"entryuuid": true, "entrycsn": true, "createtimestamp": true, "modifytimestamp": true, "creatorsname": true,
	"modifiersname": true, "entrydn": true, "usncreated": true, "usnchanged": true, "whencreated": true,
	"whenchanged": true, "objectguid": true, "objectsid": true, "dscorepropagationdata": true,
	"distinguishedname": true, "hassubordinates": true,
}

func valueSet(e ldapclient.Entry, attr string) []string {
	var out []string
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, attr) {
			if a.Binary {
				for _, b := range a.RawBytes {
					out = append(out, fmt.Sprintf("<binary %d bytes %x>", len(b), b[:min(len(b), 8)]))
				}
			} else {
				out = append(out, a.Values...)
			}
		}
	}
	sort.Strings(out)
	return out
}

func setDiff(a, b []string) (onlyA, onlyB []string) {
	inB, inA := map[string]bool{}, map[string]bool{}
	for _, x := range b {
		inB[x] = true
	}
	for _, x := range a {
		inA[x] = true
		if !inB[x] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !inA[x] {
			onlyB = append(onlyB, x)
		}
	}
	return
}

// diffEntries compares two entries attribute by attribute, ignoring
// server-maintained values that always differ.
func diffEntries(a, b ldapclient.Entry) []string {
	names := map[string]string{}
	for _, e := range []ldapclient.Entry{a, b} {
		for _, at := range e.Attributes {
			if !volatileAttrs[strings.ToLower(at.Name)] {
				names[strings.ToLower(at.Name)] = at.Name
			}
		}
	}
	var keys []string
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []string{"A: " + a.DN, "B: " + b.DN, ""}
	same, differ := 0, 0
	for _, k := range keys {
		va, vb := valueSet(a, k), valueSet(b, k)
		oa, ob := setDiff(va, vb)
		if len(oa) == 0 && len(ob) == 0 {
			same++
			continue
		}
		differ++
		out = append(out, names[k])
		for _, v := range oa {
			out = append(out, "  A only: "+v)
		}
		for _, v := range ob {
			out = append(out, "  B only: "+v)
		}
	}
	out = append(out, "", fmt.Sprintf("%d attributes differ, %d identical (server-maintained attributes ignored)", differ, same))
	return out
}

var genTimeRe = regexp.MustCompile(`^\d{14}(\.\d+)?Z$`)

// syntaxWarning checks a value against the attribute's schema syntax.
func syntaxWarning(s *schema.Schema, attr, val string) string {
	if s == nil {
		return ""
	}
	switch s.Effective(attr).Syntax {
	case "1.3.6.1.4.1.1466.115.121.1.7", "2.5.5.8":
		if val != "TRUE" && val != "FALSE" {
			return "note: " + attr + " is Boolean — expected TRUE or FALSE"
		}
	case "1.3.6.1.4.1.1466.115.121.1.27", "2.5.5.9", "1.2.840.113556.1.4.906":
		if _, err := strconv.ParseInt(val, 10, 64); err != nil {
			return "note: " + attr + " is an Integer — " + strconv.Quote(val) + " is not a number"
		}
	case "1.3.6.1.4.1.1466.115.121.1.12", "2.5.5.1":
		if !dn.Valid(val) {
			return "note: " + attr + " holds a DN — value does not parse as one"
		}
	case "1.3.6.1.4.1.1466.115.121.1.24":
		if !genTimeRe.MatchString(val) {
			return "note: " + attr + " is a Generalized Time — expected YYYYMMDDHHMMSSZ"
		}
	}
	return ""
}

// lookupBinaryCmd finds the DN of the object whose binary attribute matches.
func lookupBinaryCmd(sh *shared, attr string, raw []byte, label string) tea.Cmd {
	c := sh.client
	return func() tea.Msg {
		d := c.DSE()
		if d == nil {
			return statusMsg{text: "Root DSE unavailable", isErr: true}
		}
		base := d.DefaultNamingContext
		if base == "" && len(d.NamingContexts) > 0 {
			base = d.NamingContexts[0]
		}
		out, err := c.SearchEx(ldapclient.SearchParams{
			Base: base, Scope: ldap.ScopeWholeSubtree, Filter: "(" + attr + "=" + ldapclient.EscapeBinaryFilter(raw) + ")",
			Attributes: []string{"1.1"}, SizeLimit: 2, TimeLimit: 15,
		})
		if err != nil {
			return statusMsg{text: label + ": " + friendlyErr(err), isErr: true}
		}
		if len(out.Entries) == 0 {
			return statusMsg{text: "no object with " + label + " under " + base, isErr: true}
		}
		return gotoMsg{dn: out.Entries[0].DN}
	}
}

// secInfoMsg carries the result of the security-visibility probe.
type secInfoMsg struct {
	anon   ldapclient.AnonBindResult
	server ldapclient.ServerGuess
	d      *ldapclient.RootDSE
}

func probeSecInfoCmd(sh *shared) tea.Cmd {
	conf := sh.conf
	c := sh.client
	return func() tea.Msg {
		anon := ldapclient.ProbeAnonymousBind(conf)
		d := c.DSE()
		return secInfoMsg{anon: anon, server: ldapclient.DetectServer(d), d: d}
	}
}

func secInfoLines(m secInfoMsg) []string {
	yn := func(b bool) string {
		if b {
			return "allowed"
		}
		return "denied"
	}
	lines := []string{
		"Anonymous bind:",
		"  " + yn(m.anon.Allowed) + "  (" + m.anon.Detail + ")",
		"",
		"Server type (non-authoritative):",
		fmt.Sprintf("  %s  (confidence: %s)", m.server.Name, m.server.Confidence),
	}
	if m.d == nil {
		lines = append(lines, "", "Root DSE unavailable — TLS/SASL/control visibility limited.")
		return lines
	}
	lines = append(lines, "",
		"TLS:",
		"  advertised via connection profile only (LDAP has no standard Root DSE flag for this)",
		"",
		"StartTLS:",
		"  "+yn(hasExt(m.d, "1.3.6.1.4.1.1466.20037")),
		"",
		fmt.Sprintf("SASL mechanisms advertised (%d):", len(m.d.SupportedSASLMechanisms)),
	)
	for _, s := range m.d.SupportedSASLMechanisms {
		lines = append(lines, "  "+s)
	}
	lines = append(lines, "", fmt.Sprintf("LDAP versions: %s", strings.Join(m.d.SupportedLDAPVersion, ", ")))
	lines = append(lines, "", fmt.Sprintf("Server controls (%d):", len(m.d.SupportedControl)))
	for _, o := range m.d.SupportedControl {
		lines = append(lines, "  "+o)
	}
	lines = append(lines, "", fmt.Sprintf("Server extensions (%d):", len(m.d.SupportedExtension)))
	for _, o := range m.d.SupportedExtension {
		lines = append(lines, "  "+o)
	}
	lines = append(lines, "", "Naming contexts:")
	for _, n := range m.d.NamingContexts {
		lines = append(lines, "  "+n)
	}
	lines = append(lines, "", "Interesting schema note: run :schema to browse object classes and attributes directly.")
	return lines
}

func hasExt(d *ldapclient.RootDSE, o string) bool {
	for _, x := range d.SupportedExtension {
		if x == o {
			return true
		}
	}
	return false
}

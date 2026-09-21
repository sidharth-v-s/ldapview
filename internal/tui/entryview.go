package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zoro/ldapview/internal/ad"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
	"github.com/zoro/ldapview/internal/schema"
)

const dnSyntax = "1.3.6.1.4.1.1466.115.121.1.12"

var staticRefAttrs = map[string]bool{
	"member": true, "uniquemember": true, "memberof": true, "manager": true, "directreports": true,
	"seealso": true, "owner": true, "managedby": true, "roleoccupant": true, "secretary": true,
	"msds-managedby": true, "distinguishedname": false,
}

func parseSD(raw []byte) (*ad.SD, error) { return ad.ParseSD(raw) }

func friendlyErr(err error) string {
	if fe, ok := err.(*ldapclient.FriendlyError); ok {
		return fe.Message
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// binarySummary decodes well-known binary attributes, else shows the length.
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
	case "ntsecuritydescriptor":
		return fmt.Sprintf("<security descriptor, %d bytes> (A: decode)", len(b))
	}
	return fmt.Sprintf("<binary %d bytes> (enter: hex/base64)", len(b))
}

func (m *browserModel) rebuild() {
	m.lines = nil
	if m.entry == nil {
		return
	}
	switch m.mode {
	case modeAttrs:
		m.buildAttrs()
	case modeLDIF:
		for _, l := range strings.Split(strings.TrimRight(ldif.EntryString(toLDIFEntry(*m.entry)), "\n"), "\n") {
			m.lines = append(m.lines, eline{text: l, sel: true, val: l})
		}
	case modeRaw:
		m.buildRaw()
	case modeRel:
		m.buildRel()
	case modeSchema:
		m.buildSchema()
	case modeSec:
		if len(m.sdLines) == 0 {
			m.lines = []eline{{text: "press A to read the security descriptor (Active Directory only)", sel: true}}
		}
		for _, l := range m.sdLines {
			m.lines = append(m.lines, eline{text: l, sel: true, val: l})
		}
	}
	if m.ecur >= len(m.lines) {
		m.ecur = max(len(m.lines)-1, 0)
	}
	if len(m.lines) > 0 && !m.lines[m.ecur].sel {
		m.ecur = firstSel(m.lines)
	}
	m.snapEntry()
}

func attrFlags(s *schema.Schema, name string) string {
	if s == nil {
		return ""
	}
	at := s.Attr(name)
	if at == nil {
		return ""
	}
	var f []string
	if at.SingleValue {
		f = append(f, "single-valued")
	}
	if at.NoUserMod {
		f = append(f, "read-only")
	}
	if at.Usage != "" && at.Usage != "userApplications" {
		f = append(f, "operational")
	}
	if len(f) == 0 {
		return ""
	}
	return "  [" + strings.Join(f, ", ") + "]"
}

func (m *browserModel) buildAttrs() {
	now := time.Now()
	for _, a := range m.entry.Attributes {
		m.lines = append(m.lines, eline{text: a.Name + attrFlags(m.sh.schema, a.Name), head: true, attr: a.Name})
		if a.Binary {
			for _, b := range a.RawBytes {
				disp := binarySummary(a.Name, b)
				anno := ""
				if strings.EqualFold(a.Name, "objectSid") {
					anno = ad.SIDName(disp)
				}
				m.lines = append(m.lines, eline{text: disp, sel: true, attr: a.Name, raw: b, bin: true, anno: anno, val: disp})
			}
			continue
		}
		for _, v := range a.Values {
			m.lines = append(m.lines, eline{text: v, sel: true, attr: a.Name, val: v, anno: ad.Annotate(a.Name, v, now)})
		}
	}
}

func (m *browserModel) buildRaw() {
	for _, a := range m.entry.Attributes {
		for i, b := range a.RawBytes {
			var txt string
			if a.Binary {
				h := fmt.Sprintf("%x", b)
				if len(h) > 64 {
					h = h[:64] + "…"
				}
				txt = fmt.Sprintf("%s[%d]  binary %d bytes  0x%s", a.Name, i, len(b), h)
			} else {
				txt = fmt.Sprintf("%s[%d]  %d bytes  %q", a.Name, i, len(b), string(b))
			}
			m.lines = append(m.lines, eline{text: txt, sel: true, val: string(b)})
		}
	}
}

func (m *browserModel) buildRel() {
	s := m.sh.schema
	m.lines = append(m.lines, eline{text: "Outgoing references (this entry → other entries)", head: true})
	found := false
	for _, a := range m.entry.Attributes {
		if a.Binary {
			continue
		}
		isRef := staticRefAttrs[strings.ToLower(a.Name)]
		if !isRef && s != nil {
			isRef = s.Effective(a.Name).Syntax == dnSyntax
		}
		if !isRef || strings.EqualFold(a.Name, "entryDN") || IsSelfRef(a.Name) {
			continue
		}
		found = true
		m.lines = append(m.lines, eline{text: fmt.Sprintf("%s (%d)", a.Name, len(a.Values)), head: true, attr: a.Name})
		for _, v := range a.Values {
			m.lines = append(m.lines, eline{text: v, sel: true, dn: v, val: v})
		}
	}
	if !found {
		m.lines = append(m.lines, eline{text: "  none", head: false})
	}
	m.lines = append(m.lines, eline{text: "", head: false})
	m.lines = append(m.lines, eline{text: "Referenced by (member / uniqueMember / manager / owner / seeAlso / managedBy)", head: true})
	switch {
	case m.rel == nil:
		m.lines = append(m.lines, eline{text: "  loading…"})
	case m.rel.err != nil:
		m.lines = append(m.lines, eline{text: "  " + friendlyErr(m.rel.err)})
	case len(m.rel.reverse) == 0:
		m.lines = append(m.lines, eline{text: "  none found (searched the naming context, max 200)"})
	default:
		for _, d := range m.rel.reverse {
			m.lines = append(m.lines, eline{text: d, sel: true, dn: d, val: d})
		}
	}
}

// IsSelfRef excludes attributes that merely repeat the entry's own DN.
func IsSelfRef(name string) bool {
	switch strings.ToLower(name) {
	case "distinguishedname", "entrydn", "creatorsname", "modifiersname":
		return true
	}
	return false
}

func (m *browserModel) buildSchema() {
	s := m.sh.schema
	if s == nil {
		m.lines = []eline{{text: "loading schema…", sel: true}}
		return
	}
	classes := m.entry.Get("objectClass")
	if len(classes) == 0 {
		m.lines = []eline{{text: "entry has no objectClass values", sel: true}}
		return
	}
	add := func(t string) { m.lines = append(m.lines, eline{text: t, sel: true, val: t}) }
	var structural []string
	for _, c := range classes {
		if oc := s.Class(c); oc != nil {
			add(fmt.Sprintf("%s  (%s)  lineage: %s", oc.Name(), strings.ToLower(oc.Kind), strings.Join(s.Lineage(c), " → ")))
			if oc.Kind == "STRUCTURAL" {
				structural = append(structural, oc.Name())
			}
		} else {
			add(c + "  (not in schema)")
		}
	}
	must, may := s.Resolve(classes)
	present := map[string]bool{}
	for _, a := range m.entry.Attributes {
		present[strings.ToLower(s.CanonAttr(a.Name))] = true
	}
	add("")
	add("Required (MUST):")
	for _, a := range must {
		if present[strings.ToLower(a)] {
			add("  " + okStyle.Render("✓ ") + a)
		} else {
			add("  " + missStyle.Render("✗ ") + a + "   MISSING")
		}
	}
	add("")
	add("Allowed (MAY):")
	sort.Strings(may)
	for _, a := range may {
		if present[strings.ToLower(a)] {
			add("  " + okStyle.Render("✓ ") + a)
		} else {
			add("    " + a)
		}
	}
	allowed := map[string]bool{}
	for _, a := range append(append([]string{}, must...), may...) {
		allowed[strings.ToLower(a)] = true
	}
	var extra []string
	for _, a := range m.entry.Attributes {
		c := strings.ToLower(s.CanonAttr(a.Name))
		if allowed[c] || ldapclient.IsOperational(a.Name) {
			continue
		}
		if at := s.Attr(a.Name); at != nil && at.Usage != "" && at.Usage != "userApplications" {
			continue
		}
		extra = append(extra, a.Name)
	}
	if len(extra) > 0 {
		add("")
		add("Present but not allowed by any objectClass:")
		for _, a := range extra {
			add("  " + missStyle.Render("! ") + a)
		}
	}
}

func sdToLines(sd *ad.SD) []string {
	if sd == nil {
		return nil
	}
	name := func(sid, n string) string {
		if n != "" {
			return sid + "  (" + n + ")"
		}
		return sid
	}
	out := []string{
		"Owner: " + name(sd.Owner, sd.OwnerName),
		"Group: " + name(sd.Group, sd.GroupName),
		"Control: " + strings.Join(sd.Control, " | "),
		"",
		fmt.Sprintf("DACL (%d ACEs)", len(sd.DACL)),
	}
	for i, a := range sd.DACL {
		who := name(a.Trustee, a.TrusteeName)
		out = append(out, fmt.Sprintf("#%-3d %-13s %s", i+1, a.Type, who))
		out = append(out, fmt.Sprintf("      rights: %s  (0x%08x)", strings.Join(a.Rights, ", "), a.Mask))
		if a.ObjectType != "" {
			t := a.ObjectType
			if a.ObjectName != "" {
				t += "  (" + a.ObjectName + ")"
			}
			out = append(out, "      object: "+t)
		}
		if len(a.Flags) > 0 {
			out = append(out, "      flags:  "+strings.Join(a.Flags, " | "))
		}
	}
	return out
}

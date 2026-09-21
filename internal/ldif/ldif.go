// Package ldif reads and writes LDIF (RFC 2849) and exports entries as JSON.
package ldif

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// Attr is one attribute with raw byte values.
type Attr struct {
	Name   string
	Values [][]byte
}

// Entry is one directory entry.
type Entry struct {
	DN    string
	Attrs []Attr
}

func needsBase64(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	if v[0] == ' ' || v[0] == ':' || v[0] == '<' || v[len(v)-1] == ' ' {
		return true
	}
	for _, b := range v {
		if b == 0 || b == '\n' || b == '\r' || b >= 0x80 {
			return true
		}
	}
	return false
}

func writeLine(w io.Writer, s string) {
	first := true
	for {
		n := 76
		if !first {
			n = 75
			io.WriteString(w, " ")
		}
		if len(s) < n {
			n = len(s)
		}
		io.WriteString(w, s[:n])
		io.WriteString(w, "\n")
		s = s[n:]
		first = false
		if len(s) == 0 {
			break
		}
	}
}

func writeAttr(w io.Writer, name string, v []byte) {
	if needsBase64(v) {
		writeLine(w, name+":: "+base64.StdEncoding.EncodeToString(v))
	} else {
		writeLine(w, name+": "+string(v))
	}
}

// Write emits entries as LDIF content records (with a version header).
func Write(w io.Writer, entries []Entry) error {
	bw := bufio.NewWriter(w)
	io.WriteString(bw, "version: 1\n\n")
	for _, e := range entries {
		writeEntry(bw, e)
		io.WriteString(bw, "\n")
	}
	return bw.Flush()
}

func writeEntry(w io.Writer, e Entry) {
	writeAttr(w, "dn", []byte(e.DN))
	for _, a := range e.Attrs {
		for _, v := range a.Values {
			writeAttr(w, a.Name, v)
		}
	}
}

// String renders entries as an LDIF document.
func String(entries []Entry) string {
	var b bytes.Buffer
	_ = Write(&b, entries)
	return b.String()
}

// EntryString renders a single entry without the version header.
func EntryString(e Entry) string {
	var b bytes.Buffer
	writeEntry(&b, e)
	return b.String()
}

func printable(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if r < 0x20 && r != '\t' {
			return false
		}
	}
	return true
}

// ToJSON exports entries as a JSON array. Binary values become
// {"base64": "..."} objects.
func ToJSON(entries []Entry) ([]byte, error) {
	type jentry struct {
		DN    string                   `json:"dn"`
		Attrs map[string][]interface{} `json:"attributes"`
	}
	out := make([]jentry, 0, len(entries))
	for _, e := range entries {
		je := jentry{DN: e.DN, Attrs: map[string][]interface{}{}}
		for _, a := range e.Attrs {
			for _, v := range a.Values {
				if printable(v) {
					je.Attrs[a.Name] = append(je.Attrs[a.Name], string(v))
				} else {
					je.Attrs[a.Name] = append(je.Attrs[a.Name], map[string]string{"base64": base64.StdEncoding.EncodeToString(v)})
				}
			}
		}
		out = append(out, je)
	}
	return json.MarshalIndent(out, "", "  ")
}

// Mod is one modification inside a modify change record.
type Mod struct {
	Op     string // add | delete | replace
	Attr   string
	Values [][]byte
}

// Record is one parsed LDIF record (content or change record).
type Record struct {
	DN           string
	Change       string // add (also for content records), delete, modify, modrdn
	Attrs        []Attr
	Mods         []Mod
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
	Line         int
}

type line struct {
	key string
	val []byte
	no  int
}

func unfold(data string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(l, " ") && len(out) > 0 && out[len(out)-1] != "" {
			out[len(out)-1] += l[1:]
			continue
		}
		out = append(out, l)
	}
	return out
}

func splitLine(l string) (string, []byte, error) {
	i := strings.IndexByte(l, ':')
	if i <= 0 {
		return "", nil, fmt.Errorf("malformed line %q", trunc(l))
	}
	key, rest := l[:i], l[i+1:]
	switch {
	case strings.HasPrefix(rest, ":"):
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest[1:]))
		if err != nil {
			return "", nil, fmt.Errorf("bad base64 for %s: %v", key, err)
		}
		return key, dec, nil
	case strings.HasPrefix(rest, "<"):
		return "", nil, fmt.Errorf("URL values (%s:<) are not supported", key)
	}
	return key, []byte(strings.TrimLeft(rest, " ")), nil
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// Parse reads LDIF content and change records.
func Parse(r io.Reader) ([]Record, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	lines := unfold(string(data))
	var records []Record
	var block []line
	flush := func() error {
		if len(block) == 0 {
			return nil
		}
		rec, err := parseBlock(block)
		block = nil
		if err != nil {
			return err
		}
		if rec != nil {
			records = append(records, *rec)
		}
		return nil
	}
	for i, l := range lines {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.TrimSpace(l) == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if l == "-" {
			block = append(block, line{key: "-", no: i + 1})
			continue
		}
		k, v, err := splitLine(l)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		block = append(block, line{key: k, val: v, no: i + 1})
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return records, nil
}

func parseBlock(b []line) (*Record, error) {
	if strings.EqualFold(b[0].key, "version") {
		b = b[1:]
		if len(b) == 0 {
			return nil, nil
		}
	}
	if !strings.EqualFold(b[0].key, "dn") {
		return nil, fmt.Errorf("line %d: record must start with dn:", b[0].no)
	}
	rec := &Record{DN: string(b[0].val), Change: "add", Line: b[0].no}
	b = b[1:]
	for len(b) > 0 && strings.EqualFold(b[0].key, "control") {
		b = b[1:]
	}
	if len(b) > 0 && strings.EqualFold(b[0].key, "changetype") {
		rec.Change = strings.ToLower(string(b[0].val))
		if rec.Change == "moddn" {
			rec.Change = "modrdn"
		}
		b = b[1:]
	}
	switch rec.Change {
	case "add":
		idx := map[string]int{}
		for _, l := range b {
			k := strings.ToLower(l.key)
			if i, ok := idx[k]; ok {
				rec.Attrs[i].Values = append(rec.Attrs[i].Values, l.val)
			} else {
				idx[k] = len(rec.Attrs)
				rec.Attrs = append(rec.Attrs, Attr{Name: l.key, Values: [][]byte{l.val}})
			}
		}
	case "delete":
	case "modify":
		var cur *Mod
		for _, l := range b {
			k := strings.ToLower(l.key)
			switch {
			case k == "-":
				if cur != nil {
					rec.Mods = append(rec.Mods, *cur)
					cur = nil
				}
			case cur == nil && (k == "add" || k == "delete" || k == "replace"):
				cur = &Mod{Op: k, Attr: string(l.val)}
			case cur != nil:
				cur.Values = append(cur.Values, l.val)
			default:
				return nil, fmt.Errorf("line %d: unexpected %q in modify record", l.no, l.key)
			}
		}
		if cur != nil {
			rec.Mods = append(rec.Mods, *cur)
		}
	case "modrdn":
		for _, l := range b {
			switch strings.ToLower(l.key) {
			case "newrdn":
				rec.NewRDN = string(l.val)
			case "deleteoldrdn":
				rec.DeleteOldRDN = strings.TrimSpace(string(l.val)) == "1"
			case "newsuperior":
				rec.NewSuperior = string(l.val)
			}
		}
		if rec.NewRDN == "" {
			return nil, fmt.Errorf("line %d: modrdn record needs newrdn", rec.Line)
		}
	default:
		return nil, fmt.Errorf("line %d: unknown changetype %q", rec.Line, rec.Change)
	}
	return rec, nil
}

// SortAttrs orders attribute names alphabetically (stable, case-insensitive).
func SortAttrs(a []Attr) {
	sort.SliceStable(a, func(i, j int) bool { return strings.ToLower(a[i].Name) < strings.ToLower(a[j].Name) })
}

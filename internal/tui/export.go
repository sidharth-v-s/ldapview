package tui

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
)

func toLDIFEntry(e ldapclient.Entry) ldif.Entry {
	le := ldif.Entry{DN: e.DN}
	for _, a := range e.Attributes {
		la := ldif.Attr{Name: a.Name}
		if len(a.RawBytes) > 0 {
			la.Values = a.RawBytes
		} else {
			for _, v := range a.Values {
				la.Values = append(la.Values, []byte(v))
			}
		}
		le.Attrs = append(le.Attrs, la)
	}
	return le
}

func toLDIFEntries(es []ldapclient.Entry) []ldif.Entry {
	out := make([]ldif.Entry, len(es))
	for i, e := range es {
		out[i] = toLDIFEntry(e)
	}
	return out
}

func defaultExportName(prefix, ext string) string {
	return fmt.Sprintf("%s-%s.%s", prefix, time.Now().Format("20060102-150405"), ext)
}

// csvSafe neutralises spreadsheet formula injection from directory data.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvColumns(entries []ldapclient.Entry, want []string) []string {
	if len(want) > 0 && !(len(want) == 1 && want[0] == "*") {
		return want
	}
	seen := map[string]bool{}
	var cols []string
	for _, e := range entries {
		for _, a := range e.Attributes {
			if !a.Binary && !seen[strings.ToLower(a.Name)] && !ldapclient.IsOperational(a.Name) {
				seen[strings.ToLower(a.Name)] = true
				cols = append(cols, a.Name)
			}
		}
	}
	sort.Strings(cols)
	return cols
}

// writeExport writes entries to path; the extension selects the format
// (.json, .csv, otherwise LDIF). Files are created with 0600 permissions
// because directory data is sensitive.
func writeExport(path string, entries []ldapclient.Entry, columns []string) (string, error) {
	var data []byte
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		b, err := ldif.ToJSON(toLDIFEntries(entries))
		if err != nil {
			return "", err
		}
		data = b
	case ".csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		cols := csvColumns(entries, columns)
		_ = w.Write(append([]string{"dn"}, cols...))
		for _, e := range entries {
			row := []string{csvSafe(e.DN)}
			for _, c := range cols {
				row = append(row, csvSafe(strings.Join(e.Get(c), "; ")))
			}
			_ = w.Write(row)
		}
		w.Flush()
		data = []byte(sb.String())
	case ".txt":
		data = []byte(txtDump(entries))
	default:
		data = []byte(ldif.String(toLDIFEntries(entries)))
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d entries to %s", len(entries), path), nil
}

// txtDump renders entries as a plain, human-readable attribute dump —
// the spec's TXT export format, distinct from LDIF (no continuation
// folding or base64, no dn: prefix repetition style).
func txtDump(entries []ldapclient.Entry) string {
	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "DN: %s\n", e.DN)
		for _, a := range e.Attributes {
			if a.Binary {
				fmt.Fprintf(&b, "  %s: <binary, %d value(s)>\n", a.Name, len(a.RawBytes))
				continue
			}
			for _, v := range a.Values {
				fmt.Fprintf(&b, "  %s: %s\n", a.Name, v)
			}
		}
	}
	return b.String()
}

package cli

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/ldif"
)

func toLDIF(es []ldapclient.Entry) []ldif.Entry {
	out := make([]ldif.Entry, len(es))
	for i, e := range es {
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
		out[i] = le
	}
	return out
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func columns(es []ldapclient.Entry, want []string) []string {
	if len(want) > 0 && !(len(want) == 1 && (want[0] == "*" || want[0] == "+")) {
		return want
	}
	seen := map[string]bool{}
	var cols []string
	for _, e := range es {
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

func txt(es []ldapclient.Entry) string {
	var b strings.Builder
	for i, e := range es {
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

func render(format string, es []ldapclient.Entry, attrs []string) (string, error) {
	switch strings.ToLower(format) {
	case "", "ldif":
		return ldif.String(toLDIF(es)), nil
	case "json":
		b, err := ldif.ToJSON(toLDIF(es))
		return string(b) + "\n", err
	case "txt":
		return txt(es), nil
	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		cols := columns(es, attrs)
		_ = w.Write(append([]string{"dn"}, cols...))
		for _, e := range es {
			row := []string{csvSafe(e.DN)}
			for _, c := range cols {
				row = append(row, csvSafe(strings.Join(e.Get(c), "; ")))
			}
			_ = w.Write(row)
		}
		w.Flush()
		return sb.String(), nil
	}
	return "", fmt.Errorf("unknown format %q (want ldif, json, csv or txt)", format)
}

func writeFile(path string, es []ldapclient.Entry, attrs []string) (string, error) {
	format := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	if format == "" {
		format = "ldif"
	}
	data, err := render(format, es, attrs)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d entries to %s", len(es), path), nil
}

// printRecords converts parsed LDIF records: content records can be shown
// as ldif/json/txt; change records are shown as ldif only.
func printRecords(format string, recs []ldif.Record, stdout, stderr io.Writer, errs int) int {
	var entries []ldif.Entry
	for _, r := range recs {
		if r.Change != "add" {
			fmt.Fprintf(stderr, "ldif: %s record for %s cannot be converted to %s (only content records can)\n", r.Change, r.DN, format)
			return 1
		}
		entries = append(entries, ldif.Entry{DN: r.DN, Attrs: r.Attrs})
	}
	switch strings.ToLower(format) {
	case "ldif":
		fmt.Fprint(stdout, ldif.String(entries))
	case "json":
		b, err := ldif.ToJSON(entries)
		if err != nil {
			fmt.Fprintln(stderr, "ldif:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
	case "txt":
		for i, e := range entries {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "DN: %s\n", e.DN)
			for _, a := range e.Attrs {
				for _, v := range a.Values {
					fmt.Fprintf(stdout, "  %s: %s\n", a.Name, string(v))
				}
			}
		}
	default:
		fmt.Fprintf(stderr, "ldif: unknown format %q\n", format)
		return 2
	}
	if errs > 0 {
		fmt.Fprintf(stderr, "warning: %d validation error(s) — run `ldapview ldif -validate` to see them\n", errs)
	}
	return 0
}

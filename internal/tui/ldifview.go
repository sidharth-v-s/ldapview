package tui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldif"
)

type ldifViewMsg struct {
	path   string
	recs   []ldif.Record
	issues []ldif.Issue
	err    error
}

type ldifEditedMsg struct {
	path string
	temp bool
	err  error
}

func loadLDIFCmd(path string) tea.Cmd {
	return func() tea.Msg {
		f, err := os.Open(path)
		if err != nil {
			return ldifViewMsg{path: path, err: err}
		}
		defer f.Close()
		if st, err := f.Stat(); err == nil && st.Size() > 50<<20 {
			return ldifViewMsg{path: path, err: fmt.Errorf("file too large (>50 MB)")}
		}
		recs, err := ldif.Parse(f)
		if err != nil {
			return ldifViewMsg{path: path, err: err}
		}
		return ldifViewMsg{path: path, recs: recs, issues: ldif.Validate(recs)}
	}
}

func ldifReport(m ldifViewMsg) []string {
	sum := ldif.Summary(m.recs)
	errs := 0
	for _, i := range m.issues {
		if i.Severity == "error" {
			errs++
		}
	}
	lines := []string{
		"File: " + m.path,
		fmt.Sprintf("%d records: %d add, %d modify, %d delete, %d rename/move", len(m.recs), sum["add"], sum["modify"], sum["delete"], sum["modrdn"]),
		fmt.Sprintf("%d error(s), %d warning(s)", errs, len(m.issues)-errs),
		"",
	}
	if len(m.issues) == 0 {
		lines = append(lines, "No problems found.")
	}
	for _, i := range m.issues {
		lines = append(lines, i.String())
	}
	lines = append(lines, "", "Records:")
	for i, r := range m.recs {
		if i >= 200 {
			lines = append(lines, fmt.Sprintf("… %d more", len(m.recs)-i))
			break
		}
		lines = append(lines, fmt.Sprintf("  %-7s %s", r.Change, r.DN))
	}
	lines = append(lines, "", "Apply with :import "+m.path)
	return lines
}

const ldifTemplate = `# ldapview LDIF editor — save and quit to validate, then confirm the import.
# Lines starting with # are ignored. Examples:
#
# dn: uid=new,ou=People,dc=example,dc=com
# objectClass: inetOrgPerson
# uid: new
# cn: New User
# sn: User
#
# dn: uid=old,ou=People,dc=example,dc=com
# changetype: modify
# replace: description
# description: updated
# -

`

func editorCommand(path string) *exec.Cmd {
	ed := os.Getenv("VISUAL")
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	parts := strings.Fields(ed)
	return exec.Command(parts[0], append(parts[1:], path)...)
}

// editLDIFCmd opens an editor on path (or a private temp file) and reports
// back when it exits; nothing is sent to the server until the person
// confirms the import.
func editLDIFCmd(path string) (tea.Cmd, error) {
	temp := false
	if path == "" {
		f, err := os.CreateTemp("", "ldapview-*.ldif")
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, err
		}
		_, _ = f.WriteString(ldifTemplate)
		f.Close()
		path, temp = f.Name(), true
	}
	p := path
	return tea.ExecProcess(editorCommand(p), func(err error) tea.Msg {
		return ldifEditedMsg{path: p, temp: temp, err: err}
	}), nil
}

func readAndValidate(path string) ([]ldif.Record, []ldif.Issue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	recs, err := ldif.Parse(f)
	if err != nil {
		return nil, nil, err
	}
	return recs, ldif.Validate(recs), nil
}

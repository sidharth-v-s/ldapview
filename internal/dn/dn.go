// Package dn provides Distinguished Name parsing, escaping and
// display helpers on top of the go-ldap DN parser (RFC 4514).
package dn

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// RDN returns the leftmost relative distinguished name component of dn,
// e.g. "uid=alice" from "uid=alice,ou=People,dc=example,dc=com".
func RDN(raw string) (string, error) {
	parsed, err := ldap.ParseDN(raw)
	if err != nil {
		return "", fmt.Errorf("parsing DN %q: %w", raw, err)
	}
	if len(parsed.RDNs) == 0 {
		return "", fmt.Errorf("DN %q has no RDN components", raw)
	}
	return rdnString(parsed.RDNs[0]), nil
}

// Parent returns the parent DN of raw, i.e. everything after the first
// comma. Returns "" if raw is already a root/single-component DN.
func Parent(raw string) (string, error) {
	parsed, err := ldap.ParseDN(raw)
	if err != nil {
		return "", fmt.Errorf("parsing DN %q: %w", raw, err)
	}
	if len(parsed.RDNs) <= 1 {
		return "", nil
	}
	parts := make([]string, 0, len(parsed.RDNs)-1)
	for _, r := range parsed.RDNs[1:] {
		parts = append(parts, rdnString(r))
	}
	return strings.Join(parts, ","), nil
}

func rdnString(r *ldap.RelativeDN) string {
	attrs := make([]string, 0, len(r.Attributes))
	for _, a := range r.Attributes {
		attrs = append(attrs, fmt.Sprintf("%s=%s", a.Type, EscapeValue(a.Value)))
	}
	return strings.Join(attrs, "+")
}

// Valid reports whether raw parses as a syntactically valid DN.
func Valid(raw string) bool {
	_, err := ldap.ParseDN(raw)
	return err == nil
}

// EscapeValue escapes an attribute value for safe inclusion in a DN,
// per RFC 4514 section 2.4.
func EscapeValue(v string) string {
	return ldap.EscapeDN(v)
}

// Join builds a child DN from an RDN and a parent DN, e.g.
// Join("uid=alice", "ou=People,dc=example,dc=com") ->
// "uid=alice,ou=People,dc=example,dc=com".
func Join(rdn, parent string) string {
	if parent == "" {
		return rdn
	}
	return rdn + "," + parent
}

// Depth returns the number of RDN components in raw, or -1 if raw does
// not parse. Useful for tree indentation.
func Depth(raw string) int {
	parsed, err := ldap.ParseDN(raw)
	if err != nil {
		return -1
	}
	return len(parsed.RDNs)
}

package tui

import "github.com/zoro/ldapview/internal/ldapurl"

// parseLDAPURL is kept as a thin adapter over the shared RFC 4516 parser.
func parseLDAPURL(raw string) (ldapurl.URL, error) { return ldapurl.Parse(raw) }

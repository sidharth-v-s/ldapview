// Package ldapurl parses RFC 4516 LDAP URLs:
//
//	ldap[s]://host[:port]/base?attrs?scope?filter?extensions
package ldapurl

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// URL is a parsed LDAP URL with defaults applied.
type URL struct {
	Scheme string // ldap | ldaps
	Host   string
	Port   int // 0 = scheme default
	Base   string
	Attrs  []string
	Scope  string // base | one | sub
	Filter string
	Raw    string
}

// DefaultPort returns the explicit port or the scheme default.
func (u URL) DefaultPort() int {
	if u.Port != 0 {
		return u.Port
	}
	if u.Scheme == "ldaps" {
		return 636
	}
	return 389
}

// Is reports whether s looks like an LDAP URL.
func Is(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "ldap://") || strings.HasPrefix(s, "ldaps://")
}

// Parse parses an LDAP URL. Missing scope defaults to "base" and a missing
// filter to (objectClass=*), as RFC 4516 specifies.
func Parse(raw string) (URL, error) {
	raw = strings.TrimSpace(raw)
	u := URL{Raw: raw, Scope: "base", Filter: "(objectClass=*)"}
	if !Is(raw) {
		return u, fmt.Errorf("not an ldap:// or ldaps:// URL: %q", raw)
	}
	rest := raw[strings.Index(raw, "://")+3:]
	u.Scheme = strings.ToLower(raw[:strings.Index(raw, "://")])
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, query = rest[:i], rest[i+1:]
	}
	hostport, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport, path = rest[:i], rest[i+1:]
	}
	if hostport == "" {
		return u, fmt.Errorf("URL has no host")
	}
	host := hostport
	if strings.HasPrefix(hostport, "[") { // IPv6 literal
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return u, fmt.Errorf("unterminated IPv6 literal")
		}
		host = hostport[1:end]
		if tail := hostport[end+1:]; strings.HasPrefix(tail, ":") {
			p, err := strconv.Atoi(tail[1:])
			if err != nil || p <= 0 || p > 65535 {
				return u, fmt.Errorf("bad port %q", tail[1:])
			}
			u.Port = p
		}
	} else if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host = hostport[:i]
		p, err := strconv.Atoi(hostport[i+1:])
		if err != nil || p <= 0 || p > 65535 {
			return u, fmt.Errorf("bad port %q", hostport[i+1:])
		}
		u.Port = p
	}
	if host == "" {
		return u, fmt.Errorf("URL has no host")
	}
	u.Host = host
	if b, err := url.PathUnescape(path); err == nil {
		u.Base = b
	} else {
		u.Base = path
	}
	parts := strings.SplitN(query, "?", 4)
	if len(parts) > 0 && parts[0] != "" {
		for _, a := range strings.Split(parts[0], ",") {
			if a = strings.TrimSpace(a); a != "" {
				if d, err := url.PathUnescape(a); err == nil {
					a = d
				}
				u.Attrs = append(u.Attrs, a)
			}
		}
	}
	if len(parts) > 1 && parts[1] != "" {
		switch strings.ToLower(parts[1]) {
		case "base", "one", "sub":
			u.Scope = strings.ToLower(parts[1])
		default:
			return u, fmt.Errorf("bad scope %q (want base, one or sub)", parts[1])
		}
	}
	if len(parts) > 2 && parts[2] != "" {
		if f, err := url.PathUnescape(parts[2]); err == nil {
			u.Filter = f
		} else {
			u.Filter = parts[2]
		}
	}
	if len(parts) > 3 && strings.Contains(strings.ToLower(parts[3]), "!") {
		return u, fmt.Errorf("critical LDAP URL extensions are not supported: %q", parts[3])
	}
	return u, nil
}

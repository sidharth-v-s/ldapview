// Package store handles persistence of connection profiles.
//
// Passwords are never written to disk. Only connection metadata
// (host, port, protocol, bind DN, TLS settings) is persisted.
// The user is prompted for the password at connect time each session.
package store

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// BindMethod identifies how the client authenticates to the server.
type BindMethod string

const (
	BindAnonymous BindMethod = "anonymous"
	BindSimple    BindMethod = "simple"
	BindSASL      BindMethod = "sasl"
)

// TLSMode identifies the transport security mode for a connection.
type TLSMode string

const (
	TLSNone     TLSMode = "none"     // plain ldap://
	TLSStartTLS TLSMode = "starttls" // ldap:// + STARTTLS
	TLSImplicit TLSMode = "ldaps"    // ldaps://
)

// Connection is a saved connection profile. It never contains a password.
type Connection struct {
	Name       string     `yaml:"name"`
	Host       string     `yaml:"host"`
	Port       int        `yaml:"port"`
	TLSMode    TLSMode    `yaml:"tls_mode"`
	SkipVerify bool       `yaml:"skip_verify"`           // default false: verify certs
	CAFile     string     `yaml:"ca_file,omitempty"`     // extra trusted CA bundle (PEM)
	ClientCert string     `yaml:"client_cert,omitempty"` // client certificate (PEM) for SASL EXTERNAL
	ClientKey  string     `yaml:"client_key,omitempty"`  // client key (PEM)
	ReadOnly   bool       `yaml:"read_only,omitempty"`   // refuse all directory modifications
	BindMethod BindMethod `yaml:"bind_method"`
	BindDN     string     `yaml:"bind_dn,omitempty"`
	SASLMech   string     `yaml:"sasl_mechanism,omitempty"`
	TimeoutSec int        `yaml:"timeout_seconds"`
	SizeLimit  int        `yaml:"size_limit"`
	TimeLimit  int        `yaml:"time_limit_seconds"`
}

// DefaultPort returns the conventional port for the connection's TLS mode
// if Port is unset (0).
func (c Connection) DefaultPort() int {
	if c.Port != 0 {
		return c.Port
	}
	if c.TLSMode == TLSImplicit {
		return 636
	}
	return 389
}

// URL returns the ldap:// or ldaps:// scheme string for this connection,
// e.g. for display purposes.
func (c Connection) URL() string {
	scheme := "ldap"
	if c.TLSMode == TLSImplicit {
		scheme = "ldaps"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, c.Host, c.DefaultPort())
}

// Store is the on-disk collection of saved connections.
type Store struct {
	Connections []Connection `yaml:"connections"`
	path        string
}

// DefaultPath returns ~/.config/ldapview/connections.yaml (or
// $XDG_CONFIG_HOME/ldapview/connections.yaml when set).
func DefaultPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "ldapview", "connections.yaml"), nil
}

// Load reads the connection store from path, creating an empty one if the
// file does not yet exist.
func Load(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading connection store: %w", err)
	}
	if err := yaml.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parsing connection store: %w", err)
	}
	return s, nil
}

// Save writes the store back to disk with 0600 permissions (metadata
// only — no secrets — but restrictive regardless).
func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling connection store: %w", err)
	}
	return os.WriteFile(s.path, data, 0o600)
}

// Upsert adds a new connection or replaces an existing one with the same Name.
func (s *Store) Upsert(c Connection) {
	for i, existing := range s.Connections {
		if existing.Name == c.Name {
			s.Connections[i] = c
			return
		}
	}
	s.Connections = append(s.Connections, c)
}

// Delete removes a connection by name. Returns true if it was found.
func (s *Store) Delete(name string) bool {
	for i, existing := range s.Connections {
		if existing.Name == name {
			s.Connections = append(s.Connections[:i], s.Connections[i+1:]...)
			return true
		}
	}
	return false
}

// SavedSearch is a stored search definition (history entry or bookmark).
type SavedSearch struct {
	Name   string   `yaml:"name,omitempty"`
	Base   string   `yaml:"base"`
	Scope  string   `yaml:"scope"` // base | one | sub
	Filter string   `yaml:"filter"`
	Attrs  []string `yaml:"attrs,omitempty"`
}

// Key identifies a search for de-duplication.
func (s SavedSearch) Key() string { return s.Base + "\x00" + s.Scope + "\x00" + s.Filter }

// SearchList is a persisted list of searches (history or bookmarks).
type SearchList struct {
	Items []SavedSearch `yaml:"items"`
	path  string
	max   int
	// Fresh is true when the backing file did not exist at load time.
	Fresh bool
}

func configDir() (string, error) {
	p, err := DefaultPath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(p), nil
}

// LoadSearchList loads name (e.g. "history.yaml") from the config dir.
func LoadSearchList(name string, max int) (*SearchList, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	l := &SearchList{path: filepath.Join(dir, name), max: max}
	data, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		l.Fresh = true
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, l); err != nil {
		return nil, err
	}
	return l, nil
}

// Save writes the list with 0600 permissions.
func (l *SearchList) Save() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(l)
	if err != nil {
		return err
	}
	return os.WriteFile(l.path, data, 0o600)
}

// Push moves/adds s to the front, de-duplicating and trimming to max.
func (l *SearchList) Push(s SavedSearch) {
	out := []SavedSearch{s}
	for _, it := range l.Items {
		if it.Key() != s.Key() || (s.Name != "" && it.Name != s.Name) {
			if it.Key() == s.Key() && it.Name == "" {
				continue
			}
			out = append(out, it)
		}
	}
	if l.max > 0 && len(out) > l.max {
		out = out[:l.max]
	}
	l.Items = out
}

// Remove deletes the item at index i.
func (l *SearchList) Remove(i int) {
	if i >= 0 && i < len(l.Items) {
		l.Items = append(l.Items[:i], l.Items[i+1:]...)
	}
}

// DefaultBookmarks are seeded on first run so the bookmark list is useful
// immediately. Attribute names that do not exist on a server simply match
// nothing.
func DefaultBookmarks() []SavedSearch {
	return []SavedSearch{
		{Name: "Users", Scope: "sub", Filter: "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(&(objectCategory=person)(objectClass=user)))", Attrs: []string{"cn", "uid", "sAMAccountName", "mail"}},
		{Name: "Groups", Scope: "sub", Filter: "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group))", Attrs: []string{"cn", "description"}},
		{Name: "Computers", Scope: "sub", Filter: "(|(objectClass=computer)(objectClass=ipHost))", Attrs: []string{"cn", "dNSHostName", "operatingSystem"}},
		{Name: "Service accounts", Scope: "sub", Filter: "(|(uid=svc*)(sAMAccountName=svc*)(sAMAccountName=sa-*)(servicePrincipalName=*))", Attrs: []string{"cn", "sAMAccountName", "servicePrincipalName"}},
		{Name: "Domain Admins (AD)", Scope: "sub", Filter: "(&(objectClass=group)(cn=Domain Admins))", Attrs: []string{"cn", "member"}},
	}
}

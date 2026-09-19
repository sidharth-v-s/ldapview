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
	SkipVerify bool       `yaml:"skip_verify"`       // default false: verify certs
	CAFile     string     `yaml:"ca_file,omitempty"` // extra trusted CA bundle (PEM)
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

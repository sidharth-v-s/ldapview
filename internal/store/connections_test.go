package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundTripNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "c.yaml")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Upsert(Connection{Name: "a", Host: "h", TLSMode: TLSImplicit, BindMethod: BindSimple, BindDN: "cn=x"})
	s.Upsert(Connection{Name: "a", Host: "h2"}) // replace
	if len(s.Connections) != 1 || s.Connections[0].Host != "h2" {
		t.Fatal("upsert should replace by name")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(strings.ToLower(string(data)), "password") {
		t.Fatal("password field must never be persisted")
	}
	s2, _ := Load(path)
	if len(s2.Connections) != 1 {
		t.Fatal("reload failed")
	}
	if !s2.Delete("a") || s2.Delete("a") {
		t.Fatal("delete semantics wrong")
	}
}

func TestURLAndDefaultPort(t *testing.T) {
	if (Connection{Host: "h", TLSMode: TLSImplicit}).URL() != "ldaps://h:636" {
		t.Fatal("ldaps default")
	}
	if (Connection{Host: "h"}).URL() != "ldap://h:389" {
		t.Fatal("ldap default")
	}
}

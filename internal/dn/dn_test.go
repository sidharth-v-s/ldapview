package dn

import "testing"

func TestRDNAndParent(t *testing.T) {
	d := "uid=alice,ou=People,dc=example,dc=com"
	r, err := RDN(d)
	if err != nil || r != "uid=alice" {
		t.Fatalf("RDN = %q, %v", r, err)
	}
	p, err := Parent(d)
	if err != nil || p != "ou=People,dc=example,dc=com" {
		t.Fatalf("Parent = %q, %v", p, err)
	}
	if p, _ := Parent("dc=com"); p != "" {
		t.Fatalf("root parent = %q", p)
	}
}

func TestValidJoinDepth(t *testing.T) {
	if !Valid("cn=a,dc=b") || Valid("not a dn") {
		t.Fatal("Valid misbehaves")
	}
	if Join("cn=a", "dc=b") != "cn=a,dc=b" || Join("cn=a", "") != "cn=a" {
		t.Fatal("Join misbehaves")
	}
	if Depth("cn=a,dc=b,dc=c") != 3 || Depth("garbage") != -1 {
		t.Fatal("Depth misbehaves")
	}
}

func TestEscapeValue(t *testing.T) {
	if got := EscapeValue("a,b+c"); got != `a\,b\+c` {
		t.Fatalf("escape = %q", got)
	}
}

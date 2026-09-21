package ldapurl

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	u, err := Parse("ldap://10.10.10.10:3268/DC=corp,DC=local?cn,mail?sub?(objectClass=user)")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "ldap" || u.Host != "10.10.10.10" || u.Port != 3268 || u.Base != "DC=corp,DC=local" ||
		u.Scope != "sub" || u.Filter != "(objectClass=user)" || !reflect.DeepEqual(u.Attrs, []string{"cn", "mail"}) {
		t.Fatalf("%+v", u)
	}
	u, err = Parse("ldap://server/dc=example,dc=com??sub?(objectClass=user)")
	if err != nil || u.Scope != "sub" || len(u.Attrs) != 0 || u.Filter != "(objectClass=user)" {
		t.Fatalf("empty attrs: %+v %v", u, err)
	}
	u, err = Parse("ldaps://host")
	if err != nil || u.DefaultPort() != 636 || u.Scope != "base" || u.Filter != "(objectClass=*)" || u.Base != "" {
		t.Fatalf("defaults: %+v %v", u, err)
	}
	u, err = Parse("ldap://[::1]:1389/dc=x")
	if err != nil || u.Host != "::1" || u.Port != 1389 {
		t.Fatalf("ipv6: %+v %v", u, err)
	}
	u, err = Parse("ldap://h/cn=a%2Cb,dc=x??base?(cn=a%29b)")
	if err != nil || u.Base != "cn=a,b,dc=x" || u.Filter != "(cn=a)b)" {
		t.Fatalf("escapes: %+v %v", u, err)
	}
	for _, bad := range []string{"http://x", "ldap://", "ldap://:389/x", "ldap://h:abc", "ldap://h/?a?wrong", "ldap://h/??sub?(a=b)?!bindname=x", ""} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
	if !Is("LDAPS://x") || Is("ldapx://") || Is("host") {
		t.Fatal("Is")
	}
}

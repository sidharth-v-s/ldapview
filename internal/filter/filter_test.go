package filter

import "testing"

func TestBuildAndEscape(t *testing.T) {
	root := NewGroup(And)
	root.Add(NewCond("objectClass", "=", "person"))
	root.Add(NewCond("cn", "=", "Al*ce"))
	root.Add(NewCond("mail", "=", "*"))
	or := NewGroup(Or)
	or.Add(NewCond("sn", "=", "a)(b"))
	root.Add(or)
	n := NewGroup(Not)
	n.Add(NewCond("uid", ">=", "5"))
	root.Add(n)
	want := `(&(objectClass=person)(cn=Al*ce)(mail=*)(|(sn=a\29\28b))(!(uid>=5)))`
	if got := root.String(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if err := Validate(root.String()); err != nil {
		t.Fatal(err)
	}
	if !Remove(root, or) || len(root.Children) != 4 {
		t.Fatal("remove failed")
	}
}

func TestParseCondition(t *testing.T) {
	for in, want := range map[string]string{
		"cn=bob":     "(cn=bob)",
		"uid>=10":    "(uid>=10)",
		"mail":       "(mail=*)",
		"!cn=x":      "(!(cn=x))",
		" cn = a*b ": "(cn=a*b)",
	} {
		n, err := ParseCondition(in)
		if err != nil || n.String() != want {
			t.Fatalf("%q -> %v %v (want %s)", in, n, err, want)
		}
	}
	if _, err := ParseCondition("=x"); err == nil {
		t.Fatal("missing attr must error")
	}
}

func TestParseRaw(t *testing.T) {
	raw := `(&(objectClass=user)(|(cn=a\2ab)(userAccountControl:1.2.840.113556.1.4.803:=2))(!(mail=*)))`
	n, err := Parse(raw)
	if err != nil || n.String() != raw {
		t.Fatalf("roundtrip: %v\n%s", err, n)
	}
	if len(Flatten(n)) != 7 {
		t.Fatalf("rows = %d", len(Flatten(n)))
	}
	for _, bad := range []string{"cn=x", "(cn=x", "(&(a=b)"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

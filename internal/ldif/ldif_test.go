package ldif

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	long := strings.Repeat("x", 200)
	es := []Entry{{DN: "uid=a,dc=x", Attrs: []Attr{
		{Name: "cn", Values: [][]byte{[]byte("Alice"), []byte(" lead space")}},
		{Name: "description", Values: [][]byte{[]byte(long)}},
		{Name: "sn", Values: [][]byte{[]byte("Müller")}},
		{Name: "photo", Values: [][]byte{{0, 1, 2, 255}}},
	}}}
	out := String(es)
	if !strings.Contains(out, "cn:: ") || !strings.Contains(out, "sn:: ") {
		t.Fatalf("expected base64 for unsafe values:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 76 {
			t.Fatalf("line not folded: %d", len(l))
		}
	}
	recs, err := Parse(strings.NewReader(out))
	if err != nil || len(recs) != 1 {
		t.Fatalf("parse: %v %d", err, len(recs))
	}
	r := recs[0]
	if r.DN != "uid=a,dc=x" || len(r.Attrs) != 4 {
		t.Fatalf("bad record: %+v", r)
	}
	if string(r.Attrs[1].Values[0]) != long {
		t.Fatal("folded value lost")
	}
	if string(r.Attrs[2].Values[0]) != "Müller" || len(r.Attrs[3].Values[0]) != 4 {
		t.Fatal("binary/utf8 round trip failed")
	}
}

func TestParseChangeRecords(t *testing.T) {
	src := `version: 1
# comment
dn: uid=a,dc=x
changetype: modify
add: mail
mail: a@x
mail: b@x
-
delete: description
-
replace: sn
sn: Smith
-

dn: uid=b,dc=x
changetype: delete

dn: uid=c,dc=x
changetype: modrdn
newrdn: uid=cc
deleteoldrdn: 1
newsuperior: ou=p,dc=x

dn: uid=d,dc=x
objectClass: person
cn: D
`
	recs, err := Parse(strings.NewReader(src))
	if err != nil || len(recs) != 4 {
		t.Fatalf("%v %d", err, len(recs))
	}
	m := recs[0]
	if m.Change != "modify" || len(m.Mods) != 3 || len(m.Mods[0].Values) != 2 || m.Mods[1].Op != "delete" || len(m.Mods[1].Values) != 0 {
		t.Fatalf("modify parse: %+v", m)
	}
	if recs[1].Change != "delete" || recs[2].NewRDN != "uid=cc" || !recs[2].DeleteOldRDN || recs[2].NewSuperior != "ou=p,dc=x" {
		t.Fatalf("delete/modrdn parse: %+v %+v", recs[1], recs[2])
	}
	if recs[3].Change != "add" || len(recs[3].Attrs) != 2 {
		t.Fatalf("content parse: %+v", recs[3])
	}
	if _, err := Parse(strings.NewReader("cn: x\n")); err == nil {
		t.Fatal("record without dn must fail")
	}
}

func TestJSON(t *testing.T) {
	b, err := ToJSON([]Entry{{DN: "a", Attrs: []Attr{{Name: "cn", Values: [][]byte{[]byte("x")}}, {Name: "b", Values: [][]byte{{0, 1}}}}}})
	if err != nil || !strings.Contains(string(b), `"base64": "AAE="`) || !strings.Contains(string(b), `"cn"`) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestValidate(t *testing.T) {
	src := `dn: uid=a,dc=x
objectClass: person
uid: a

dn: uid=a,dc=x
objectClass: person
uid: a

dn: cn=noclass,dc=x
cn: noclass

dn: not a dn
objectClass: top

dn: uid=b,dc=x
objectClass: person
cn: b

dn: cn=m,dc=x
changetype: modify
add: mail
-

dn: cn=e,dc=x
changetype: modify
replace: description
-

dn: cn=bad name,dc=x
objectClass: person
bad name: 1
cn: bad name
`
	recs, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	issues := Validate(recs)
	var all []string
	for _, i := range issues {
		all = append(all, i.Severity+":"+i.Msg)
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{
		"error:duplicate add of the same DN",
		"error:add record has no objectClass",
		"error:invalid DN syntax",
		"warning:RDN value uid=b is not among the record's attributes",
		"error:add: mail has no values",
		"warning:replace: description with no values removes the attribute",
		"error:invalid attribute name",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	good, _ := Parse(strings.NewReader("dn: uid=ok,dc=x\nobjectClass: person\nuid: ok\n"))
	if got := Validate(good); len(got) != 0 {
		t.Fatalf("clean record flagged: %v", got)
	}
	if s := Summary(recs); s["add"] != 6 || s["modify"] != 2 {
		t.Fatalf("summary %v", s)
	}
}

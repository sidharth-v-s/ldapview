package schema

import (
	"reflect"
	"testing"
)

var ocs = []string{
	"( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
	"( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( mail $ uid ) X-ORIGIN 'RFC2798' )",
	"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ ou ) )",
	"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber ) )",
}
var ats = []string{
	"( 2.5.4.0 NAME 'objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
	"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s)' SUP name )",
	"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) SINGLE-VALUE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
	"( 2.5.18.1 NAME 'createTimestamp' SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
}

func TestParseAndResolve(t *testing.T) {
	s := Parse(ocs, ats, []string{"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )"}, []string{"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"})
	if len(s.ClassList) != 5 || len(s.AttrList) != 6 || len(s.RuleList) != 1 {
		t.Fatalf("counts %d %d %d", len(s.ClassList), len(s.AttrList), len(s.RuleList))
	}
	if got := s.Lineage("inetOrgPerson"); !reflect.DeepEqual(got, []string{"inetOrgPerson", "organizationalPerson", "person", "top"}) {
		t.Fatalf("lineage %v", got)
	}
	must, may := s.Resolve([]string{"inetOrgPerson"})
	if !reflect.DeepEqual(must, []string{"objectClass", "sn", "cn"}) && !reflect.DeepEqual(must, []string{"sn", "cn", "objectClass"}) {
		// order follows lineage; just require the set
		set := map[string]bool{}
		for _, m := range must {
			set[m] = true
		}
		if len(must) != 3 || !set["objectClass"] || !set["sn"] || !set["cn"] {
			t.Fatalf("must %v", must)
		}
	}
	found := map[string]bool{}
	for _, m := range may {
		found[m] = true
	}
	for _, want := range []string{"mail", "uid", "title", "userPassword", "description"} {
		if !found[want] {
			t.Fatalf("may missing %s: %v", want, may)
		}
	}
	if found["cn"] {
		t.Fatal("MAY must exclude MUST attrs")
	}
	if s.CanonAttr("commonName") != "cn" || s.CanonAttr("SURNAME") != "sn" || s.CanonAttr("nope") != "nope" {
		t.Fatal("canon attr")
	}
	e := s.Effective("cn")
	if e.Syntax != "1.3.6.1.4.1.1466.115.121.1.15" || e.Equality != "caseIgnoreMatch" || e.Substr == "" {
		t.Fatalf("effective: %+v", e)
	}
	if !s.Attr("uid").SingleValue || !s.Attr("createTimestamp").NoUserMod || s.Attr("createTimestamp").Usage != "directoryOperation" {
		t.Fatal("flags")
	}
	if s.SyntaxName("1.3.6.1.4.1.1466.115.121.1.15") != "Directory String" || s.SyntaxName("1.3.6.1.4.1.1466.115.121.1.7") != "Boolean" {
		t.Fatal("syntax names")
	}
	m, _ := s.UsedBy("cn")
	if len(m) != 2 { // person, posixAccount
		t.Fatalf("usedBy %v", m)
	}
	if s.Class("posixaccount").Kind != "AUXILIARY" || s.Class("top").Kind != "ABSTRACT" {
		t.Fatal("kinds")
	}
	if len(Parse([]string{"garbage", ""}, nil, nil, nil).ClassList) != 0 {
		t.Fatal("garbage must be skipped")
	}
}

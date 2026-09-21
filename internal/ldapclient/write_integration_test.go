//go:build integration

package ldapclient

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/store"
)

func bound(t *testing.T) *Client {
	c, err := Connect(testConf(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("secret"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestWriteLifecycle(t *testing.T) {
	c := bound(t)
	dn := "uid=carol,ou=People,dc=example,dc=com"
	_ = c.Delete(dn)
	_ = c.Delete("uid=carol2,ou=Groups,dc=example,dc=com")

	err := c.Add(dn, []AttrVals{
		{"objectClass", []string{"inetOrgPerson"}}, {"uid", []string{"carol"}}, {"cn", []string{"Carol"}},
		{"sn", []string{"Doe"}}, {"userPassword", []string{"hunter2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Add(dn, []AttrVals{{"objectClass", []string{"inetOrgPerson"}}, {"uid", []string{"carol"}}, {"cn", []string{"C"}}, {"sn", []string{"D"}}}); err == nil {
		t.Fatal("duplicate add must fail")
	} else if fe, ok := err.(*FriendlyError); !ok || fe.Message != "Entry Already Exists" {
		t.Fatalf("dup add error: %#v", err)
	}
	if err := c.Modify(dn, []Change{{"add", "mail", []string{"carol@example.com"}}, {"replace", "sn", []string{"Smith"}}}); err != nil {
		t.Fatal(err)
	}
	e, _ := c.ReadEntry(dn)
	if e.Get("sn")[0] != "Smith" || e.Get("mail")[0] != "carol@example.com" {
		t.Fatalf("modify not applied: %v", e.Attributes)
	}
	// value-level replace: delete old + add new atomically
	if err := c.Modify(dn, []Change{{"delete", "mail", []string{"carol@example.com"}}, {"add", "mail", []string{"c@example.org"}}}); err != nil {
		t.Fatal(err)
	}
	e, _ = c.ReadEntry(dn)
	if len(e.Get("mail")) != 1 || e.Get("mail")[0] != "c@example.org" {
		t.Fatalf("value replace: %v", e.Get("mail"))
	}
	// rename + move
	if err := c.ModifyDN(dn, "uid=carol2", true, "ou=Groups,dc=example,dc=com"); err != nil {
		t.Fatal(err)
	}
	moved := "uid=carol2,ou=Groups,dc=example,dc=com"
	if _, err := c.ReadEntry(moved); err != nil {
		t.Fatalf("moved entry missing: %v", err)
	}
	if _, err := c.ReadEntry(dn); err == nil {
		t.Fatal("old DN should be gone")
	}
	// non-leaf delete refused
	if err := c.Delete("ou=Groups,dc=example,dc=com"); err == nil {
		t.Fatal("non-leaf delete must fail")
	} else if fe, ok := err.(*FriendlyError); !ok || fe.Code != 66 {
		t.Fatalf("expected code 66, got %#v", err)
	}
	if err := c.Delete(moved); err != nil {
		t.Fatal(err)
	}

	// op log: recorded, and no secret in any entry
	ops := c.Ops()
	var kinds []string
	for _, o := range ops {
		kinds = append(kinds, o.Kind)
		if strings.Contains(o.Detail+o.Target+o.Err, "hunter2") {
			t.Fatalf("secret in op log: %+v", o)
		}
	}
	for _, want := range []string{"BIND", "ADD", "MODIFY", "MODDN", "DELETE"} {
		if !strings.Contains(strings.Join(kinds, ","), want) {
			t.Fatalf("op log missing %s: %v", want, kinds)
		}
	}
	var sawMask bool
	for _, o := range ops {
		if o.Kind == "ADD" && strings.Contains(o.Detail, "userPassword: ********") {
			sawMask = true
		}
	}
	if !sawMask {
		t.Fatal("userPassword must be masked in ADD detail")
	}
}

func TestPagingWhoAmISchema(t *testing.T) {
	c := bound(t)
	var got []string
	var cookie []byte
	pages := 0
	for {
		out, err := c.SearchEx(SearchParams{Base: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)", Attributes: []string{"1.1"}, PageSize: 2, Cookie: cookie})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, e := range out.Entries {
			got = append(got, e.DN)
		}
		if len(out.NextCookie) == 0 {
			break
		}
		cookie = out.NextCookie
	}
	all, err := c.Search(SearchParams{Base: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=*)", Attributes: []string{"1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(all) || pages != (len(all)+1)/2 {
		t.Fatalf("paged %d entries in %d pages, unpaged search sees %d: %v", len(got), pages, len(all), got)
	}

	who, err := c.WhoAmI()
	if err != nil || who != "dn:cn=admin,dc=example,dc=com" {
		t.Fatalf("whoami %q %v", who, err)
	}

	s, err := c.Schema()
	if err != nil {
		t.Fatal(err)
	}
	if s.Class("inetOrgPerson") == nil || s.Attr("mail") == nil {
		t.Fatalf("schema missing core definitions: %d classes %d attrs", len(s.ClassList), len(s.AttrList))
	}
	must, _ := s.Resolve([]string{"inetOrgPerson"})
	joined := strings.Join(must, ",")
	if !strings.Contains(joined, "sn") || !strings.Contains(joined, "cn") {
		t.Fatalf("inetOrgPerson MUST = %v", must)
	}
	if s.Effective("cn").Syntax == "" {
		t.Fatal("effective syntax for cn should be inherited from name")
	}
	if !c.AdvertisedSASL("EXTERNAL") && len(c.DSE().SupportedSASLMechanisms) == 0 {
		t.Log("no SASL list advertised")
	}
	if !c.SupportsControl("1.2.840.113556.1.4.319") {
		t.Fatal("OpenLDAP should advertise paging")
	}
}

func TestProtocolCapture(t *testing.T) {
	for name, conf := range map[string]store.Connection{
		"plain":    testConf(t),
		"ldaps":    tlsConf(t, store.TLSImplicit, 3636, true),
		"starttls": tlsConf(t, store.TLSStartTLS, 3389, true),
	} {
		c, err := Connect(conf)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.Bind("secret"); err != nil {
			t.Fatalf("%s bind: %v", name, err)
		}
		if _, err := c.ExpandOneLevel("dc=example,dc=com"); err != nil {
			t.Fatal(err)
		}
		msgs := c.ProtoLog().Messages()
		ops := map[string]int{}
		for _, m := range msgs {
			ops[m.Op]++
			if strings.Contains(strings.Join(m.Tree, "\n")+string(m.Raw), "secret") && m.Op != "NOTE" {
				t.Fatalf("%s: password leaked in %s", name, m.Op)
			}
		}
		for _, want := range []string{"bindRequest", "bindResponse", "searchRequest", "searchResEntry", "searchResDone"} {
			if ops[want] == 0 {
				t.Fatalf("%s: no %s captured (%v)", name, want, ops)
			}
		}
		if name == "starttls" {
			if ops["extendedRequest"] == 0 || ops["extendedResponse"] == 0 {
				t.Fatalf("starttls exchange not captured: %v", ops)
			}
			if c.TLS() == nil || !c.TLS().StartTLS {
				t.Fatal("TLS info should report StartTLS")
			}
		}
		if name == "plain" && c.TLS() != nil {
			t.Fatal("plain connection must have no TLS info")
		}
		c.Close()
	}
}

func TestPreviewSearch(t *testing.T) {
	c := bound(t)
	m, err := c.PreviewSearch(SearchParams{Base: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree, Filter: "(cn=a*)", PageSize: 10, Controls: []string{"manageDsaIT"}})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(m.Tree, "\n")
	if !strings.Contains(all, "Simple Paged Results") || !strings.Contains(all, "ManageDsaIT") || !strings.Contains(all, "(cn=a*)") {
		t.Fatalf("preview:\n%s", all)
	}
}

func TestEntryCache(t *testing.T) {
	c := bound(t)
	dn := "uid=alice,ou=People,dc=example,dc=com"
	countNet := func() int {
		n := 0
		for _, o := range c.Ops() {
			if o.Kind == "READ" && !strings.Contains(o.Detail, "cached") {
				n++
			}
		}
		return n
	}
	if _, err := c.ReadEntry(dn); err != nil {
		t.Fatal(err)
	}
	base := countNet()
	if _, err := c.ReadEntry(dn); err != nil {
		t.Fatal(err)
	}
	if countNet() != base {
		t.Fatal("second read should be served from cache")
	}
	if _, err := c.ReadEntryFresh(dn); err != nil {
		t.Fatal(err)
	}
	if countNet() != base+1 {
		t.Fatal("ReadEntryFresh must hit the server")
	}
	if err := c.Modify(dn, []Change{{"replace", "description", []string{"cache-test"}}}); err != nil {
		t.Fatal(err)
	}
	e, err := c.ReadEntry(dn)
	if err != nil || len(e.Get("description")) == 0 || e.Get("description")[0] != "cache-test" {
		t.Fatalf("write must invalidate the cache: %v %v", e, err)
	}
	_ = c.Modify(dn, []Change{{"delete", "description", nil}})
}

//go:build integration

package ldapclient

import (
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/store"
)

// Run with: LDAPVIEW_TEST_HOST=127.0.0.1 LDAPVIEW_TEST_PORT=3389 go test -tags integration ./...
func testConf(t *testing.T) store.Connection {
	host := os.Getenv("LDAPVIEW_TEST_HOST")
	if host == "" {
		t.Skip("LDAPVIEW_TEST_HOST not set")
	}
	port := 389
	if p := os.Getenv("LDAPVIEW_TEST_PORT"); p != "" {
		port = 0
		for _, c := range p {
			port = port*10 + int(c-'0')
		}
	}
	return store.Connection{
		Name: "t", Host: host, Port: port, TLSMode: store.TLSNone,
		BindMethod: store.BindSimple, BindDN: "cn=admin,dc=example,dc=com", TimeoutSec: 5,
	}
}

func TestMVPWorkflow(t *testing.T) {
	c, err := Connect(testConf(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("secret"); err != nil {
		t.Fatal(err)
	}

	dse, err := c.FetchRootDSE()
	if err != nil {
		t.Fatal(err)
	}
	if len(dse.NamingContexts) == 0 || dse.NamingContexts[0] != "dc=example,dc=com" {
		t.Fatalf("naming contexts: %v", dse.NamingContexts)
	}
	t.Logf("RootDSE: contexts=%v ldapv=%v controls=%d", dse.NamingContexts, dse.SupportedLDAPVersion, len(dse.SupportedControl))

	kids, err := c.ExpandOneLevel("dc=example,dc=com")
	if err != nil || len(kids) != 2 {
		t.Fatalf("expand: %v %v", kids, err)
	}
	people, err := c.ExpandOneLevel("ou=People,dc=example,dc=com")
	if err != nil || len(people) != 2 {
		t.Fatalf("people: %v %v", people, err)
	}

	e, err := c.ReadEntry("uid=alice,ou=People,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, a := range e.Attributes {
		found[a.Name] = true
	}
	if !found["mail"] || !found["entryUUID"] && !found["createTimestamp"] {
		t.Fatalf("expected user + operational attrs, got %v", found)
	}

	res, err := c.Search(SearchParams{
		Base: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree,
		Filter: "(&(objectClass=inetOrgPerson)(mail=*))", Attributes: []string{"cn", "mail"},
	})
	if err != nil || len(res) != 2 {
		t.Fatalf("search: %d %v", len(res), err)
	}

	_, err = c.ReadEntry("uid=nobody,dc=example,dc=com")
	if fe, ok := err.(*FriendlyError); !ok || fe.Message != "No Such Object" {
		t.Fatalf("expected No Such Object, got %#v", err)
	}
}

func TestBadCredentials(t *testing.T) {
	c, err := Connect(testConf(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Bind("wrong")
	if fe, ok := err.(*FriendlyError); !ok || fe.Code != 49 {
		t.Fatalf("expected Invalid Credentials, got %#v", err)
	}
}

func TestAnonymousBind(t *testing.T) {
	conf := testConf(t)
	conf.BindMethod = store.BindAnonymous
	c, err := Connect(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind(""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.FetchRootDSE(); err != nil {
		t.Fatal(err)
	}
}

func TestSizeLimitPartialResults(t *testing.T) {
	c, err := Connect(testConf(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("secret"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Search(SearchParams{
		Base: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree,
		Filter: "(objectClass=inetOrgPerson)", SizeLimit: 1,
	})
	le, ok := err.(*LimitError)
	if !ok || le.Code != 4 || len(res) != 1 {
		t.Fatalf("want partial result + LimitError(4), got %d entries, %#v", len(res), err)
	}
}

func TestHasSubordinates(t *testing.T) {
	c, err := Connect(testConf(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("secret"); err != nil {
		t.Fatal(err)
	}
	kids, _ := c.ExpandOneLevel("dc=example,dc=com")
	for _, k := range kids {
		if k.HasSubordinates == nil {
			t.Fatalf("%s: hasSubordinates not reported", k.DN)
		}
	}
}

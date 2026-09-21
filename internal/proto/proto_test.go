package proto

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestEncodeDecodeSearch(t *testing.T) {
	raw, err := EncodeSearch(7, SearchReq{Base: "dc=example,dc=com", Scope: 2, SizeLimit: 10, Filter: "(&(objectClass=person)(cn=a*))", Attrs: []string{"cn", "mail"},
		Controls: []ldap.Control{ldap.NewControlManageDsaIT(false), ldap.NewControlPaging(50)}})
	if err != nil {
		t.Fatal(err)
	}
	m := Decode(raw)
	if m.Op != "searchRequest" || m.ID != 7 || m.Raw == nil || m.RawHidden {
		t.Fatalf("decode: %+v", m)
	}
	all := strings.Join(m.Tree, "\n")
	for _, want := range []string{`baseObject: "dc=example,dc=com"`, "wholeSubtree (2)", "(&(objectClass=person)(cn=a*))", "ManageDsaIT", "Simple Paged Results", "sizeLimit: 10", "mail"} {
		if !strings.Contains(all, want) {
			t.Fatalf("tree missing %q:\n%s", want, all)
		}
	}
	if !strings.Contains(m.Summary, "SEARCH base=") {
		t.Fatalf("summary %q", m.Summary)
	}
	if _, err := EncodeSearch(1, SearchReq{Filter: "(bad"}); err == nil {
		t.Fatal("bad filter must fail")
	}
}

func TestSecretsAreMasked(t *testing.T) {
	req := ldap.NewSimpleBindRequest("cn=admin,dc=x", "hunter2", nil)
	_ = req
	add := ldap.NewAddRequest("uid=z,dc=x", nil)
	add.Attribute("userPassword", []string{"hunter2"})
	add.Attribute("cn", []string{"z"})
	// encode through a pipe-backed tap to capture what a client would send
	c1, c2 := net.Pipe()
	log := NewLog(50)
	tap := NewTap(c1, log)
	conn := ldap.NewConn(tap, false)
	conn.Start()
	go func() { io.Copy(io.Discard, c2) }()
	conn.SetTimeout(200 * 1e6)
	_, _ = conn.SimpleBind(&ldap.SimpleBindRequest{Username: "cn=admin,dc=x", Password: "hunter2"})
	_ = conn.Add(add)
	conn.Close()

	msgs := log.Messages()
	if len(msgs) < 2 {
		t.Fatalf("captured %d messages", len(msgs))
	}
	for _, m := range msgs {
		blob := strings.Join(m.Tree, "\n") + string(m.Raw)
		if strings.Contains(blob, "hunter2") {
			t.Fatalf("secret leaked in %s:\n%s", m.Op, blob)
		}
	}
	if msgs[0].Op != "bindRequest" || !msgs[0].RawHidden || msgs[0].Dir != "C→S" {
		t.Fatalf("bind message: %+v", msgs[0])
	}
	var sawAdd bool
	for _, m := range msgs {
		if m.Op == "addRequest" {
			sawAdd = true
			if !strings.Contains(strings.Join(m.Tree, "\n"), "********") || !m.RawHidden {
				t.Fatalf("add not masked: %v", m.Tree)
			}
		}
	}
	if !sawAdd {
		t.Fatal("add request not captured")
	}
}

func TestFrameLen(t *testing.T) {
	if _, st := frameLen([]byte{0x30}); st != 0 {
		t.Fatal("short header needs more")
	}
	if n, st := frameLen([]byte{0x30, 0x03, 1, 2, 3, 9}); n != 5 || st != 1 {
		t.Fatalf("n=%d st=%d", n, st)
	}
	if _, st := frameLen([]byte{0x17, 0x03, 1, 2, 3}); st != -1 {
		t.Fatal("non-sequence must be rejected")
	}
	if n, st := frameLen(append([]byte{0x30, 0x82, 0x01, 0x00}, make([]byte, 256)...)); n != 260 || st != 1 {
		t.Fatalf("long form n=%d st=%d", n, st)
	}
}

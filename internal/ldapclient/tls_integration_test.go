//go:build integration

package ldapclient

import (
	"testing"

	"github.com/zoro/ldapview/internal/store"
)

func tlsConf(t *testing.T, mode store.TLSMode, port int, skip bool) store.Connection {
	c := testConf(t)
	c.Host, c.Port, c.TLSMode, c.SkipVerify = "127.0.0.1", port, mode, skip
	return c
}

// The self-signed test CA is not in the system trust store, so with
// verification ON (the default) both TLS modes must be REJECTED.
func TestTLSVerifyRejectsUntrusted(t *testing.T) {
	if c, err := Connect(tlsConf(t, store.TLSImplicit, 3636, false)); err == nil {
		c.Close()
		t.Fatal("LDAPS with untrusted cert should fail verification by default")
	}
	if c, err := Connect(tlsConf(t, store.TLSStartTLS, 3389, false)); err == nil {
		c.Close()
		t.Fatal("StartTLS with untrusted cert should fail verification by default")
	}
}

func TestLDAPSAndStartTLSWithSkipVerify(t *testing.T) {
	for name, conf := range map[string]store.Connection{
		"ldaps":    tlsConf(t, store.TLSImplicit, 3636, true),
		"starttls": tlsConf(t, store.TLSStartTLS, 3389, true),
	} {
		c, err := Connect(conf)
		if err != nil {
			t.Fatalf("%s connect: %v", name, err)
		}
		if err := c.Bind("secret"); err != nil {
			t.Fatalf("%s bind: %v", name, err)
		}
		if dse, err := c.FetchRootDSE(); err != nil || len(dse.NamingContexts) == 0 {
			t.Fatalf("%s rootdse: %v", name, err)
		}
		c.Close()
	}
}

// With verification ON and the test CA supplied via ca_file, the
// connection must succeed WITHOUT skip_verify. Cert SAN covers 127.0.0.1.
func TestCAFileTrust(t *testing.T) {
	for name, conf := range map[string]store.Connection{
		"ldaps":    tlsConf(t, store.TLSImplicit, 3636, false),
		"starttls": tlsConf(t, store.TLSStartTLS, 3389, false),
	} {
		conf.CAFile = "/tmp/ldaptest/ca.crt"
		c, err := Connect(conf)
		if err != nil {
			t.Fatalf("%s with CA file: %v", name, err)
		}
		if err := c.Bind("secret"); err != nil {
			t.Fatalf("%s bind: %v", name, err)
		}
		c.Close()
	}
	bad := tlsConf(t, store.TLSImplicit, 3636, false)
	bad.CAFile = "/nonexistent.pem"
	if _, err := Connect(bad); err == nil {
		t.Fatal("missing CA file must error")
	}
}

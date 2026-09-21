package ldapclient

import (
	"strings"

	"github.com/zoro/ldapview/internal/store"
)

// AnonBindResult is the outcome of a non-destructive anonymous-bind probe.
type AnonBindResult struct {
	Allowed bool
	Detail  string
}

// ProbeAnonymousBind opens a short-lived second connection using the same
// transport settings as conf and attempts an unauthenticated bind, without
// disturbing the caller's already-bound connection. It never sends the
// caller's credentials.
func ProbeAnonymousBind(conf store.Connection) AnonBindResult {
	probeConf := conf
	probeConf.BindMethod = store.BindAnonymous
	probeConf.BindDN = ""
	c, err := Connect(probeConf)
	if err != nil {
		return AnonBindResult{Allowed: false, Detail: "connect failed: " + friendlyDetail(err)}
	}
	defer c.Close()
	if err := c.conn.UnauthenticatedBind(""); err != nil {
		return AnonBindResult{Allowed: false, Detail: friendlyDetail(TranslateError(err))}
	}
	// Confirm it's actually usable, not just accepted-then-empty: try a
	// base-scope Root DSE read.
	if _, err := c.FetchRootDSE(); err != nil {
		return AnonBindResult{Allowed: true, Detail: "bind accepted, but Root DSE unreadable anonymously"}
	}
	return AnonBindResult{Allowed: true, Detail: "bind accepted; Root DSE readable"}
}

func friendlyDetail(err error) string {
	if fe, ok := err.(*FriendlyError); ok {
		return fe.Message
	}
	return err.Error()
}

// ServerGuess is a best-effort, non-authoritative server identification.
type ServerGuess struct {
	Name       string
	Confidence string // high | medium | low
	Reasons    []string
}

// DetectServer inspects Root DSE fields only — it never fingerprints via
// probing or version banners beyond what the server already advertised.
func DetectServer(d *RootDSE) ServerGuess {
	if d == nil {
		return ServerGuess{Name: "unknown", Confidence: "low", Reasons: []string{"Root DSE unavailable"}}
	}
	has := func(vals []string, sub string) bool {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), strings.ToLower(sub)) {
				return true
			}
		}
		return false
	}
	hasOID := func(vals []string, oid string) bool {
		for _, v := range vals {
			if v == oid {
				return true
			}
		}
		return false
	}

	ocs := d.Get("objectClass")
	switch {
	case has(ocs, "OpenLDAProotDSE"):
		return ServerGuess{Name: "OpenLDAP", Confidence: "high", Reasons: []string{"Root DSE objectClass is OpenLDAProotDSE"}}
	case hasOID(d.SupportedCapabilities, "1.2.840.113556.1.4.800"):
		return ServerGuess{Name: "Microsoft Active Directory", Confidence: "high",
			Reasons: []string{"supportedCapabilities advertises LDAP_CAP_ACTIVE_DIRECTORY_OID"}}
	case d.ConfigurationNamingContext != "" && strings.Contains(strings.ToLower(d.ConfigurationNamingContext), "cn=configuration"):
		return ServerGuess{Name: "Microsoft Active Directory", Confidence: "medium",
			Reasons: []string{"configurationNamingContext looks like an AD configuration partition"}}
	case strings.Contains(strings.ToLower(d.VendorName), "openldap") || has(d.SupportedControl, "1.3.6.1.4.1.4203.1.9.1"):
		return ServerGuess{Name: "OpenLDAP", Confidence: "high", Reasons: []string{"vendorName / OpenLDAP-specific control OIDs present"}}
	case strings.Contains(strings.ToLower(d.VendorName), "389") || strings.Contains(strings.ToLower(d.VendorName), "red hat") || strings.Contains(strings.ToLower(d.VendorName), "fedora"):
		return ServerGuess{Name: "389 Directory Server", Confidence: "medium", Reasons: []string{"vendorName mentions 389/Red Hat/Fedora Directory Server"}}
	case strings.Contains(strings.ToLower(d.VendorName), "novell") || strings.Contains(strings.ToLower(d.VendorName), "edirectory"):
		return ServerGuess{Name: "Novell/NetIQ eDirectory", Confidence: "medium", Reasons: []string{"vendorName mentions Novell/eDirectory"}}
	case strings.Contains(strings.ToLower(d.VendorName), "oracle") || strings.Contains(strings.ToLower(d.VendorName), "sun"):
		return ServerGuess{Name: "Oracle/Sun Directory Server", Confidence: "medium", Reasons: []string{"vendorName mentions Oracle/Sun"}}
	case d.VendorName != "":
		return ServerGuess{Name: d.VendorName, Confidence: "low", Reasons: []string{"vendorName reported, but not a recognized pattern"}}
	default:
		return ServerGuess{Name: "unknown", Confidence: "low", Reasons: []string{"no vendorName or recognizable capability advertised"}}
	}
}

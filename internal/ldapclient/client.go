// Package ldapclient wraps github.com/go-ldap/ldap/v3 with the specific
// operations ldapview needs: connect/bind, Root DSE discovery, lazy
// one-level tree expansion, and filtered search — plus translation of
// raw LDAP result codes into human-readable errors.
//
// This package intentionally does not implement any automated attack
// or enumeration logic. It performs exactly the LDAP operations the
// user explicitly requests through the TUI (RFC 4510-4519).
package ldapclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/store"
)

// Client wraps a live LDAP connection plus the profile used to establish it.
type Client struct {
	conn *ldap.Conn
	conf store.Connection
}

// Attribute mirrors one LDAP attribute: its name and all values, plus
// whether it looks binary (can't be rendered as text).
type Attribute struct {
	Name     string
	Values   []string
	RawBytes [][]byte // populated only when Binary is true
	Binary   bool
}

// Entry is a single directory entry: DN plus its attributes.
type Entry struct {
	DN         string
	Attributes []Attribute
}

// RootDSE holds the server capability attributes read immediately after
// connecting (RFC 4512 section 5.1).
type RootDSE struct {
	NamingContexts             []string
	DefaultNamingContext       string
	RootDomainNamingContext    string
	ConfigurationNamingContext string
	SchemaNamingContext        string
	SupportedLDAPVersion       []string
	SupportedSASLMechanisms    []string
	SupportedControl           []string
	SupportedExtension         []string
	SupportedFeatures          []string
	SubschemaSubentry          string
	VendorName                 string
	VendorVersion              string
}

// Connect dials the server according to conf's TLS mode. It does not bind.
func Connect(conf store.Connection) (*Client, error) {
	addr := fmt.Sprintf("%s:%d", conf.Host, conf.DefaultPort())

	timeout := time.Duration(conf.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var conn *ldap.Conn
	var err error

	switch conf.TLSMode {
	case store.TLSImplicit:
		tlsConf, terr := buildTLSConfig(conf)
		if terr != nil {
			return nil, terr
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", addr),
			ldap.DialWithTLSConfig(tlsConf),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	default:
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", addr),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}

	if conf.TLSMode == store.TLSStartTLS {
		tlsConf, terr := buildTLSConfig(conf)
		if terr != nil {
			conn.Close()
			return nil, terr
		}
		if err := conn.StartTLS(tlsConf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", TranslateError(err))
		}
	}

	return &Client{conn: conn, conf: conf}, nil
}

// buildTLSConfig verifies certificates by default; conf.CAFile adds trusted
// roots on top of the system pool, conf.SkipVerify disables verification.
func buildTLSConfig(conf store.Connection) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: conf.Host, InsecureSkipVerify: conf.SkipVerify, MinVersion: tls.VersionTLS12}
	if conf.CAFile != "" {
		pem, err := os.ReadFile(conf.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certificates in %s", conf.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Bind authenticates using conf.BindMethod. password is never persisted —
// callers must hold it only in memory for the duration of the bind call.
func (c *Client) Bind(password string) error {
	switch c.conf.BindMethod {
	case store.BindAnonymous, "":
		return TranslateError(c.conn.UnauthenticatedBind(""))
	case store.BindSimple:
		return TranslateError(c.conn.Bind(c.conf.BindDN, password))
	case store.BindSASL:
		// Mechanism-specific SASL binds are dispatched here; architecture
		// supports adding more (DIGEST-MD5, GSSAPI, EXTERNAL, ...).
		return fmt.Errorf("SASL mechanism %q not yet implemented", c.conf.SASLMech)
	default:
		return fmt.Errorf("unknown bind method %q", c.conf.BindMethod)
	}
}

// Close closes the underlying connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// FetchRootDSE reads the Root DSE (base "", scope base, filter
// objectClass=*) immediately after connecting.
func (c *Client) FetchRootDSE() (*RootDSE, error) {
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{
			"namingContexts", "defaultNamingContext", "rootDomainNamingContext",
			"configurationNamingContext", "schemaNamingContext",
			"supportedLDAPVersion", "supportedSASLMechanisms",
			"supportedControl", "supportedExtension", "supportedFeatures",
			"subschemaSubentry", "vendorName", "vendorVersion",
		},
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("Root DSE search: %w", TranslateError(err))
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("server returned no Root DSE entry")
	}
	e := res.Entries[0]
	dse := &RootDSE{
		NamingContexts:             e.GetAttributeValues("namingContexts"),
		DefaultNamingContext:       e.GetAttributeValue("defaultNamingContext"),
		RootDomainNamingContext:    e.GetAttributeValue("rootDomainNamingContext"),
		ConfigurationNamingContext: e.GetAttributeValue("configurationNamingContext"),
		SchemaNamingContext:        e.GetAttributeValue("schemaNamingContext"),
		SupportedLDAPVersion:       e.GetAttributeValues("supportedLDAPVersion"),
		SupportedSASLMechanisms:    e.GetAttributeValues("supportedSASLMechanisms"),
		SupportedControl:           e.GetAttributeValues("supportedControl"),
		SupportedExtension:         e.GetAttributeValues("supportedExtension"),
		SupportedFeatures:          e.GetAttributeValues("supportedFeatures"),
		SubschemaSubentry:          e.GetAttributeValue("subschemaSubentry"),
		VendorName:                 e.GetAttributeValue("vendorName"),
		VendorVersion:              e.GetAttributeValue("vendorVersion"),
	}
	return dse, nil
}

// Child is a single one-level tree child: its DN and whether it has
// its own children (best-effort, from hasSubordinates-style probing
// is not always available so this may be optimistic).
type Child struct {
	DN              string
	ObjectClass     []string
	HasSubordinates *bool // nil when the server doesn't expose hasSubordinates
}

// ExpandOneLevel performs a oneLevel-scope search under base, returning
// direct children only. Callers should call this lazily per tree-node
// expansion rather than pre-loading the whole DIT (spec section 9).
func (c *Client) ExpandOneLevel(base string) ([]Child, error) {
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectClass", "hasSubordinates"},
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("expanding %s: %w", base, TranslateError(err))
	}
	children := make([]Child, 0, len(res.Entries))
	for _, e := range res.Entries {
		ch := Child{DN: e.DN, ObjectClass: e.GetAttributeValues("objectClass")}
		switch e.GetAttributeValue("hasSubordinates") {
		case "TRUE":
			t := true
			ch.HasSubordinates = &t
		case "FALSE":
			f := false
			ch.HasSubordinates = &f
		}
		children = append(children, ch)
	}
	sort.Slice(children, func(i, j int) bool { return children[i].DN < children[j].DN })
	return children, nil
}

// SearchParams configures a user-initiated LDAP search (spec section 17).
type SearchParams struct {
	Base       string
	Scope      int // ldap.ScopeBaseObject / SingleLevel / WholeSubtree
	Filter     string
	Attributes []string // empty/nil means all user attributes
	SizeLimit  int
	TimeLimit  int // seconds
}

// Search runs a user-driven search and returns matching entries.
func (c *Client) Search(p SearchParams) ([]Entry, error) {
	attrs := p.Attributes
	if len(attrs) == 0 {
		attrs = []string{"*"}
	}
	req := ldap.NewSearchRequest(
		p.Base,
		p.Scope, ldap.NeverDerefAliases, p.SizeLimit, p.TimeLimit, false,
		p.Filter,
		attrs,
		nil,
	)
	res, err := c.conn.Search(req)
	// go-ldap returns partial results alongside a size/time-limit error.
	// Keep them and report the limit via a *LimitError so the UI can say so.
	var entries []Entry
	if res != nil {
		entries = make([]Entry, 0, len(res.Entries))
		for _, e := range res.Entries {
			entries = append(entries, toEntry(e))
		}
	}
	if err != nil {
		te := TranslateError(err)
		if fe, ok := te.(*FriendlyError); ok && (fe.Code == 3 || fe.Code == 4) && len(entries) > 0 {
			return entries, &LimitError{Code: fe.Code, Message: fe.Message}
		}
		return nil, te
	}
	return entries, nil
}

// LimitError signals that a search hit a size/time limit; the returned
// entries are still valid partial results (spec section 22).
type LimitError struct {
	Code    uint16
	Message string
}

func (e *LimitError) Error() string { return e.Message }

// ReadEntry fetches a single entry by DN with all user and operational
// attributes.
func (c *Client) ReadEntry(dnStr string) (*Entry, error) {
	req := ldap.NewSearchRequest(
		dnStr,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"*", "+"}, // '+' requests operational attributes
		nil,
	)
	res, err := c.conn.Search(req)
	if err != nil {
		return nil, TranslateError(err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("entry not found: %s", dnStr)
	}
	e := toEntry(res.Entries[0])
	return &e, nil
}

func toEntry(e *ldap.Entry) Entry {
	attrs := make([]Attribute, 0, len(e.Attributes))
	for _, a := range e.Attributes {
		attr := Attribute{Name: a.Name}
		if looksBinary(a.Name, a.ByteValues) {
			attr.Binary = true
			attr.RawBytes = a.ByteValues
		} else {
			attr.Values = a.Values
		}
		attrs = append(attrs, attr)
	}
	sort.Slice(attrs, func(i, j int) bool {
		oi, oj := IsOperational(attrs[i].Name), IsOperational(attrs[j].Name)
		if oi != oj {
			return !oi // user attributes first
		}
		return toLower(attrs[i].Name) < toLower(attrs[j].Name)
	})
	return Entry{DN: e.DN, Attributes: attrs}
}

// operationalAttrs lists common operational attributes (RFC 4512 3.4 plus
// widespread vendor ones). Real classification needs schema (usage field);
// this heuristic is used until schema browsing lands.
var operationalAttrs = map[string]bool{
	"createtimestamp": true, "modifytimestamp": true, "creatorsname": true,
	"modifiersname": true, "entryuuid": true, "entrycsn": true, "entrydn": true,
	"hassubordinates": true, "numsubordinates": true, "structuralobjectclass": true,
	"subschemasubentry": true, "governingstructurerule": true, "pwdchangedtime": true,
	"whencreated": true, "whenchanged": true, "usncreated": true, "usnchanged": true,
	"instancetype": true, "distinguishedname": true, "dscorepropagationdata": true,
}

// IsOperational reports whether name is (heuristically) an operational attribute.
func IsOperational(name string) bool { return operationalAttrs[toLower(name)] }

// knownBinaryAttrs lists attribute names that are always binary
// regardless of whether their bytes happen to be printable.
var knownBinaryAttrs = map[string]bool{
	"jpegphoto":                 true,
	"objectguid":                true,
	"objectsid":                 true,
	"usercertificate":           true,
	"cacertificate":             true,
	"certificaterevocationlist": true,
	"ntsecuritydescriptor":      true,
	"thumbnailphoto":            true,
}

func looksBinary(name string, values [][]byte) bool {
	lower := toLower(name)
	if knownBinaryAttrs[lower] {
		return true
	}
	for _, v := range values {
		for _, b := range v {
			if b == 0 {
				return true
			}
			if b < 0x09 || (b > 0x0d && b < 0x20) {
				return true
			}
		}
	}
	return false
}

func toLower(s string) string {
	out := []byte(s)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		}
	}
	return string(out)
}

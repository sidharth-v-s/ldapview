package ldapclient

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/oid"
	"github.com/zoro/ldapview/internal/proto"
)

// Attribute is one LDAP attribute. Values always holds string forms and
// RawBytes the exact bytes; Binary marks values that are not display text.
type Attribute struct {
	Name     string
	Values   []string
	RawBytes [][]byte
	Binary   bool
}

// Entry is a directory entry.
type Entry struct {
	DN         string
	Attributes []Attribute
}

// Get returns the values of an attribute (case-insensitive), or nil.
func (e Entry) Get(name string) []string {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}

// RootDSE holds server capability information (RFC 4512 5.1).
type RootDSE struct {
	Attrs                      map[string][]string
	NamingContexts             []string
	DefaultNamingContext       string
	ConfigurationNamingContext string
	SchemaNamingContext        string
	SupportedLDAPVersion       []string
	SupportedSASLMechanisms    []string
	SupportedControl           []string
	SupportedExtension         []string
	SupportedFeatures          []string
	SupportedCapabilities      []string
	SubschemaSubentry          string
	VendorName                 string
	VendorVersion              string
}

// Get returns a Root DSE attribute case-insensitively.
func (d *RootDSE) Get(name string) []string {
	for k, v := range d.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func (d *RootDSE) first(name string) string {
	if v := d.Get(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

// DSE returns the cached Root DSE (nil until fetched).
func (c *Client) DSE() *RootDSE {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dse
}

// FetchRootDSE reads (and caches) the Root DSE.
func (c *Client) FetchRootDSE() (*RootDSE, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"*", "+"}, nil)
	res, err := c.conn.Search(req)
	c.record("ROOTDSE", "", "read Root DSE", TranslateError(err))
	if err != nil {
		return nil, fmt.Errorf("Root DSE search: %w", TranslateError(err))
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("server returned no Root DSE entry")
	}
	e := res.Entries[0]
	d := &RootDSE{Attrs: map[string][]string{}}
	for _, a := range e.Attributes {
		d.Attrs[a.Name] = a.Values
	}
	d.NamingContexts = d.Get("namingContexts")
	d.DefaultNamingContext = d.first("defaultNamingContext")
	d.ConfigurationNamingContext = d.first("configurationNamingContext")
	d.SchemaNamingContext = d.first("schemaNamingContext")
	d.SupportedLDAPVersion = d.Get("supportedLDAPVersion")
	d.SupportedSASLMechanisms = d.Get("supportedSASLMechanisms")
	d.SupportedControl = d.Get("supportedControl")
	d.SupportedExtension = d.Get("supportedExtension")
	d.SupportedFeatures = d.Get("supportedFeatures")
	d.SupportedCapabilities = d.Get("supportedCapabilities")
	d.SubschemaSubentry = d.first("subschemaSubentry")
	d.VendorName = d.first("vendorName")
	d.VendorVersion = d.first("vendorVersion")
	c.mu.Lock()
	c.dse = d
	c.mu.Unlock()
	return d, nil
}

// Child is a one-level tree child.
type Child struct {
	DN              string
	ObjectClass     []string
	HasSubordinates *bool // nil when the server doesn't expose hasSubordinates
}

// ExpandOneLevel lists direct children of base (lazy tree expansion).
func (c *Client) ExpandOneLevel(base string) ([]Child, error) {
	req := ldap.NewSearchRequest(base, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"objectClass", "hasSubordinates"}, nil)
	res, err := c.conn.Search(req)
	c.record("LIST", base, "one-level children", TranslateError(err))
	if err != nil {
		return nil, fmt.Errorf("expanding %s: %w", base, TranslateError(err))
	}
	children := make([]Child, 0, len(res.Entries))
	for _, e := range res.Entries {
		ch := Child{DN: e.DN, ObjectClass: e.GetAttributeValues("objectClass")}
		switch strings.ToUpper(e.GetAttributeValue("hasSubordinates")) {
		case "TRUE":
			t := true
			ch.HasSubordinates = &t
		case "FALSE":
			f := false
			ch.HasSubordinates = &f
		}
		children = append(children, ch)
	}
	sort.Slice(children, func(i, j int) bool { return strings.ToLower(children[i].DN) < strings.ToLower(children[j].DN) })
	return children, nil
}

// ReadEntry returns an entry, served from the recently-visited cache when
// fresh (no network round trip), otherwise fetched from the server.
func (c *Client) ReadEntry(dn string) (*Entry, error) {
	if e, ok := c.cacheGet(dn); ok {
		c.record("READ", dn, "all attributes (cached)", nil)
		return e, nil
	}
	return c.ReadEntryFresh(dn)
}

// ReadEntryFresh always queries the server and refreshes the cache.
func (c *Client) ReadEntryFresh(dn string) (*Entry, error) {
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"*", "+"}, nil)
	res, err := c.conn.Search(req)
	c.record("READ", dn, "all attributes", TranslateError(err))
	if err != nil {
		return nil, TranslateError(err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("entry not found: %s", dn)
	}
	e := toEntry(res.Entries[0])
	c.cachePut(e)
	return &e, nil
}

// SearchParams configures a user-initiated search.
type SearchParams struct {
	Base        string
	Scope       int
	Filter      string
	Attributes  []string
	SizeLimit   int
	TimeLimit   int
	Deref       int
	TypesOnly   bool
	PageSize    uint32
	Cookie      []byte
	Controls    []string // manageDsaIT, showDeleted, showRecycled
	SortAttr    string
	SortReverse bool

	// VLV requests a Virtual List View window: BeforeCount/AfterCount
	// entries around Offset of ContentCount total (or around a value with
	// GreaterThanOrEqual). VLV requires a matching server-side sort control
	// and is only sent when the server advertises the VLV control.
	VLV          bool
	VLVBefore    int
	VLVAfter     int
	VLVOffset    int
	VLVContent   int
	VLVGreaterEq string
}

// SearchOutcome is the result of SearchEx.
type SearchOutcome struct {
	Entries    []Entry
	Referrals  []string
	NextCookie []byte
	Limit      *LimitError
}

// LimitError signals a size/time limit; partial results remain valid.
type LimitError struct {
	Code    uint16
	Message string
}

func (e *LimitError) Error() string { return e.Message }

func (c *Client) controls(p SearchParams) []ldap.Control {
	var cs []ldap.Control
	for _, name := range p.Controls {
		switch name {
		case "manageDsaIT":
			cs = append(cs, ldap.NewControlManageDsaIT(false))
		case "showDeleted":
			cs = append(cs, ldap.NewControlMicrosoftShowDeleted())
		case "showRecycled":
			cs = append(cs, ldap.NewControlString(oid.ShowRecycled, true, ""))
		case "dirSync":
			// Cookie-less DirSync request: object security flag 0, max
			// attribute count unlimited (0), empty cookie for a fresh sync.
			cs = append(cs, dirSyncControl(nil))
		}
	}
	if p.SortAttr != "" && c.SupportsControl(oid.ServerSort) {
		cs = append(cs, ldap.NewControlServerSideSortingWithSortKeys([]*ldap.SortKey{{AttributeType: p.SortAttr, Reverse: p.SortReverse}}))
	}
	if p.VLV && c.SupportsControl(oid.VLVRequest) {
		cs = append(cs, vlvControl(p))
	}
	if p.PageSize > 0 {
		pc := ldap.NewControlPaging(p.PageSize)
		pc.SetCookie(p.Cookie)
		cs = append(cs, pc)
	}
	return cs
}

func attrsOrAll(a []string) []string {
	if len(a) == 0 {
		return []string{"*"}
	}
	return a
}

// PreviewSearch encodes the request that SearchEx would send (BER preview).
func (c *Client) PreviewSearch(p SearchParams) (proto.Message, error) {
	raw, err := proto.EncodeSearch(0, proto.SearchReq{
		Base: p.Base, Scope: p.Scope, Deref: p.Deref, SizeLimit: p.SizeLimit, TimeLimit: p.TimeLimit,
		TypesOnly: p.TypesOnly, Filter: p.Filter, Attrs: attrsOrAll(p.Attributes), Controls: c.controls(p),
	})
	if err != nil {
		return proto.Message{}, err
	}
	m := proto.Decode(raw)
	m.Dir = "preview"
	return m, nil
}

func scopeName(s int) string {
	switch s {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	}
	return "sub"
}

// SearchEx runs a search and returns entries, referrals, the paging cookie
// and any size/time limit indication.
func (c *Client) SearchEx(p SearchParams) (*SearchOutcome, error) {
	req := ldap.NewSearchRequest(p.Base, p.Scope, p.Deref, p.SizeLimit, p.TimeLimit, p.TypesOnly,
		p.Filter, attrsOrAll(p.Attributes), c.controls(p))
	res, err := c.conn.Search(req)
	out := &SearchOutcome{}
	if res != nil {
		out.Entries = make([]Entry, 0, len(res.Entries))
		for _, e := range res.Entries {
			out.Entries = append(out.Entries, toEntry(e))
		}
		out.Referrals = res.Referrals
		if pc, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok && len(pc.Cookie) > 0 {
			out.NextCookie = pc.Cookie
		}
	}
	detail := fmt.Sprintf("scope=%s filter=%s", scopeName(p.Scope), p.Filter)
	if err != nil {
		te := TranslateError(err)
		c.record("SEARCH", p.Base, detail, te)
		if fe, ok := te.(*FriendlyError); ok && (fe.Code == 3 || fe.Code == 4) && len(out.Entries) > 0 {
			out.Limit = &LimitError{Code: fe.Code, Message: fe.Message}
			return out, nil
		}
		return out, te
	}
	c.record("SEARCH", p.Base, fmt.Sprintf("%s → %d entries", detail, len(out.Entries)), nil)
	return out, nil
}

// Search runs a search returning entries; a *LimitError accompanies
// partial results when a size/time limit was hit.
func (c *Client) Search(p SearchParams) ([]Entry, error) {
	out, err := c.SearchEx(p)
	if err != nil {
		return nil, err
	}
	if out.Limit != nil {
		return out.Entries, out.Limit
	}
	return out.Entries, nil
}

func toEntry(e *ldap.Entry) Entry {
	attrs := make([]Attribute, 0, len(e.Attributes))
	for _, a := range e.Attributes {
		attrs = append(attrs, Attribute{
			Name: a.Name, Values: a.Values, RawBytes: a.ByteValues,
			Binary: looksBinary(a.Name, a.ByteValues),
		})
	}
	sort.Slice(attrs, func(i, j int) bool {
		oi, oj := IsOperational(attrs[i].Name), IsOperational(attrs[j].Name)
		if oi != oj {
			return !oi
		}
		return toLower(attrs[i].Name) < toLower(attrs[j].Name)
	})
	return Entry{DN: e.DN, Attributes: attrs}
}

var operationalAttrs = map[string]bool{
	"createtimestamp": true, "modifytimestamp": true, "creatorsname": true,
	"modifiersname": true, "entryuuid": true, "entrycsn": true, "entrydn": true,
	"hassubordinates": true, "numsubordinates": true, "structuralobjectclass": true,
	"subschemasubentry": true, "governingstructurerule": true, "pwdchangedtime": true,
	"whencreated": true, "whenchanged": true, "usncreated": true, "usnchanged": true,
	"instancetype": true, "distinguishedname": true, "dscorepropagationdata": true,
}

// IsOperational reports whether name is (heuristically) operational.
func IsOperational(name string) bool { return operationalAttrs[toLower(name)] }

var knownBinaryAttrs = map[string]bool{
	"jpegphoto": true, "objectguid": true, "objectsid": true, "usercertificate": true,
	"cacertificate": true, "certificaterevocationlist": true, "ntsecuritydescriptor": true,
	"thumbnailphoto": true, "msds-generationid": true, "logonhours": true, "usersmimecertificate": true,
}

func looksBinary(name string, values [][]byte) bool {
	lower := toLower(name)
	if i := strings.IndexByte(lower, ';'); i >= 0 {
		if strings.Contains(lower[i:], ";binary") {
			return true
		}
		lower = lower[:i]
	}
	if knownBinaryAttrs[lower] {
		return true
	}
	for _, v := range values {
		for _, b := range v {
			if b == 0 || b < 0x09 || (b > 0x0d && b < 0x20) {
				return true
			}
		}
	}
	return false
}

func toLower(s string) string { return strings.ToLower(s) }

package ldapclient

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/oid"
	"github.com/zoro/ldapview/internal/schema"
)

// Schema reads and caches the subschema (objectClasses, attributeTypes,
// ldapSyntaxes, matchingRules).
func (c *Client) Schema() (*schema.Schema, error) {
	c.mu.Lock()
	if c.sch != nil {
		s := c.sch
		c.mu.Unlock()
		return s, nil
	}
	c.mu.Unlock()
	dse := c.DSE()
	if dse == nil {
		var err error
		if dse, err = c.FetchRootDSE(); err != nil {
			return nil, err
		}
	}
	dn := dse.SubschemaSubentry
	if dn == "" {
		dn = "cn=Subschema"
	}
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"objectClasses", "attributeTypes", "ldapSyntaxes", "matchingRules"}, nil)
	res, err := c.conn.Search(req)
	c.record("SCHEMA", dn, "read subschema", TranslateError(err))
	if err != nil {
		return nil, fmt.Errorf("reading schema: %w", TranslateError(err))
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("subschema entry %s not found", dn)
	}
	e := res.Entries[0]
	s := schema.Parse(e.GetAttributeValues("objectClasses"), e.GetAttributeValues("attributeTypes"),
		e.GetAttributeValues("ldapSyntaxes"), e.GetAttributeValues("matchingRules"))
	if len(s.ClassList) == 0 && len(s.AttrList) == 0 {
		return nil, fmt.Errorf("no schema definitions readable at %s (insufficient access?)", dn)
	}
	c.mu.Lock()
	c.sch = s
	c.mu.Unlock()
	return s, nil
}

// WhoAmI performs the RFC 4532 "Who am I?" extended operation.
func (c *Client) WhoAmI() (string, error) {
	r, err := c.conn.WhoAmI(nil)
	te := TranslateError(err)
	c.record("EXTENDED", "", "Who am I?", te)
	if err != nil {
		return "", te
	}
	return r.AuthzID, nil
}

// ReadSecurityDescriptor reads nTSecurityDescriptor (owner, group, DACL) as raw bytes.
func (c *Client) ReadSecurityDescriptor(dn string) ([]byte, error) {
	flags := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlags")
	flags.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 7, "flags")) // owner|group|dacl
	ctl := ldap.NewControlString(oid.SDFlags, true, string(flags.Bytes()))
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"nTSecurityDescriptor"}, []ldap.Control{ctl})
	res, err := c.conn.Search(req)
	c.record("READ", dn, "nTSecurityDescriptor (owner, group, DACL)", TranslateError(err))
	if err != nil {
		return nil, TranslateError(err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("entry not found: %s", dn)
	}
	for _, a := range res.Entries[0].Attributes {
		if a.Name == "nTSecurityDescriptor" && len(a.ByteValues) > 0 {
			return a.ByteValues[0], nil
		}
	}
	return nil, fmt.Errorf("no nTSecurityDescriptor returned (not Active Directory, or access denied)")
}

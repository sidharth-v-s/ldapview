package ldapclient

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Change is one modification within a modify request.
type Change struct {
	Op     string // add | delete | replace
	Attr   string
	Values []string
}

// AttrVals is one attribute for an add request.
type AttrVals struct {
	Name   string
	Values []string
}

// DescribeChanges renders changes for display/logging with secrets masked.
func DescribeChanges(changes []Change) string {
	var parts []string
	for _, ch := range changes {
		vals := make([]string, len(ch.Values))
		for i, v := range ch.Values {
			if IsSecretAttr(ch.Attr) {
				vals[i] = "********"
			} else {
				vals[i] = v
			}
		}
		s := ch.Op + " " + ch.Attr
		if len(vals) > 0 {
			s += ": " + strings.Join(vals, ", ")
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// Add creates an entry.
func (c *Client) Add(dn string, attrs []AttrVals) error {
	req := ldap.NewAddRequest(dn, nil)
	var masked []Change
	for _, a := range attrs {
		req.Attribute(a.Name, a.Values)
		masked = append(masked, Change{Op: "add", Attr: a.Name, Values: a.Values})
	}
	err := TranslateError(c.conn.Add(req))
	c.InvalidateEntries()
	c.record("ADD", dn, DescribeChanges(masked), err)
	return err
}

// Modify applies changes to an entry in one request.
func (c *Client) Modify(dn string, changes []Change) error {
	if len(changes) == 0 {
		return fmt.Errorf("no changes to apply")
	}
	req := ldap.NewModifyRequest(dn, nil)
	for _, ch := range changes {
		switch ch.Op {
		case "add":
			req.Add(ch.Attr, ch.Values)
		case "delete":
			req.Delete(ch.Attr, ch.Values)
		case "replace":
			req.Replace(ch.Attr, ch.Values)
		default:
			return fmt.Errorf("unknown modify operation %q", ch.Op)
		}
	}
	err := TranslateError(c.conn.Modify(req))
	c.InvalidateEntries()
	c.record("MODIFY", dn, DescribeChanges(changes), err)
	return err
}

// Delete removes a single (leaf) entry.
func (c *Client) Delete(dn string) error {
	err := TranslateError(c.conn.Del(ldap.NewDelRequest(dn, nil)))
	c.InvalidateEntries()
	c.record("DELETE", dn, "", err)
	return err
}

// ModifyDN renames and/or moves an entry.
func (c *Client) ModifyDN(dn, newRDN string, deleteOld bool, newSuperior string) error {
	err := TranslateError(c.conn.ModifyDN(ldap.NewModifyDNRequest(dn, newRDN, deleteOld, newSuperior)))
	c.InvalidateEntries()
	detail := fmt.Sprintf("newrdn=%s deleteoldrdn=%v", newRDN, deleteOld)
	if newSuperior != "" {
		detail += " newsuperior=" + newSuperior
	}
	c.record("MODDN", dn, detail, err)
	return err
}

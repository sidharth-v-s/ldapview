package ldapclient

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/oid"
)

// rawControl wraps a pre-built BER value as an ldap.Control, for controls
// go-ldap has no typed helper for (DirSync, VLV).
type rawControl struct {
	OID      string
	Crit     bool
	Value    *ber.Packet
	Describe string
}

func (c *rawControl) GetControlType() string { return c.OID }
func (c *rawControl) String() string         { return c.Describe }
func (c *rawControl) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.OID, "Control Type"))
	if c.Crit {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	}
	if c.Value != nil {
		val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
		val.Data.Write(c.Value.Bytes())
		val.Value = c.Value.Bytes()
		p.AppendChild(val)
	}
	return p
}

// dirSyncControl builds a Microsoft DirSync request control
// (flags=0, maxAttrCount=0 meaning unlimited, cookie=cookie or empty).
func dirSyncControl(cookie []byte) *rawControl {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "DirSync")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Flags"))
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "MaxAttributeCount"))
	c := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(cookie), "Cookie")
	seq.AppendChild(c)
	return &rawControl{OID: oid.DirSync, Crit: true, Value: seq, Describe: "DirSync"}
}

// vlvControl builds a Virtual List View request control window.
func vlvControl(p SearchParams) *rawControl {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "VLV")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.VLVBefore, "beforeCount"))
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.VLVAfter, "afterCount"))
	if p.VLVGreaterEq != "" {
		target := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, p.VLVGreaterEq, "greaterThanOrEqual")
		seq.AppendChild(target)
	} else {
		byOffset := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "byOffset")
		byOffset.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.VLVOffset, "offset"))
		byOffset.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.VLVContent, "contentCount"))
		seq.AppendChild(byOffset)
	}
	return &rawControl{OID: oid.VLVRequest, Crit: true, Value: seq, Describe: "VLV"}
}

var _ ldap.Control = (*rawControl)(nil)

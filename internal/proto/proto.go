// Package proto captures and decodes LDAP protocol traffic for the raw
// message viewer, and encodes search requests for the BER preview.
//
// Secrets are never displayed: bind credentials and password-like
// attribute values are masked, and the raw bytes of messages that may
// contain secrets (bind/add/modify/extended requests) are withheld.
package proto

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/oid"
)

// Message is one captured or synthesised LDAP protocol message.
type Message struct {
	Seq       int
	Time      time.Time
	Dir       string // "C→S", "S→C" or "•" for notes
	ID        int
	Op        string
	Summary   string
	Tree      []string
	Raw       []byte
	RawHidden bool
	Size      int
}

// Log is a bounded, concurrency-safe message log shared by taps.
type Log struct {
	mu   sync.Mutex
	msgs []Message
	seq  int
	max  int
}

// NewLog creates a log holding at most max messages.
func NewLog(max int) *Log { return &Log{max: max} }

// Add appends a message, assigning its sequence number and timestamp.
func (l *Log) Add(m Message) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	m.Seq = l.seq
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	l.msgs = append(l.msgs, m)
	if l.max > 0 && len(l.msgs) > l.max {
		l.msgs = l.msgs[len(l.msgs)-l.max:]
	}
}

// Note adds a synthetic annotation line.
func (l *Log) Note(text string) {
	l.Add(Message{Dir: "•", Op: "NOTE", Summary: text, Tree: []string{text}})
}

// Messages returns a copy of the log.
func (l *Log) Messages() []Message {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Message(nil), l.msgs...)
}

// Clear empties the log.
func (l *Log) Clear() {
	l.mu.Lock()
	l.msgs = nil
	l.mu.Unlock()
}

// Tap wraps a net.Conn and records the LDAP messages flowing through it.
type Tap struct {
	net.Conn
	log *Log
	mu  sync.Mutex
	buf [2][]byte // 0 = outbound (C→S), 1 = inbound (S→C)
}

// NewTap wraps c, recording into l.
func NewTap(c net.Conn, l *Log) *Tap { return &Tap{Conn: c, log: l} }

func (t *Tap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.feed(1, p[:n])
	}
	return n, err
}

func (t *Tap) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.feed(0, p[:n])
	}
	return n, err
}

// frameLen returns the total length of the BER frame at the start of b and
// a status: 1 complete, 0 need more data, -1 not an LDAPMessage.
func frameLen(b []byte) (int, int) {
	if len(b) < 2 {
		return 0, 0
	}
	if b[0] != 0x30 {
		return 0, -1
	}
	l := int(b[1])
	if l < 0x80 {
		if len(b) >= 2+l {
			return 2 + l, 1
		}
		return 0, 0
	}
	k := l & 0x7f
	if k == 0 || k > 4 {
		return 0, -1
	}
	if len(b) < 2+k {
		return 0, 0
	}
	n := 0
	for i := 0; i < k; i++ {
		n = n<<8 | int(b[2+i])
	}
	if n > 64<<20 {
		return 0, -1
	}
	if len(b) >= 2+k+n {
		return 2 + k + n, 1
	}
	return 0, 0
}

func (t *Tap) feed(dir int, data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf[dir] = append(t.buf[dir], data...)
	for {
		n, st := frameLen(t.buf[dir])
		if st == 0 {
			return
		}
		if st < 0 {
			t.buf[dir] = nil
			t.log.Note("unparseable bytes (encrypted or out of sync) — capture resynchronised")
			return
		}
		raw := append([]byte(nil), t.buf[dir][:n]...)
		t.buf[dir] = t.buf[dir][n:]
		m := Decode(raw)
		if dir == 0 {
			m.Dir = "C→S"
		} else {
			m.Dir = "S→C"
		}
		t.log.Add(m)
	}
}

// ---- decoding ----

type node struct {
	label string
	kids  []*node
}

func (n *node) add(label string) *node {
	c := &node{label: label}
	n.kids = append(n.kids, c)
	return c
}

func render(n *node) []string {
	lines := []string{n.label}
	var rec func(kids []*node, prefix string)
	rec = func(kids []*node, prefix string) {
		for i, k := range kids {
			conn, next := "├── ", "│   "
			if i == len(kids)-1 {
				conn, next = "└── ", "    "
			}
			lines = append(lines, prefix+conn+k.label)
			rec(k.kids, prefix+next)
		}
	}
	rec(n.kids, "")
	return lines
}

func pbytes(p *ber.Packet) []byte {
	if p == nil {
		return nil
	}
	if p.ByteValue != nil {
		return p.ByteValue
	}
	if p.Data != nil {
		return p.Data.Bytes()
	}
	return nil
}

func pint(p *ber.Packet) int64 {
	if p == nil {
		return 0
	}
	if v, ok := p.Value.(int64); ok {
		return v
	}
	var n int64
	for _, b := range pbytes(p) {
		n = n<<8 | int64(b)
	}
	return n
}

func pbool(p *ber.Packet) bool {
	if v, ok := p.Value.(bool); ok {
		return v
	}
	b := pbytes(p)
	return len(b) > 0 && b[0] != 0
}

func show(b []byte) string {
	const max = 96
	if utf8.Valid(b) && !hasCtl(b) {
		s := string(b)
		if len(s) > max {
			return strconv.Quote(s[:max]) + "…"
		}
		return strconv.Quote(s)
	}
	h := hex.EncodeToString(b)
	if len(h) > max {
		h = h[:max] + "…"
	}
	return fmt.Sprintf("0x%s (%d bytes)", h, len(b))
}

func hasCtl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' {
			return true
		}
	}
	return false
}

func secretAttr(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "password") || strings.Contains(n, "unicodepwd") || strings.Contains(n, "userpkcs12") ||
		n == "authpassword" || n == "supplementalcredentials" || strings.Contains(n, "secret")
}

func enumName(v int64, names []string) string {
	if v >= 0 && int(v) < len(names) {
		return fmt.Sprintf("%s (%d)", names[v], v)
	}
	return strconv.FormatInt(v, 10)
}

var (
	scopeNames = []string{"baseObject", "singleLevel", "wholeSubtree"}
	derefNames = []string{"neverDerefAliases", "derefInSearching", "derefFindingBaseObj", "derefAlways"}
	modNames   = []string{"add", "delete", "replace", "increment"}
)

func resultName(code int64) string {
	if n, ok := ldap.LDAPResultCodeMap[uint16(code)]; ok {
		return fmt.Sprintf("%s (%d)", n, code)
	}
	return strconv.FormatInt(code, 10)
}

func attrNode(parent *node, a *ber.Packet) {
	if len(a.Children) < 2 {
		return
	}
	name := string(pbytes(a.Children[0]))
	an := parent.add(name)
	for _, v := range a.Children[1].Children {
		if secretAttr(name) {
			an.add("********")
		} else {
			an.add(show(pbytes(v)))
		}
	}
}

func filterString(p *ber.Packet) string {
	if s, err := ldap.DecompileFilter(p); err == nil {
		return s
	}
	return "<undecodable filter>"
}

func ldapResult(n *node, c []*ber.Packet) string {
	if len(c) < 3 {
		return ""
	}
	code := pint(c[0])
	n.add("resultCode: " + resultName(code))
	if md := string(pbytes(c[1])); md != "" {
		n.add("matchedDN: " + strconv.Quote(md))
	}
	if dm := string(pbytes(c[2])); dm != "" {
		n.add("diagnosticMessage: " + strconv.Quote(dm))
	}
	for _, x := range c[3:] {
		if x.ClassType == ber.ClassContext && x.Tag == 3 {
			r := n.add("referral")
			for _, u := range x.Children {
				r.add(string(pbytes(u)))
			}
		}
	}
	if s, ok := ldap.LDAPResultCodeMap[uint16(code)]; ok {
		return s
	}
	return strconv.FormatInt(code, 10)
}

func describeOp(op *ber.Packet) (name, summary string, n *node, hideRaw bool) {
	c := op.Children
	n = &node{}
	switch op.Tag {
	case 0:
		name, hideRaw = "bindRequest", true
		n.label = "protocolOp: bindRequest [APPLICATION 0]"
		if len(c) >= 3 {
			n.add(fmt.Sprintf("version: %d", pint(c[0])))
			n.add("name: " + show(pbytes(c[1])))
			switch c[2].Tag {
			case 0:
				n.add("authentication: simple  ********")
				summary = fmt.Sprintf("BIND simple name=%s", show(pbytes(c[1])))
			case 3:
				mech := ""
				if len(c[2].Children) > 0 {
					mech = string(pbytes(c[2].Children[0]))
				}
				a := n.add("authentication: sasl")
				a.add("mechanism: " + mech)
				a.add("credentials: ********")
				summary = "BIND sasl mechanism=" + mech
			}
		}
	case 1:
		name = "bindResponse"
		n.label = "protocolOp: bindResponse [APPLICATION 1]"
		summary = "BIND → " + ldapResult(n, c)
	case 2:
		name, summary = "unbindRequest", "UNBIND"
		n.label = "protocolOp: unbindRequest [APPLICATION 2]"
	case 3:
		name = "searchRequest"
		n.label = "protocolOp: searchRequest [APPLICATION 3]"
		if len(c) >= 8 {
			base := string(pbytes(c[0]))
			var attrs []string
			for _, a := range c[7].Children {
				attrs = append(attrs, string(pbytes(a)))
			}
			f := filterString(c[6])
			n.add("baseObject: " + strconv.Quote(base))
			n.add("scope: " + enumName(pint(c[1]), scopeNames))
			n.add("derefAliases: " + enumName(pint(c[2]), derefNames))
			n.add(fmt.Sprintf("sizeLimit: %d", pint(c[3])))
			n.add(fmt.Sprintf("timeLimit: %d", pint(c[4])))
			n.add(fmt.Sprintf("typesOnly: %v", pbool(c[5])))
			n.add("filter: " + f)
			an := n.add("attributes")
			for _, a := range attrs {
				an.add(a)
			}
			scope := enumName(pint(c[1]), scopeNames)
			summary = fmt.Sprintf("SEARCH base=%q scope=%s filter=%s attrs=[%s]", base, strings.SplitN(scope, " ", 2)[0], f, strings.Join(attrs, ","))
		}
	case 4:
		name = "searchResEntry"
		n.label = "protocolOp: searchResEntry [APPLICATION 4]"
		if len(c) >= 2 {
			dn := string(pbytes(c[0]))
			n.add("objectName: " + strconv.Quote(dn))
			at := n.add("attributes")
			for _, a := range c[1].Children {
				attrNode(at, a)
			}
			summary = fmt.Sprintf("ENTRY %s (%d attrs)", dn, len(c[1].Children))
		}
	case 5:
		name = "searchResDone"
		n.label = "protocolOp: searchResDone [APPLICATION 5]"
		summary = "SEARCH DONE → " + ldapResult(n, c)
	case 19:
		name = "searchResRef"
		n.label = "protocolOp: searchResRef [APPLICATION 19]"
		var us []string
		for _, u := range c {
			n.add(string(pbytes(u)))
			us = append(us, string(pbytes(u)))
		}
		summary = "REFERENCE " + strings.Join(us, " ")
	case 6:
		name, hideRaw = "modifyRequest", true
		n.label = "protocolOp: modifyRequest [APPLICATION 6]"
		if len(c) >= 2 {
			dn := string(pbytes(c[0]))
			n.add("object: " + strconv.Quote(dn))
			ch := n.add("changes")
			for _, m := range c[1].Children {
				if len(m.Children) < 2 {
					continue
				}
				cn := ch.add(enumName(pint(m.Children[0]), modNames))
				attrNode(cn, m.Children[1])
			}
			summary = fmt.Sprintf("MODIFY %s (%d changes)", dn, len(c[1].Children))
		}
	case 7:
		name = "modifyResponse"
		n.label = "protocolOp: modifyResponse [APPLICATION 7]"
		summary = "MODIFY → " + ldapResult(n, c)
	case 8:
		name, hideRaw = "addRequest", true
		n.label = "protocolOp: addRequest [APPLICATION 8]"
		if len(c) >= 2 {
			dn := string(pbytes(c[0]))
			n.add("entry: " + strconv.Quote(dn))
			at := n.add("attributes")
			for _, a := range c[1].Children {
				attrNode(at, a)
			}
			summary = "ADD " + dn
		}
	case 9:
		name = "addResponse"
		n.label = "protocolOp: addResponse [APPLICATION 9]"
		summary = "ADD → " + ldapResult(n, c)
	case 10:
		name = "delRequest"
		n.label = "protocolOp: delRequest [APPLICATION 10]"
		dn := string(pbytes(op))
		n.add("entry: " + strconv.Quote(dn))
		summary = "DELETE " + dn
	case 11:
		name = "delResponse"
		n.label = "protocolOp: delResponse [APPLICATION 11]"
		summary = "DELETE → " + ldapResult(n, c)
	case 12:
		name = "modDNRequest"
		n.label = "protocolOp: modDNRequest [APPLICATION 12]"
		if len(c) >= 3 {
			n.add("entry: " + strconv.Quote(string(pbytes(c[0]))))
			n.add("newrdn: " + strconv.Quote(string(pbytes(c[1]))))
			n.add(fmt.Sprintf("deleteoldrdn: %v", pbool(c[2])))
			sup := ""
			if len(c) > 3 {
				sup = string(pbytes(c[3]))
				n.add("newSuperior: " + strconv.Quote(sup))
			}
			summary = fmt.Sprintf("MODDN %s → %s", string(pbytes(c[0])), string(pbytes(c[1])))
		}
	case 13:
		name = "modDNResponse"
		n.label = "protocolOp: modDNResponse [APPLICATION 13]"
		summary = "MODDN → " + ldapResult(n, c)
	case 14:
		name = "compareRequest"
		n.label = "protocolOp: compareRequest [APPLICATION 14]"
		summary = "COMPARE"
	case 15:
		name = "compareResponse"
		n.label = "protocolOp: compareResponse [APPLICATION 15]"
		summary = "COMPARE → " + ldapResult(n, c)
	case 16:
		name = "abandonRequest"
		n.label = "protocolOp: abandonRequest [APPLICATION 16]"
		summary = fmt.Sprintf("ABANDON id=%d", pint(op))
		n.add(fmt.Sprintf("messageID: %d", pint(op)))
	case 23:
		name, hideRaw = "extendedRequest", true
		n.label = "protocolOp: extendedRequest [APPLICATION 23]"
		o := ""
		for _, x := range c {
			if x.Tag == 0 {
				o = string(pbytes(x))
				n.add("requestName: " + oid.Label(o))
			} else if x.Tag == 1 {
				n.add("requestValue: ********")
			}
		}
		summary = "EXTENDED " + firstNonEmpty(oid.Name(o), o)
	case 24:
		name = "extendedResponse"
		n.label = "protocolOp: extendedResponse [APPLICATION 24]"
		summary = "EXTENDED → " + ldapResult(n, c)
		if len(c) > 3 {
			for _, x := range c[3:] {
				if x.Tag == 10 {
					n.add("responseName: " + oid.Label(string(pbytes(x))))
				} else if x.Tag == 11 {
					n.add("responseValue: " + show(pbytes(x)))
				}
			}
		}
	default:
		name = fmt.Sprintf("op%d", op.Tag)
		n.label = fmt.Sprintf("protocolOp: unknown [APPLICATION %d]", op.Tag)
		summary = name
	}
	return
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Decode turns one raw LDAPMessage into a displayable Message.
func Decode(raw []byte) Message {
	p, err := ber.DecodePacketErr(raw)
	if err != nil || len(p.Children) < 2 {
		msg := "undecodable BER"
		if err != nil {
			msg += ": " + err.Error()
		}
		return Message{Op: "?", Summary: msg, Tree: []string{msg, hex.EncodeToString(raw)}, Raw: raw, Size: len(raw)}
	}
	id := int(pint(p.Children[0]))
	name, summary, opNode, hide := describeOp(p.Children[1])
	root := &node{label: fmt.Sprintf("LDAPMessage  messageID=%d  %s", id, name)}
	root.kids = append(root.kids, opNode)
	if len(p.Children) > 2 && p.Children[2].ClassType == ber.ClassContext && p.Children[2].Tag == 0 {
		cn := root.add("controls")
		for _, c := range p.Children[2].Children {
			if len(c.Children) == 0 {
				continue
			}
			o := string(pbytes(c.Children[0]))
			label := "control: " + oid.Label(o)
			for _, x := range c.Children[1:] {
				if x.Tag == ber.TagBoolean {
					label += fmt.Sprintf("  criticality=%v", pbool(x))
				}
			}
			cn.add(label)
		}
	}
	m := Message{ID: id, Op: name, Summary: summary, Tree: render(root), Size: len(raw)}
	if hide {
		m.RawHidden = true
	} else {
		m.Raw = raw
	}
	return m
}

// SearchReq describes a search for BER preview encoding.
type SearchReq struct {
	Base      string
	Scope     int
	Deref     int
	SizeLimit int
	TimeLimit int
	TypesOnly bool
	Filter    string
	Attrs     []string
	Controls  []ldap.Control
}

// EncodeSearch encodes r as an LDAPMessage with the given message ID.
func EncodeSearch(id int, r SearchReq) ([]byte, error) {
	f, err := ldap.CompileFilter(r.Filter)
	if err != nil {
		return nil, err
	}
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "Search Request")
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.Base, "Base DN"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.Scope, "Scope"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, r.Deref, "Deref"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, r.SizeLimit, "Size Limit"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, r.TimeLimit, "Time Limit"))
	req.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, r.TypesOnly, "Types Only"))
	req.AppendChild(f)
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, a := range r.Attrs {
		attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "Attribute"))
	}
	req.AppendChild(attrs)
	env.AppendChild(req)
	if len(r.Controls) > 0 {
		cs := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		for _, c := range r.Controls {
			cs.AppendChild(c.Encode())
		}
		env.AppendChild(cs)
	}
	return env.Bytes(), nil
}

// HexDump renders bytes as a hex+ASCII dump (16 bytes per line).
func HexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "%08x  ", i)
		for j := 0; j < 16; j++ {
			if i+j < end {
				fmt.Fprintf(&sb, "%02x ", b[i+j])
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for _, c := range b[i:end] {
			if c >= 0x20 && c <= 0x7e {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

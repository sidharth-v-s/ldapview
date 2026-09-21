// Package ldapclient wraps github.com/go-ldap/ldap/v3 with the operations
// ldapview needs: connect/bind (LDAP, StartTLS, LDAPS; simple and SASL),
// Root DSE, lazy tree expansion, search (paging, sorting, controls),
// entry modification, schema and security-descriptor reads.
//
// It performs exactly the operations the user requests through the UI and
// records them in an operation log that never contains secrets.
package ldapclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/zoro/ldapview/internal/proto"
	"github.com/zoro/ldapview/internal/schema"
	"github.com/zoro/ldapview/internal/store"
)

// Op is one entry in the operation log.
type Op struct {
	Time   time.Time
	Kind   string
	Target string
	Detail string
	OK     bool
	Err    string
	Raw    string
}

// TLSInfo describes the negotiated transport security.
type TLSInfo struct {
	Version   string
	Cipher    string
	Subject   string
	Issuer    string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
	Verified  bool
	StartTLS  bool
}

// Client is a live LDAP connection plus cached metadata.
type Client struct {
	conn *ldap.Conn
	conf store.Connection
	log  *proto.Log
	tls  *TLSInfo

	mu   sync.Mutex
	dse  *RootDSE
	sch  *schema.Schema
	ents map[string]cachedEntry // recently visited entries, keyed by lower-case DN
	opMu sync.Mutex
	ops  []Op
}

type cachedEntry struct {
	e  Entry
	at time.Time
}

const (
	entryCacheMax = 64
	entryCacheTTL = 60 * time.Second
)

func (c *Client) cacheGet(dn string) (*Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ce, ok := c.ents[strings.ToLower(dn)]
	if !ok || time.Since(ce.at) > entryCacheTTL {
		return nil, false
	}
	e := ce.e
	return &e, true
}

func (c *Client) cachePut(e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ents == nil {
		c.ents = map[string]cachedEntry{}
	}
	if len(c.ents) >= entryCacheMax {
		var oldK string
		var oldT time.Time
		for k, v := range c.ents {
			if oldK == "" || v.at.Before(oldT) {
				oldK, oldT = k, v.at
			}
		}
		delete(c.ents, oldK)
	}
	c.ents[strings.ToLower(e.DN)] = cachedEntry{e: e, at: time.Now()}
}

// InvalidateEntries drops every cached entry (called after any write).
func (c *Client) InvalidateEntries() {
	c.mu.Lock()
	c.ents = nil
	c.mu.Unlock()
}

// Conf returns the connection profile used.
func (c *Client) Conf() store.Connection { return c.conf }

// TLS returns negotiated TLS details, or nil for plaintext connections.
func (c *Client) TLS() *TLSInfo { return c.tls }

// ProtoLog returns the captured protocol messages.
func (c *Client) ProtoLog() *proto.Log { return c.log }

// Ops returns a copy of the operation log.
func (c *Client) Ops() []Op {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	return append([]Op(nil), c.ops...)
}

// ClearOps empties the operation log.
func (c *Client) ClearOps() {
	c.opMu.Lock()
	c.ops = nil
	c.opMu.Unlock()
}

func (c *Client) record(kind, target, detail string, err error) {
	op := Op{Time: time.Now(), Kind: kind, Target: target, Detail: detail, OK: err == nil}
	if err != nil {
		op.Err = err.Error()
		if fe, ok := err.(*FriendlyError); ok {
			op.Raw = fe.RawString()
		}
	}
	c.opMu.Lock()
	c.ops = append(c.ops, op)
	if len(c.ops) > 1000 {
		c.ops = c.ops[len(c.ops)-1000:]
	}
	c.opMu.Unlock()
}

// IsSecretAttr reports whether an attribute's values must never be logged.
func IsSecretAttr(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "password") || strings.Contains(n, "unicodepwd") ||
		strings.Contains(n, "secret") || n == "supplementalcredentials" || strings.Contains(n, "userpkcs12")
}

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
	if conf.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func tlsInfo(tc *tls.Conn, conf store.Connection, startTLS bool) *TLSInfo {
	st := tc.ConnectionState()
	info := &TLSInfo{Version: tls.VersionName(st.Version), Cipher: tls.CipherSuiteName(st.CipherSuite), Verified: !conf.SkipVerify, StartTLS: startTLS}
	if len(st.PeerCertificates) > 0 {
		pc := st.PeerCertificates[0]
		info.Subject, info.Issuer = pc.Subject.String(), pc.Issuer.String()
		info.DNSNames, info.NotBefore, info.NotAfter = pc.DNSNames, pc.NotBefore, pc.NotAfter
	}
	return info
}

func startTLSExchange(c net.Conn, timeout time.Duration) error {
	c.SetDeadline(time.Now().Add(timeout))
	defer c.SetDeadline(time.Time{})
	pkt := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))
	ext := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Start TLS")
	ext.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	pkt.AppendChild(ext)
	if _, err := c.Write(pkt.Bytes()); err != nil {
		return err
	}
	resp, err := ber.ReadPacket(c)
	if err != nil {
		return err
	}
	if len(resp.Children) < 2 || resp.Children[1].Tag != ldap.ApplicationExtendedResponse || len(resp.Children[1].Children) < 3 {
		return fmt.Errorf("unexpected response to StartTLS")
	}
	r := resp.Children[1].Children
	code, _ := r[0].Value.(int64)
	if code != 0 {
		return TranslateError(ldap.NewError(uint16(code), fmt.Errorf("%s", r[2].Value)))
	}
	return nil
}

// Connect dials the server according to conf's TLS mode. It does not bind.
func Connect(conf store.Connection) (*Client, error) {
	addr := net.JoinHostPort(conf.Host, strconv.Itoa(conf.DefaultPort()))
	timeout := time.Duration(conf.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	raw, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	log := proto.NewLog(1000)
	log.Note(fmt.Sprintf("connected to %s (tls mode: %s)", addr, conf.TLSMode))

	var nc net.Conn = raw
	var info *TLSInfo
	if conf.TLSMode == store.TLSImplicit || conf.TLSMode == store.TLSStartTLS {
		cfg, err := buildTLSConfig(conf)
		if err != nil {
			raw.Close()
			return nil, err
		}
		if conf.TLSMode == store.TLSStartTLS {
			if err := startTLSExchange(proto.NewTap(raw, log), timeout); err != nil {
				raw.Close()
				return nil, fmt.Errorf("StartTLS: %w", TranslateError(err))
			}
		}
		raw.SetDeadline(time.Now().Add(timeout))
		tc := tls.Client(raw, cfg)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		raw.SetDeadline(time.Time{})
		info = tlsInfo(tc, conf, conf.TLSMode == store.TLSStartTLS)
		log.Note(fmt.Sprintf("TLS established: %s %s, verified=%v", info.Version, info.Cipher, info.Verified))
		nc = tc
	}
	conn := ldap.NewConn(proto.NewTap(nc, log), info != nil)
	conn.Start()
	op := 3 * timeout
	if op < 30*time.Second {
		op = 30 * time.Second
	}
	conn.SetTimeout(op)
	return &Client{conn: conn, conf: conf, log: log, tls: info}, nil
}

func splitNTLM(user string) (domain, name string) {
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.IndexByte(user, '@'); i >= 0 {
		return user[i+1:], user[:i]
	}
	return "", user
}

// SASLMechanisms lists mechanisms implemented by this client.
var SASLMechanisms = []string{"DIGEST-MD5", "NTLM", "EXTERNAL"}

// Bind authenticates using conf.BindMethod. The password is used only for
// the bind call and is never stored or logged.
func (c *Client) Bind(password string) error {
	var err error
	detail := string(c.conf.BindMethod)
	switch c.conf.BindMethod {
	case store.BindAnonymous, "":
		err = c.conn.UnauthenticatedBind("")
	case store.BindSimple:
		err = c.conn.Bind(c.conf.BindDN, password)
	case store.BindSASL:
		mech := strings.ToUpper(c.conf.SASLMech)
		detail = "sasl " + mech
		switch mech {
		case "DIGEST-MD5":
			err = c.conn.MD5Bind(c.conf.Host, c.conf.BindDN, password)
		case "NTLM":
			d, u := splitNTLM(c.conf.BindDN)
			err = c.conn.NTLMBind(d, u, password)
		case "EXTERNAL":
			err = c.conn.ExternalBind()
		default:
			err = fmt.Errorf("SASL mechanism %q is not supported by this build (supported: %s)", c.conf.SASLMech, strings.Join(SASLMechanisms, ", "))
		}
	default:
		err = fmt.Errorf("unknown bind method %q", c.conf.BindMethod)
	}
	err = TranslateError(err)
	c.record("BIND", c.conf.BindDN, detail, err)
	return err
}

// Close closes the underlying connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// AdvertisedSASL reports whether the server lists mech among its SASL
// mechanisms (true when the Root DSE is unavailable).
func (c *Client) AdvertisedSASL(mech string) bool {
	d := c.DSE()
	if d == nil || len(d.SupportedSASLMechanisms) == 0 {
		return true
	}
	for _, m := range d.SupportedSASLMechanisms {
		if strings.EqualFold(m, mech) {
			return true
		}
	}
	return false
}

// SupportsControl reports whether the Root DSE advertises the control OID.
func (c *Client) SupportsControl(oid string) bool {
	d := c.DSE()
	if d == nil {
		return false
	}
	for _, o := range d.SupportedControl {
		if o == oid {
			return true
		}
	}
	return false
}

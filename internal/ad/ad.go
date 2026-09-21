// Package ad provides Active Directory aware decoding for display:
// userAccountControl / groupType flags, FILETIME and generalized time,
// SID names, security descriptors, functional levels and search presets.
// It only interprets data the server already returned.
package ad

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/oid"
)

type flag struct {
	bit  uint32
	name string
}

var uacFlags = []flag{
	{0x1, "SCRIPT"}, {0x2, "ACCOUNTDISABLE"}, {0x8, "HOMEDIR_REQUIRED"}, {0x10, "LOCKOUT"},
	{0x20, "PASSWD_NOTREQD"}, {0x40, "PASSWD_CANT_CHANGE"}, {0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"},
	{0x100, "TEMP_DUPLICATE_ACCOUNT"}, {0x200, "NORMAL_ACCOUNT"}, {0x800, "INTERDOMAIN_TRUST_ACCOUNT"},
	{0x1000, "WORKSTATION_TRUST_ACCOUNT"}, {0x2000, "SERVER_TRUST_ACCOUNT"}, {0x10000, "DONT_EXPIRE_PASSWORD"},
	{0x20000, "MNS_LOGON_ACCOUNT"}, {0x40000, "SMARTCARD_REQUIRED"}, {0x80000, "TRUSTED_FOR_DELEGATION"},
	{0x100000, "NOT_DELEGATED"}, {0x200000, "USE_DES_KEY_ONLY"}, {0x400000, "DONT_REQ_PREAUTH"},
	{0x800000, "PASSWORD_EXPIRED"}, {0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"}, {0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

var groupTypeFlags = []flag{
	{0x1, "SYSTEM"}, {0x2, "GLOBAL"}, {0x4, "DOMAIN_LOCAL"}, {0x8, "UNIVERSAL"},
	{0x10, "APP_BASIC"}, {0x20, "APP_QUERY"}, {0x80000000, "SECURITY"},
}

var encTypeFlags = []flag{{1, "DES-CBC-CRC"}, {2, "DES-CBC-MD5"}, {4, "RC4-HMAC"}, {8, "AES128"}, {16, "AES256"}}

func names(v uint32, fl []flag) []string {
	var out []string
	for _, f := range fl {
		if v&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// UACFlags decodes userAccountControl.
func UACFlags(v uint32) []string { return names(v, uacFlags) }

// GroupTypeFlags decodes groupType (signed 32-bit stored as decimal).
func GroupTypeFlags(v uint32) []string {
	out := names(v, groupTypeFlags)
	if v&0x80000000 == 0 {
		out = append(out, "DISTRIBUTION")
	}
	return out
}

var samTypes = map[uint32]string{
	0x10000000: "GROUP_OBJECT", 0x10000001: "NON_SECURITY_GROUP_OBJECT",
	0x20000000: "ALIAS_OBJECT", 0x20000001: "NON_SECURITY_ALIAS_OBJECT",
	0x30000000: "NORMAL_USER_ACCOUNT", 0x30000001: "MACHINE_ACCOUNT", 0x30000002: "TRUST_ACCOUNT",
	0x40000000: "APP_BASIC_GROUP", 0x40000001: "APP_QUERY_GROUP",
}

var levels = map[string]string{
	"0": "Windows 2000", "1": "Windows Server 2003 interim", "2": "Windows Server 2003",
	"3": "Windows Server 2008", "4": "Windows Server 2008 R2", "5": "Windows Server 2012",
	"6": "Windows Server 2012 R2", "7": "Windows Server 2016", "10": "Windows Server 2025",
}

var wellKnownSIDs = map[string]string{
	"S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-3-0": "Creator Owner", "S-1-3-1": "Creator Group",
	"S-1-5-1": "Dialup", "S-1-5-2": "Network", "S-1-5-3": "Batch", "S-1-5-4": "Interactive",
	"S-1-5-6": "Service", "S-1-5-7": "Anonymous Logon", "S-1-5-9": "Enterprise Domain Controllers",
	"S-1-5-10": "Principal Self", "S-1-5-11": "Authenticated Users", "S-1-5-13": "Terminal Server Users",
	"S-1-5-18": "Local System", "S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
	"S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users", "S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users", "S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators", "S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators", "S-1-5-32-552": "BUILTIN\\Replicator",
	"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access", "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-556": "BUILTIN\\Network Configuration Operators", "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
	"S-1-5-32-562": "BUILTIN\\Distributed COM Users", "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers", "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
}

var domainRIDs = map[uint32]string{
	498: "Enterprise Read-only Domain Controllers", 500: "Administrator", 501: "Guest", 502: "krbtgt",
	512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests", 515: "Domain Computers",
	516: "Domain Controllers", 517: "Cert Publishers", 518: "Schema Admins", 519: "Enterprise Admins",
	520: "Group Policy Creator Owners", 521: "Read-only Domain Controllers", 522: "Cloneable Domain Controllers",
	525: "Protected Users", 526: "Key Admins", 527: "Enterprise Key Admins", 553: "RAS and IAS Servers",
}

var domSID = regexp.MustCompile(`^S-1-5-21-\d+-\d+-\d+-(\d+)$`)

// SIDName returns a well-known name for a SID string, or "".
func SIDName(sid string) string {
	if n, ok := wellKnownSIDs[sid]; ok {
		return n
	}
	if m := domSID.FindStringSubmatch(sid); m != nil {
		if rid, err := strconv.ParseUint(m[1], 10, 32); err == nil {
			return domainRIDs[uint32(rid)]
		}
	}
	return ""
}

var ridOnly = func(rid uint32) string { return domainRIDs[rid] }

var fileTimeAttrs = map[string]bool{
	"pwdlastset": true, "lastlogon": true, "lastlogontimestamp": true, "accountexpires": true,
	"badpasswordtime": true, "lockouttime": true, "lastlogoff": true, "ms-mcs-admpwdexpirationtime": true,
}

var genTime = regexp.MustCompile(`^\d{14}(\.\d+)?Z$`)

// FileTime formats a Windows FILETIME (100ns ticks since 1601-01-01 UTC).
func FileTime(v int64, now time.Time) string {
	switch {
	case v == 0:
		return "not set / never (0)"
	case v == 9223372036854775807:
		return "never"
	case v < 0:
		return ""
	}
	ticks := v - 116444736000000000
	t := time.Unix(ticks/10_000_000, (ticks%10_000_000)*100).UTC()
	return t.Format("2006-01-02 15:04:05 UTC") + " " + relative(t, now)
}

// GeneralizedTime formats an LDAP generalized time value.
func GeneralizedTime(s string, now time.Time) string {
	t, err := time.Parse("20060102150405Z", s)
	if err != nil {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC") + " " + relative(t, now)
}

func relative(t, now time.Time) string {
	d := now.Sub(t)
	suffix := "ago"
	if d < 0 {
		d, suffix = -d, "from now"
	}
	switch {
	case d < time.Minute:
		return "(just now)"
	case d < time.Hour:
		return fmt.Sprintf("(%dm %s)", int(d.Minutes()), suffix)
	case d < 48*time.Hour:
		return fmt.Sprintf("(%dh %s)", int(d.Hours()), suffix)
	case d < 2*365*24*time.Hour:
		return fmt.Sprintf("(%dd %s)", int(d.Hours()/24), suffix)
	}
	return fmt.Sprintf("(%dy %s)", int(d.Hours()/24/365), suffix)
}

// Annotate returns a human-readable interpretation of a value, or "".
func Annotate(attr, value string, now time.Time) string {
	a := strings.ToLower(attr)
	switch {
	case a == "useraccountcontrol":
		if n, err := strconv.ParseUint(value, 10, 32); err == nil {
			return strings.Join(UACFlags(uint32(n)), " | ")
		}
	case a == "grouptype":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return strings.Join(GroupTypeFlags(uint32(n)), " | ")
		}
	case a == "samaccounttype":
		if n, err := strconv.ParseUint(value, 10, 32); err == nil {
			return samTypes[uint32(n)]
		}
	case a == "primarygroupid":
		if n, err := strconv.ParseUint(value, 10, 32); err == nil {
			return ridOnly(uint32(n))
		}
	case a == "msds-supportedencryptiontypes":
		if n, err := strconv.ParseUint(value, 10, 32); err == nil {
			return strings.Join(names(uint32(n), encTypeFlags), " | ")
		}
	case a == "domainfunctionality" || a == "forestfunctionality" || a == "domaincontrollerfunctionality" || a == "msds-behavior-version":
		return levels[value]
	case a == "objectsid":
		return SIDName(value)
	case fileTimeAttrs[a]:
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return FileTime(n, now)
		}
	}
	if genTime.MatchString(value) {
		return GeneralizedTime(value, now)
	}
	return ""
}

// IsAD reports whether Root DSE data indicates Active Directory.
func IsAD(capabilities []string, configNC string) bool {
	for _, c := range capabilities {
		if c == oid.ADCapability {
			return true
		}
	}
	return false
}

// ---- security descriptors ----

// ACE is one access control entry.
type ACE struct {
	Type        string
	Flags       []string
	Mask        uint32
	Rights      []string
	Trustee     string
	TrusteeName string
	ObjectType  string
	ObjectName  string
	Inherited   string
}

// SD is a parsed self-relative security descriptor.
type SD struct {
	Control   []string
	Owner     string
	OwnerName string
	Group     string
	GroupName string
	DACL      []ACE
	HasDACL   bool
	HasSACL   bool
}

var aceTypes = map[byte]string{
	0: "ALLOW", 1: "DENY", 2: "AUDIT", 5: "ALLOW_OBJECT", 6: "DENY_OBJECT", 7: "AUDIT_OBJECT",
	9: "ALLOW_CALLBACK", 10: "DENY_CALLBACK", 11: "ALLOW_CALLBACK_OBJECT", 12: "DENY_CALLBACK_OBJECT",
}

var sdControl = []flag{
	{0x1, "OWNER_DEFAULTED"}, {0x2, "GROUP_DEFAULTED"}, {0x4, "DACL_PRESENT"}, {0x8, "DACL_DEFAULTED"},
	{0x10, "SACL_PRESENT"}, {0x100, "DACL_AUTO_INHERIT_REQ"}, {0x400, "DACL_AUTO_INHERITED"},
	{0x1000, "DACL_PROTECTED"}, {0x2000, "SACL_PROTECTED"}, {0x8000, "SELF_RELATIVE"},
}

var aceFlags = []flag{
	{0x1, "OBJECT_INHERIT"}, {0x2, "CONTAINER_INHERIT"}, {0x4, "NO_PROPAGATE"},
	{0x8, "INHERIT_ONLY"}, {0x10, "INHERITED"},
}

var rightBits = []flag{
	{0x1, "CreateChild"}, {0x2, "DeleteChild"}, {0x4, "ListChildren"}, {0x8, "Self"},
	{0x10, "ReadProperty"}, {0x20, "WriteProperty"}, {0x40, "DeleteTree"}, {0x80, "ListObject"},
	{0x100, "ExtendedRight"}, {0x10000, "Delete"}, {0x20000, "ReadControl"}, {0x40000, "WriteDacl"},
	{0x80000, "WriteOwner"}, {0x100000, "Synchronize"},
}

// Rights decodes an AD access mask.
func Rights(mask uint32) []string {
	if mask&0x000F01FF == 0x000F01FF || mask&0x10000000 != 0 {
		return []string{"GenericAll(FullControl)"}
	}
	out := names(mask, rightBits)
	if mask&0x80000000 != 0 {
		out = append(out, "GenericRead")
	}
	if mask&0x40000000 != 0 {
		out = append(out, "GenericWrite")
	}
	if mask&0x20000000 != 0 {
		out = append(out, "GenericExecute")
	}
	return out
}

var guidNames = map[string]string{
	"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
	"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
	"bf9679c0-0de6-11d0-a285-00aa003049e2": "member / Self-Membership",
	"f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
	"5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
	"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msDS-AllowedToActOnBehalfOfOtherIdentity",
}

func sidAt(b []byte, off int) (string, int, error) {
	if off < 0 || off+8 > len(b) {
		return "", 0, fmt.Errorf("SID out of range")
	}
	n := 8 + 4*int(b[off+1])
	if off+n > len(b) {
		return "", 0, fmt.Errorf("SID truncated")
	}
	s, err := ldapclient.DecodeObjectSID(b[off : off+n])
	return s, n, err
}

// ParseSD parses a self-relative security descriptor (owner, group, DACL).
func ParseSD(b []byte) (*SD, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("security descriptor too short (%d bytes)", len(b))
	}
	ctl := binary.LittleEndian.Uint16(b[2:4])
	sd := &SD{Control: names(uint32(ctl), sdControl), HasDACL: ctl&0x4 != 0, HasSACL: ctl&0x10 != 0}
	ownerOff := int(binary.LittleEndian.Uint32(b[4:8]))
	groupOff := int(binary.LittleEndian.Uint32(b[8:12]))
	daclOff := int(binary.LittleEndian.Uint32(b[16:20]))
	var err error
	if ownerOff != 0 {
		if sd.Owner, _, err = sidAt(b, ownerOff); err != nil {
			return nil, fmt.Errorf("owner: %v", err)
		}
		sd.OwnerName = SIDName(sd.Owner)
	}
	if groupOff != 0 {
		if sd.Group, _, err = sidAt(b, groupOff); err != nil {
			return nil, fmt.Errorf("group: %v", err)
		}
		sd.GroupName = SIDName(sd.Group)
	}
	if daclOff != 0 && sd.HasDACL {
		if daclOff+8 > len(b) {
			return nil, fmt.Errorf("DACL out of range")
		}
		count := int(binary.LittleEndian.Uint16(b[daclOff+4 : daclOff+6]))
		pos := daclOff + 8
		for i := 0; i < count; i++ {
			if pos+8 > len(b) {
				return nil, fmt.Errorf("ACE %d truncated", i)
			}
			typ, fl := b[pos], b[pos+1]
			size := int(binary.LittleEndian.Uint16(b[pos+2 : pos+4]))
			if size < 8 || pos+size > len(b) {
				return nil, fmt.Errorf("ACE %d has bad size", i)
			}
			ace := ACE{Type: aceTypes[typ], Flags: names(uint32(fl), aceFlags), Mask: binary.LittleEndian.Uint32(b[pos+4 : pos+8])}
			if ace.Type == "" {
				ace.Type = fmt.Sprintf("TYPE_%d", typ)
			}
			ace.Rights = Rights(ace.Mask)
			p := pos + 8
			if typ == 5 || typ == 6 || typ == 7 || typ == 11 || typ == 12 {
				if p+4 > pos+size {
					return nil, fmt.Errorf("ACE %d object flags truncated", i)
				}
				of := binary.LittleEndian.Uint32(b[p : p+4])
				p += 4
				if of&1 != 0 && p+16 <= pos+size {
					ace.ObjectType, _ = ldapclient.DecodeObjectGUID(b[p : p+16])
					ace.ObjectName = guidNames[ace.ObjectType]
					p += 16
				}
				if of&2 != 0 && p+16 <= pos+size {
					ace.Inherited, _ = ldapclient.DecodeObjectGUID(b[p : p+16])
					p += 16
				}
			}
			if ace.Trustee, _, err = sidAt(b, p); err == nil {
				ace.TrusteeName = SIDName(ace.Trustee)
			}
			sd.DACL = append(sd.DACL, ace)
			pos += size
		}
	}
	return sd, nil
}

// ---- presets ----

// Preset is a ready-made search.
type Preset struct {
	Name   string
	Filter string
	Scope  string
	Attrs  string
	AD     bool
}

// Presets returns generic presets plus AD-specific ones when isAD.
func Presets(isAD bool, now time.Time) []Preset {
	since := now.Add(-7 * 24 * time.Hour).UTC().Format("20060102150405.0Z")
	p := []Preset{
		{Name: "Users", Filter: "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))", Scope: "sub", Attrs: "*"},
		{Name: "Groups", Filter: "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=group))", Scope: "sub", Attrs: "*"},
		{Name: "Organizational units", Filter: "(objectClass=organizationalUnit)", Scope: "sub", Attrs: "ou,description"},
		{Name: "Computers / hosts", Filter: "(|(objectClass=computer)(objectClass=ipHost)(objectClass=device))", Scope: "sub", Attrs: "*"},
		{Name: "Service-account-like names", Filter: "(|(uid=svc*)(uid=sa-*)(sAMAccountName=svc*)(sAMAccountName=sa-*)(cn=svc*))", Scope: "sub", Attrs: "*"},
		{Name: "Objects with mail", Filter: "(mail=*)", Scope: "sub", Attrs: "cn,mail"},
		{Name: "Objects with SPNs", Filter: "(servicePrincipalName=*)", Scope: "sub", Attrs: "cn,servicePrincipalName"},
		{Name: "Changed in last 7 days", Filter: "(|(modifyTimestamp>=" + since + ")(whenChanged>=" + since + "))", Scope: "sub", Attrs: "*"},
		{Name: "All entries (one level)", Filter: "(objectClass=*)", Scope: "one", Attrs: "*"},
	}
	if isAD {
		p = append(p,
			Preset{Name: "AD: user accounts", Filter: "(&(objectCategory=person)(objectClass=user))", Scope: "sub", Attrs: "sAMAccountName,cn,mail,userAccountControl", AD: true},
			Preset{Name: "AD: disabled accounts", Filter: "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))", Scope: "sub", Attrs: "sAMAccountName,cn,userAccountControl", AD: true},
			Preset{Name: "AD: password never expires", Filter: "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))", Scope: "sub", Attrs: "sAMAccountName,cn,pwdLastSet", AD: true},
			Preset{Name: "AD: privileged (adminCount=1)", Filter: "(adminCount=1)", Scope: "sub", Attrs: "sAMAccountName,cn,memberOf", AD: true},
			Preset{Name: "AD: computers", Filter: "(objectClass=computer)", Scope: "sub", Attrs: "cn,dNSHostName,operatingSystem,operatingSystemVersion", AD: true},
			Preset{Name: "AD: domain controllers", Filter: "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", Scope: "sub", Attrs: "cn,dNSHostName,operatingSystem", AD: true},
			Preset{Name: "AD: security groups", Filter: "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))", Scope: "sub", Attrs: "cn,groupType,member", AD: true},
			Preset{Name: "AD: group policy objects", Filter: "(objectClass=groupPolicyContainer)", Scope: "sub", Attrs: "displayName,gPCFileSysPath", AD: true},
			Preset{Name: "AD: trusts", Filter: "(objectClass=trustedDomain)", Scope: "sub", Attrs: "cn,trustDirection,trustType,trustAttributes", AD: true},
			Preset{Name: "AD: locked out accounts", Filter: "(&(objectClass=user)(lockoutTime>=1))", Scope: "sub", Attrs: "sAMAccountName,lockoutTime", AD: true},
		)
	}
	return p
}

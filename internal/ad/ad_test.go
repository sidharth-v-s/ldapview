package ad

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

func TestFlagsAndAnnotate(t *testing.T) {
	if got := strings.Join(UACFlags(0x10202), "|"); got != "ACCOUNTDISABLE|NORMAL_ACCOUNT|DONT_EXPIRE_PASSWORD" {
		t.Fatalf("uac = %s", got)
	}
	if got := Annotate("userAccountControl", "514", now); got != "ACCOUNTDISABLE | NORMAL_ACCOUNT" {
		t.Fatalf("annotate uac = %q", got)
	}
	if got := Annotate("groupType", "-2147483646", now); got != "GLOBAL | SECURITY" {
		t.Fatalf("groupType = %q", got)
	}
	if got := Annotate("groupType", "2", now); !strings.Contains(got, "DISTRIBUTION") {
		t.Fatalf("distribution = %q", got)
	}
	if Annotate("sAMAccountType", "805306368", now) != "NORMAL_USER_ACCOUNT" || Annotate("primaryGroupID", "513", now) != "Domain Users" {
		t.Fatal("sam/primary group")
	}
	if Annotate("domainFunctionality", "7", now) != "Windows Server 2016" {
		t.Fatal("functional level")
	}
}

func TestTimes(t *testing.T) {
	// 2026-01-10 00:00:00 UTC as FILETIME
	ft := (time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC).Unix() + 11644473600) * 10_000_000
	got := Annotate("lastLogon", strconv.FormatInt(ft, 10), now)
	if !strings.HasPrefix(got, "2026-01-10 00:00:00 UTC") || !strings.Contains(got, "12h ago") {
		t.Fatalf("filetime = %q", got)
	}
	if !strings.Contains(Annotate("accountExpires", "9223372036854775807", now), "never") || !strings.Contains(Annotate("pwdLastSet", "0", now), "not set") {
		t.Fatal("special filetimes")
	}
	if got := Annotate("whenCreated", "20250101120000.0Z", now); !strings.HasPrefix(got, "2025-01-01 12:00:00 UTC") {
		t.Fatalf("generalized = %q", got)
	}
	if Annotate("cn", "hello", now) != "" {
		t.Fatal("plain value must not be annotated")
	}
}

func TestSIDNames(t *testing.T) {
	for sid, want := range map[string]string{
		"S-1-1-0":             "Everyone",
		"S-1-5-32-544":        "BUILTIN\\Administrators",
		"S-1-5-21-1-2-3-512":  "Domain Admins",
		"S-1-5-21-1-2-3-1105": "",
		"S-1-5-21-1-2-3-500":  "Administrator",
	} {
		if got := SIDName(sid); got != want {
			t.Fatalf("%s = %q want %q", sid, got, want)
		}
	}
}

func sidBytes(auth byte, subs ...uint32) []byte {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, auth}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return b
}

func TestParseSD(t *testing.T) {
	owner := sidBytes(5, 32, 544)
	group := sidBytes(5, 18)
	everyone := sidBytes(1, 0)
	da := sidBytes(5, 21, 1, 2, 3, 512)

	ace1 := append([]byte{0, 0x10, 0, 0, 0x10, 0, 0, 0x10}, everyone...) // ALLOW, INHERITED, GENERIC_ALL (0x10000000)
	binary.LittleEndian.PutUint16(ace1[2:], uint16(len(ace1)))
	guid := []byte{0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	ace2 := []byte{5, 0, 0, 0, 0x00, 0x01, 0, 0, 1, 0, 0, 0}
	ace2 = append(ace2, guid...)
	ace2 = append(ace2, da...)
	binary.LittleEndian.PutUint16(ace2[2:], uint16(len(ace2)))

	dacl := []byte{4, 0, 0, 0, 2, 0, 0, 0}
	dacl = append(dacl, ace1...)
	dacl = append(dacl, ace2...)
	binary.LittleEndian.PutUint16(dacl[2:], uint16(len(dacl)))

	hdr := make([]byte, 20)
	hdr[0] = 1
	binary.LittleEndian.PutUint16(hdr[2:], 0x8004) // SELF_RELATIVE | DACL_PRESENT
	off := 20
	binary.LittleEndian.PutUint32(hdr[4:], uint32(off))
	body := append([]byte{}, owner...)
	off += len(owner)
	binary.LittleEndian.PutUint32(hdr[8:], uint32(off))
	body = append(body, group...)
	off += len(group)
	binary.LittleEndian.PutUint32(hdr[16:], uint32(off))
	body = append(body, dacl...)
	raw := append(hdr, body...)

	sd, err := ParseSD(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Owner != "S-1-5-32-544" || sd.OwnerName != "BUILTIN\\Administrators" || sd.GroupName != "Local System" {
		t.Fatalf("owner/group: %+v", sd)
	}
	if len(sd.DACL) != 2 {
		t.Fatalf("aces = %d", len(sd.DACL))
	}
	a := sd.DACL[0]
	if a.Type != "ALLOW" || a.TrusteeName != "Everyone" || a.Rights[0] != "GenericAll(FullControl)" || len(a.Flags) != 1 || a.Flags[0] != "INHERITED" {
		t.Fatalf("ace1: %+v", a)
	}
	b := sd.DACL[1]
	if b.Type != "ALLOW_OBJECT" || b.ObjectType != "00299570-246d-11d0-a768-00aa006e0529" || b.ObjectName != "User-Force-Change-Password" || b.TrusteeName != "Domain Admins" {
		t.Fatalf("ace2: %+v", b)
	}
	if _, err := ParseSD(raw[:30]); err == nil {
		t.Fatal("truncated SD must fail")
	}
}

func TestPresets(t *testing.T) {
	g := Presets(false, now)
	a := Presets(true, now)
	if len(a) <= len(g) {
		t.Fatal("AD presets must add entries")
	}
	for _, p := range g {
		if p.AD {
			t.Fatal("generic list must not contain AD presets")
		}
	}
	if !strings.Contains(g[7].Filter, "20260103120000.0Z") {
		t.Fatalf("recent preset: %s", g[7].Filter)
	}
}

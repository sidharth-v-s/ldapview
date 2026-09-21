package ldapclient

import "testing"

func TestDecodeObjectSID(t *testing.T) {
	// S-1-5-21-1-2-3-500
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5,
		21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xf4, 1, 0, 0}
	got, err := DecodeObjectSID(b)
	if err != nil || got != "S-1-5-21-1-2-3-500" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := DecodeObjectSID([]byte{1, 2}); err == nil {
		t.Fatal("expected error for short SID")
	}
	if _, err := DecodeObjectSID([]byte{1, 5, 0, 0, 0, 0, 0, 5, 1}); err == nil {
		t.Fatal("expected error for truncated SID")
	}
}

func TestDecodeObjectGUID(t *testing.T) {
	// AD mixed-endian encoding of 33221100-5544-7766-8899-aabbccddeeff
	b := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	got, err := DecodeObjectGUID(b)
	if err != nil || got != "33221100-5544-7766-8899-aabbccddeeff" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := DecodeObjectGUID(b[:10]); err == nil {
		t.Fatal("expected error for bad length")
	}
}

func TestHexDumpAndBase64(t *testing.T) {
	if got := Base64String([]byte{0, 1, 2}); got != "AAEC" {
		t.Fatalf("base64 = %q", got)
	}
	if HexDump([]byte("hi")) == "" {
		t.Fatal("empty hexdump")
	}
}

func TestLooksBinary(t *testing.T) {
	if !looksBinary("objectSid", [][]byte{[]byte("abc")}) {
		t.Fatal("objectSid should be binary")
	}
	if !looksBinary("x", [][]byte{{0x00, 0x01}}) {
		t.Fatal("control bytes should be binary")
	}
	if looksBinary("cn", [][]byte{[]byte("Alice")}) {
		t.Fatal("plain text should not be binary")
	}
}

func TestEncodeSIDGUIDRoundTrip(t *testing.T) {
	for _, s := range []string{"S-1-5-21-1-2-3-500", "S-1-5-32-544", "S-1-1-0"} {
		b, err := EncodeSID(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := DecodeObjectSID(b); got != s {
			t.Fatalf("SID roundtrip %s -> %s", s, got)
		}
	}
	for _, bad := range []string{"", "X-1-5", "S-1", "S-1-5-abc", "S-1-5-99999999999"} {
		if _, err := EncodeSID(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
	g := "33221100-5544-7766-8899-aabbccddeeff"
	b, err := EncodeGUID(g)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := DecodeObjectGUID(b); got != g {
		t.Fatalf("GUID roundtrip %s", got)
	}
	if EscapeBinaryFilter([]byte{0x01, 0xff}) != `\01\ff` {
		t.Fatal("escape")
	}
}

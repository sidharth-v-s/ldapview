package ldapclient

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// HexDump renders b as a classic hex+ASCII dump, 16 bytes per line.
func HexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]
		fmt.Fprintf(&sb, "%08x  ", i)
		for j := 0; j < 16; j++ {
			if j < len(chunk) {
				fmt.Fprintf(&sb, "%02x ", chunk[j])
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for _, c := range chunk {
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

// Base64String encodes b as standard base64 (useful for LDIF, copy, etc).
func Base64String(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeObjectSID decodes an Active Directory objectSid binary value into
// its S-1-... string form.
func DecodeObjectSID(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("objectSid too short: %d bytes", len(b))
	}
	revision := b[0]
	subAuthorityCount := int(b[1])
	// authority is a 48-bit big-endian value in bytes 2-7
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}
	if len(b) < 8+4*subAuthorityCount {
		return "", fmt.Errorf("objectSid truncated")
	}
	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthorityCount; i++ {
		off := 8 + i*4
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		sid += fmt.Sprintf("-%d", sub)
	}
	return sid, nil
}

// DecodeObjectGUID decodes an Active Directory objectGUID binary value
// (mixed-endian) into standard GUID string form.
func DecodeObjectGUID(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("objectGUID must be 16 bytes, got %d", len(b))
	}
	// AD stores GUIDs with the first three components little-endian.
	reordered := []byte{
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
	}
	u, err := uuid.FromBytes(reordered)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

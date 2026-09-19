package ldapclient

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// resultCodeMessages maps common LDAP result codes to human-readable
// descriptions (RFC 4511 section 4.1.9).
var resultCodeMessages = map[uint16]string{
	0:  "Success",
	1:  "Operations Error",
	2:  "Protocol Error",
	3:  "Time Limit Exceeded",
	4:  "Size Limit Exceeded",
	10: "Referral",
	32: "No Such Object",
	34: "Invalid DN Syntax",
	48: "Inappropriate Authentication",
	49: "Invalid Credentials",
	50: "Insufficient Access Rights",
	51: "Busy",
	52: "Unavailable",
	53: "Unwilling To Perform",
	65: "Object Class Violation",
	66: "Not Allowed On Non-Leaf (entry has children)",
	68: "Entry Already Exists",
}

// FriendlyError wraps an underlying LDAP error with a human-readable
// summary while preserving the raw error for display on request
// (spec section 46: "Also provide the raw LDAP result when requested").
type FriendlyError struct {
	Code    uint16
	Message string
	Raw     error
}

func (e *FriendlyError) Error() string {
	return e.Message
}

func (e *FriendlyError) Unwrap() error {
	return e.Raw
}

// RawString returns the original, unmodified LDAP error text.
func (e *FriendlyError) RawString() string {
	if e.Raw == nil {
		return ""
	}
	return e.Raw.Error()
}

// TranslateError converts a raw error (typically an *ldap.Error) into a
// FriendlyError with a human-readable message, when possible. Non-LDAP
// errors (e.g. network failures) are passed through unchanged.
func TranslateError(err error) error {
	if err == nil {
		return nil
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		code := ldapErr.ResultCode
		msg, known := resultCodeMessages[code]
		if !known {
			msg = fmt.Sprintf("LDAP Result Code %d", code)
		}
		return &FriendlyError{Code: code, Message: msg, Raw: err}
	}
	return err
}

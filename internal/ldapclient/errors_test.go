package ldapclient

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestTranslateError(t *testing.T) {
	if TranslateError(nil) != nil {
		t.Fatal("nil should stay nil")
	}
	err := TranslateError(&ldap.Error{ResultCode: 49, Err: errors.New("bad creds")})
	fe, ok := err.(*FriendlyError)
	if !ok || fe.Message != "Invalid Credentials" || fe.Code != 49 {
		t.Fatalf("unexpected: %#v", err)
	}
	if fe.RawString() == "" {
		t.Fatal("raw string should be preserved")
	}
	fe2 := TranslateError(&ldap.Error{ResultCode: 999, Err: errors.New("x")}).(*FriendlyError)
	if fe2.Message != "LDAP Result Code 999" {
		t.Fatalf("unknown code msg: %q", fe2.Message)
	}
	plain := errors.New("network down")
	if TranslateError(plain) != plain {
		t.Fatal("non-LDAP errors must pass through")
	}
}

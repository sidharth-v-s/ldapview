package ldapclient

import "testing"

func TestDetectServer(t *testing.T) {
	cases := []struct {
		d    *RootDSE
		name string
		conf string
	}{
		{nil, "unknown", "low"},
		{&RootDSE{SupportedCapabilities: []string{"1.2.840.113556.1.4.800"}}, "Microsoft Active Directory", "high"},
		{&RootDSE{VendorName: "OpenLDAP Foundation"}, "OpenLDAP", "high"},
		{&RootDSE{Attrs: map[string][]string{"objectClass": {"top", "OpenLDAProotDSE"}}}, "OpenLDAP", "high"},
		{&RootDSE{VendorName: "389 Project"}, "389 Directory Server", "medium"},
		{&RootDSE{VendorName: "Something Else"}, "Something Else", "low"},
		{&RootDSE{}, "unknown", "low"},
	}
	for _, c := range cases {
		g := DetectServer(c.d)
		if g.Name != c.name || g.Confidence != c.conf {
			t.Fatalf("DetectServer(%+v) = %+v, want name=%s conf=%s", c.d, g, c.name, c.conf)
		}
		if len(g.Reasons) == 0 {
			t.Fatalf("expected reasons for %+v", c.d)
		}
	}
}

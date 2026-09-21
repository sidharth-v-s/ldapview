// Package oid names well-known LDAP controls, extended operations and features.
package oid

var names = map[string]string{
	// controls
	"1.2.840.113556.1.4.319":    "Simple Paged Results",
	"1.2.840.113556.1.4.473":    "Server-Side Sort (request)",
	"1.2.840.113556.1.4.474":    "Server-Side Sort (response)",
	"2.16.840.1.113730.3.4.2":   "ManageDsaIT",
	"2.16.840.1.113730.3.4.9":   "Virtual List View (request)",
	"2.16.840.1.113730.3.4.10":  "Virtual List View (response)",
	"2.16.840.1.113730.3.4.3":   "Persistent Search",
	"2.16.840.1.113730.3.4.18":  "Proxied Authorization",
	"1.2.840.113556.1.4.417":    "Show Deleted Objects",
	"1.2.840.113556.1.4.2064":   "Show Recycled Objects",
	"1.2.840.113556.1.4.841":    "DirSync",
	"1.2.840.113556.1.4.801":    "SD Flags",
	"1.2.840.113556.1.4.805":    "Tree Delete",
	"1.2.840.113556.1.4.529":    "Extended DN",
	"1.2.840.113556.1.4.528":    "Change Notification",
	"1.2.840.113556.1.4.1339":   "Domain Scope",
	"1.2.840.113556.1.4.1413":   "Permissive Modify",
	"1.2.840.113556.1.4.1504":   "Attribute Scoped Query",
	"1.3.6.1.1.12":              "Assertion",
	"1.3.6.1.1.13.1":            "Pre-Read",
	"1.3.6.1.1.13.2":            "Post-Read",
	"1.3.6.1.4.1.4203.1.10.1":   "Subentries",
	"1.3.6.1.4.1.42.2.27.8.5.1": "Password Policy",
	"1.2.826.0.1.3344810.2.3":   "Matched Values",
	"1.3.6.1.4.1.4203.666.5.12": "Relax Rules",
	// extended operations
	"1.3.6.1.4.1.1466.20037":     "StartTLS",
	"1.3.6.1.4.1.4203.1.11.1":    "Password Modify",
	"1.3.6.1.4.1.4203.1.11.3":    "Who am I?",
	"1.3.6.1.1.8":                "Cancel",
	"1.3.6.1.1.21.1":             "Start Transaction",
	"1.3.6.1.1.21.3":             "End Transaction",
	"1.3.6.1.4.1.1466.101.119.1": "Dynamic Refresh",
	// features
	"1.3.6.1.1.14":           "Modify-Increment",
	"1.3.6.1.4.1.4203.1.5.1": "All Operational Attributes",
	"1.3.6.1.4.1.4203.1.5.2": "Requesting Attributes by Object Class",
	"1.3.6.1.4.1.4203.1.5.3": "True/False Filters",
	"1.3.6.1.4.1.4203.1.5.4": "Language Tag Options",
	"1.3.6.1.4.1.4203.1.5.5": "Language Range Options",
	// AD capability
	"1.2.840.113556.1.4.800": "Active Directory",
}

// Well-known OIDs used by the client.
const (
	Paging       = "1.2.840.113556.1.4.319"
	ServerSort   = "1.2.840.113556.1.4.473"
	ManageDsaIT  = "2.16.840.1.113730.3.4.2"
	ShowDeleted  = "1.2.840.113556.1.4.417"
	ShowRecycled = "1.2.840.113556.1.4.2064"
	SDFlags      = "1.2.840.113556.1.4.801"
	WhoAmI       = "1.3.6.1.4.1.4203.1.11.3"
	ADCapability = "1.2.840.113556.1.4.800"
	DirSync      = "1.2.840.113556.1.4.841"
	VLVRequest   = "2.16.840.1.113730.3.4.9"
	VLVResponse  = "2.16.840.1.113730.3.4.10"
)

// Name returns the friendly name of an OID, or "".
func Name(o string) string { return names[o] }

// Label returns "oid (name)" when the name is known, else the bare OID.
func Label(o string) string {
	if n := names[o]; n != "" {
		return o + "  (" + n + ")"
	}
	return o
}

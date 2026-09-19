// Package model holds TUI-agnostic domain state: the directory tree,
// search history, bookmarks, and operation log.
package model

import "time"

// Node is one entry in the lazily-loaded directory tree.
type Node struct {
	DN          string
	ObjectClass []string
	Parent      *Node
	Children    []*Node
	Loaded      bool // whether ExpandOneLevel has been called for this node
	Expanded    bool // UI expand/collapse state
	Loading     bool
	KnownLeaf   bool // server said hasSubordinates=FALSE
}

// IsLeaf reports whether this node has been loaded and found to have
// no children. Unloaded nodes are optimistically treated as expandable.
func (n *Node) IsLeaf() bool {
	return n.KnownLeaf || (n.Loaded && len(n.Children) == 0)
}

// Visible flattens the tree into the currently visible rows (respecting
// Expanded state) for rendering in a list/table widget.
func Visible(root *Node) []*Node {
	var out []*Node
	var walk func(n *Node)
	walk = func(n *Node) {
		out = append(out, n)
		if n.Expanded {
			for _, c := range n.Children {
				walk(c)
			}
		}
	}
	if root != nil {
		walk(root)
	}
	return out
}

// Depth returns how many ancestors n has, for indentation.
func (n *Node) Depth() int {
	d := 0
	for p := n.Parent; p != nil; p = p.Parent {
		d++
	}
	return d
}

// OperationKind identifies the type of LDAP operation logged in the
// session operation history (spec section 28/48).
type OperationKind string

const (
	OpBind     OperationKind = "BIND"
	OpSearch   OperationKind = "SEARCH"
	OpRead     OperationKind = "READ"
	OpModify   OperationKind = "MODIFY"
	OpAdd      OperationKind = "ADD"
	OpDelete   OperationKind = "DELETE"
	OpModifyDN OperationKind = "MODDN"
)

// Operation is one entry in the session's operation audit log. Never
// stores passwords or other authentication secrets.
type Operation struct {
	Time    time.Time
	Kind    OperationKind
	Target  string // DN or search base
	Detail  string
	Success bool
	Err     string
}

// SavedSearch is a bookmarked search (spec section 21).
type SavedSearch struct {
	Name   string
	Base   string
	Scope  int
	Filter string
	Attrs  []string
}

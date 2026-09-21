package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ad"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/schema"
	"github.com/zoro/ldapview/internal/store"
)

type statusMsg struct {
	text  string
	isErr bool
}

func statusCmd(text string, isErr bool) tea.Cmd {
	return func() tea.Msg { return statusMsg{text: text, isErr: isErr} }
}

func msgCmd(m tea.Msg) tea.Cmd { return func() tea.Msg { return m } }

// cmdMsg carries a palette command line.
type cmdMsg struct{ line string }

type connectRequestMsg struct {
	conn store.Connection
	test bool
}

type doConnectMsg struct {
	conn     store.Connection
	password string
	test     bool
}

type connectResultMsg struct {
	client *ldapclient.Client
	conn   store.Connection
	err    error
	test   bool
	warns  []string
	info   []string
}

type cancelPromptMsg struct{}
type disconnectMsg struct{}
type backMsg struct{}

type openScreenMsg struct{ s screen }

// gotoMsg asks the browser to reveal and load a DN.
type gotoMsg struct{ dn string }

type openBinaryMsg struct {
	attrName string
	data     []byte
}

type openRootDSEMsg struct{}
type openSearchMsg struct {
	base   string
	filter string
}
type openSchemaMsg struct{ query string }
type openFilterMsg struct{ raw string }
type applyFilterMsg struct{ filter string }
type openReferralMsg struct{ url string }

// browser data
type rootsLoadedMsg struct {
	dse   *ldapclient.RootDSE
	roots []string
	err   error
}

type childrenLoadedMsg struct {
	dn       string
	children []ldapclient.Child
	err      error
}

type entryLoadedMsg struct {
	entry *ldapclient.Entry
	err   error
}

type relLoadedMsg struct {
	dn      string
	reverse []string
	err     error
}

type sdLoadedMsg struct {
	dn  string
	sd  *ad.SD
	err error
}

type schemaLoadedMsg struct {
	s   *schema.Schema
	err error
}

type needSchemaMsg struct{}

// write requests emitted by the browser
type editValueMsg struct{ dn, attr, old string }
type addValueMsg struct{ dn, attr string }
type delValueMsg struct{ dn, attr, val string }
type deleteEntryMsg struct{ dn string }
type addEntryMsg struct{ parent string }
type modDNMsg struct{ dn string }
type exportEntryMsg struct {
	path  string
	entry *ldapclient.Entry
}

// opDoneMsg reports a completed directory operation.
type opDoneMsg struct {
	desc            string
	failDesc        string // wording for the failure message ("delete X")
	err             error
	refreshEntry    string   // DN whose entry to reload
	refreshChildren []string // DNs whose children to reload
	selectDN        string
	clearEntry      bool
}

type searchDoneMsg struct {
	out  *ldapclient.SearchOutcome
	err  error
	page int
}

type importDoneMsg struct {
	applied, total int
	err            error
}

type diffMsg struct{}

type openExtOpMsg struct{ oid string }
type openFollowReferralMsg struct{ url string }

type referralConnectedMsg struct {
	client              *ldapclient.Client
	conn                store.Connection
	base, scope, filter string
}

type refChoice struct {
	url    string
	follow bool
}

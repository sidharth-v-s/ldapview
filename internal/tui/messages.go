package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/model"
	"github.com/zoro/ldapview/internal/store"
)

type statusMsg struct {
	text  string
	isErr bool
}

func statusCmd(text string, isErr bool) tea.Cmd {
	return func() tea.Msg { return statusMsg{text: text, isErr: isErr} }
}

// connectRequestMsg is emitted when the user picks a connection to open;
// it routes to the password prompt screen.
type connectRequestMsg struct {
	conn store.Connection
}

// doConnectMsg is emitted once the password prompt is submitted (or
// skipped for anonymous binds), carrying the password only in memory.
type doConnectMsg struct {
	conn     store.Connection
	password string
}

type connectResultMsg struct {
	client *ldapclient.Client
	err    error
}

func (a App) performConnect(conf store.Connection, password string) tea.Cmd {
	return func() tea.Msg {
		client, err := ldapclient.Connect(conf)
		if err != nil {
			return connectResultMsg{err: err}
		}
		if err := client.Bind(password); err != nil {
			client.Close()
			return connectResultMsg{err: err}
		}
		return connectResultMsg{client: client}
	}
}

type openRootDSEMsg struct {
	dse *ldapclient.RootDSE
}

type openSearchMsg struct {
	base string
}

type openBinaryMsg struct {
	attrName string
	data     []byte
}

type backToBrowserMsg struct{}

type disconnectMsg struct{}

type opLogMsg struct {
	op model.Operation
}

type cancelPromptMsg struct{}

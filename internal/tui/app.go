// Package tui implements the ldapview terminal UI using Bubble Tea.
package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/ldapclient"
	"github.com/zoro/ldapview/internal/model"
	"github.com/zoro/ldapview/internal/store"
)

// screen identifies which top-level view is active.
type screen int

const (
	screenConnections screen = iota
	screenPasswordPrompt
	screenBrowser
	screenSearch
	screenRootDSE
	screenHelp
	screenBinaryView
)

// App is the root Bubble Tea model. It owns shared state and delegates
// rendering/update to the active screen.
type App struct {
	screen    screen
	width     int
	height    int
	statusMsg string
	statusErr bool

	store  *store.Store
	client *ldapclient.Client
	active store.Connection

	// screens
	connections connectionsModel
	pwPrompt    passwordPromptModel
	browser     browserModel
	search      searchModel
	rootDSE     rootDSEModel
	help        helpModel
	binaryView  binaryViewModel

	previousScreen screen // for returning from help/binary overlays

	operations []model.Operation
}

// NewApp constructs the initial application model.
func NewApp(s *store.Store) App {
	return App{
		screen:      screenConnections,
		store:       s,
		connections: newConnectionsModel(s),
		help:        newHelpModel(),
	}
}

func (a App) Init() tea.Cmd {
	return nil
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.connections.setSize(msg.Width, msg.Height)
		a.browser.setSize(msg.Width, msg.Height)
		a.search.setSize(msg.Width, msg.Height)
		return a, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			a.closeClient()
			return a, tea.Quit
		}
		if msg.String() == "?" && a.screen != screenHelp && a.screen != screenPasswordPrompt {
			a.previousScreen = a.screen
			a.screen = screenHelp
			return a, nil
		}
		if a.screen == screenHelp {
			if msg.String() == "?" || msg.String() == "q" || msg.String() == "esc" {
				a.screen = a.previousScreen
			}
			return a, nil
		}

	case statusMsg:
		a.statusMsg = msg.text
		a.statusErr = msg.isErr
		return a, nil

	case connectRequestMsg:
		a.active = msg.conn
		a.pwPrompt = newPasswordPromptModel(msg.conn)
		a.screen = screenPasswordPrompt
		return a, nil

	case doConnectMsg:
		return a, a.performConnect(msg.conn, msg.password)

	case connectResultMsg:
		if msg.err != nil {
			a.statusMsg = fmt.Sprintf("connect failed: %s", friendlyErr(msg.err))
			a.statusErr = true
			a.screen = screenConnections
			return a, nil
		}
		a.client = msg.client
		a.browser = newBrowserModel(a.client, a.active)
		a.browser.setSize(a.width, a.height)
		a.screen = screenBrowser
		a.statusMsg = fmt.Sprintf("connected to %s", a.active.URL())
		a.statusErr = false
		a.logOp(model.Operation{Time: time.Now(), Kind: model.OpBind, Target: a.active.URL(), Success: true})
		return a, a.browser.loadRootCmd()

	case openRootDSEMsg:
		a.rootDSE = newRootDSEModel(msg.dse)
		a.previousScreen = a.screen
		a.screen = screenRootDSE
		return a, nil

	case openSearchMsg:
		a.search = newSearchModel(a.client, msg.base)
		a.search.setSize(a.width, a.height)
		a.previousScreen = a.screen
		a.screen = screenSearch
		return a, nil

	case openBinaryMsg:
		a.binaryView = newBinaryViewModel(msg.attrName, msg.data)
		a.previousScreen = a.screen
		a.screen = screenBinaryView
		return a, nil

	case backToBrowserMsg:
		a.screen = screenBrowser
		return a, nil

	case cancelPromptMsg:
		a.screen = screenConnections
		return a, nil

	case disconnectMsg:
		a.closeClient()
		a.screen = screenConnections
		a.statusMsg = "disconnected"
		return a, nil

	case opLogMsg:
		a.logOp(msg.op)
		return a, nil
	}

	var cmd tea.Cmd
	switch a.screen {
	case screenConnections:
		a.connections, cmd = a.connections.update(msg)
	case screenPasswordPrompt:
		a.pwPrompt, cmd = a.pwPrompt.update(msg)
	case screenBrowser:
		a.browser, cmd = a.browser.update(msg)
	case screenSearch:
		a.search, cmd = a.search.update(msg)
	case screenRootDSE:
		a.rootDSE, cmd = a.rootDSE.update(msg)
	case screenBinaryView:
		a.binaryView, cmd = a.binaryView.update(msg)
	}
	return a, cmd
}

func (a App) View() string {
	var body string
	switch a.screen {
	case screenConnections:
		body = a.connections.view()
	case screenPasswordPrompt:
		body = a.pwPrompt.view()
	case screenBrowser:
		body = a.browser.view()
	case screenSearch:
		body = a.search.view()
	case screenRootDSE:
		body = a.rootDSE.view()
	case screenHelp:
		body = a.help.view()
	case screenBinaryView:
		body = a.binaryView.view()
	}
	return body + "\n" + a.statusBar()
}

func (a App) statusBar() string {
	style := statusBarStyle
	if a.statusErr {
		style = statusBarErrStyle
	}
	name := "ldapview"
	if a.client != nil {
		name = fmt.Sprintf("ldapview | %s | connected", a.active.Name)
	}
	msg := a.statusMsg
	if msg == "" {
		msg = "? help  :quit with q or ctrl+c"
	}
	w := a.width
	if w <= 0 {
		w = 80
	}
	return style.Width(w).MaxWidth(w).Render(fmt.Sprintf(" %s — %s", name, msg))
}

func (a *App) closeClient() {
	if a.client != nil {
		a.client.Close()
		a.client = nil
	}
}

func (a *App) logOp(op model.Operation) {
	a.operations = append(a.operations, op)
	if len(a.operations) > 500 {
		a.operations = a.operations[len(a.operations)-500:]
	}
}

func friendlyErr(err error) string {
	if fe, ok := err.(*ldapclient.FriendlyError); ok {
		return fe.Message
	}
	return err.Error()
}

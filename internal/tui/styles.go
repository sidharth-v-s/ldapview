package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

	activePaneStyle = paneStyle.Copy().
			BorderForeground(lipgloss.Color("62"))

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("236"))

	statusBarErrStyle = statusBarStyle.Copy().
				Foreground(lipgloss.Color("15")).
				Background(lipgloss.Color("124"))

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("214"))

	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	attrNameStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("117"))

	binaryTagStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("208")).
			Italic(true)

	helpKeyStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("214"))

	warnStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
)

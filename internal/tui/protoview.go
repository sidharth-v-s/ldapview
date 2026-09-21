package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zoro/ldapview/internal/proto"
)

type protoModel struct {
	sh      *shared
	cur     int
	follow  bool
	hex     bool
	dscroll int
	height  int
}

func newProtoModel(sh *shared) protoModel { return protoModel{sh: sh, follow: true} }

func (m protoModel) update(msg tea.Msg) (protoModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok || m.sh.client == nil {
		return m, nil
	}
	msgs := m.sh.client.ProtoLog().Messages()
	if m.follow {
		m.cur = len(msgs) - 1
	}
	switch k.String() {
	case "j", "down":
		if m.cur < len(msgs)-1 {
			m.cur++
			m.dscroll = 0
		}
		m.follow = m.cur == len(msgs)-1
	case "k", "up":
		if m.cur > 0 {
			m.cur--
			m.dscroll = 0
		}
		m.follow = false
	case "G", "end":
		m.follow = true
		m.dscroll = 0
	case "J", "pgdown":
		m.dscroll += 8
	case "K", "pgup":
		m.dscroll = max(m.dscroll-8, 0)
	case "h":
		m.hex = !m.hex
		m.dscroll = 0
	case "y":
		if m.cur >= 0 && m.cur < len(msgs) {
			return m, copyCmd(strings.Join(msgs[m.cur].Tree, "\n"), "message tree")
		}
	case "c":
		m.sh.client.ProtoLog().Clear()
		m.cur = 0
		return m, statusCmd("protocol log cleared", false)
	case "q", "esc":
		return m, msgCmd(backMsg{})
	}
	return m, nil
}

func (m protoModel) detail(msg proto.Message) []string {
	var out []string
	if m.hex {
		switch {
		case msg.RawHidden:
			out = append(out, "raw bytes hidden: this message type may contain credentials")
		case msg.Raw == nil:
			out = append(out, "no raw bytes for this entry")
		default:
			out = append(out, strings.Split(strings.TrimRight(proto.HexDump(msg.Raw), "\n"), "\n")...)
		}
		return out
	}
	out = append(out, msg.Tree...)
	if msg.RawHidden {
		out = append(out, "", "(raw bytes hidden: message may contain credentials; secrets are masked above)")
	}
	return out
}

func (m protoModel) view(w, h int) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Raw LDAP protocol") + "\n")
	if m.sh.client == nil {
		return b.String()
	}
	msgs := m.sh.client.ProtoLog().Messages()
	cur := m.cur
	if m.follow {
		cur = len(msgs) - 1
	}
	total := max(h-4, 10)
	listRows := max(total/2-1, 4)
	detRows := max(total-listRows-2, 4)
	start := max(cur-listRows+1, 0)
	b.WriteString(dimStyle.Render(fmt.Sprintf("  %d messages — encrypted transports are captured above the TLS layer", len(msgs))) + "\n")
	for i := start; i < len(msgs) && i < start+listRows; i++ {
		x := msgs[i]
		line := fmt.Sprintf("#%-4d %s %-4s %-16s %s", x.Seq, x.Time.Format("15:04:05.000"), x.Dir, x.Op, x.Summary)
		line = truncate(line, w-1)
		if i == cur {
			line = selectedStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	for i := min(len(msgs), start+listRows) - start; i < listRows; i++ {
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat("─", max(w-1, 1)) + "\n")
	if cur >= 0 && cur < len(msgs) {
		ls := m.detail(msgs[cur])
		ds := min(m.dscroll, max(len(ls)-1, 0))
		for i := ds; i < len(ls) && i < ds+detRows; i++ {
			b.WriteString(truncate(ls[i], w-1) + "\n")
		}
	}
	b.WriteString(dimStyle.Render("j/k message  J/K scroll detail  h hex  y copy  c clear  G follow  q back"))
	return b.String()
}

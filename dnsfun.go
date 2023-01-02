package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

func init() {
	_ = configureLogger()
}

const (
	hotPink         = lipgloss.Color("#FF06B7")
	logFile         = "dnsfun.log"
	errorRed        = lipgloss.Color("#FF5733")
	googleDNSServer = "8.8.8.8:53"
)

var (
	logger       zerolog.Logger
	inputStyle   = lipgloss.NewStyle().Foreground(hotPink)
	errorStyle   = lipgloss.NewStyle().Foreground(errorRed)
	domainPrompt = inputStyle.Render("Enter a domain name:")
	aRecordLabel = inputStyle.Render("A Record:")
	cnamesLabel  = inputStyle.Render("CName Records:")
	errLabel     = errorStyle.Render("Error Messages:")
)

func main() {
	p := tea.NewProgram(initialModel())
	_, err := p.Run()
	if err != nil {
		log.Fatal(err)
	}
}

type (
	errMsg error
)

type model struct {
	textInput textinput.Model
	arecord   string
	cnames    []string
	errMsg    string
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEnter:
			arecord, err := getDnsARecord(m.textInput.Value())
			var errMsg strings.Builder
			if err != nil {
				errMsg.WriteString(fmt.Sprintf("%s\n", err.Error()))
			}
			cnames, err := getDnsCNames(m.textInput.Value())
			if err != nil {
				errMsg.WriteString(fmt.Sprintf("%s\n", err.Error()))
			}
			m.arecord = arecord
			m.cnames = cnames
			m.errMsg = errMsg.String()
			return m, nil
		}
	}
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

// View renders the UI
func (m model) View() string {
	if m.errMsg != "" {
		return fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s\n%s\n%s\n%s",
			domainPrompt,
			m.textInput.View(),
			aRecordLabel,
			m.arecord,
			cnamesLabel,
			m.cnames,
			errLabel,
			strings.TrimRight(m.errMsg, "\n"),
		)
	}
	return fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s\n%s",
		domainPrompt,
		m.textInput.View(),
		aRecordLabel,
		m.arecord,
		cnamesLabel,
		m.cnames,
	)
}

func initialModel() model {
	ti := textinput.New()
	ti.BackgroundStyle = lipgloss.NewStyle().BorderBackground(lipgloss.Color("#D9DCCF")).Background(lipgloss.Color("#D9DCCF"))
	ti.Focus()
	ti.CharLimit = 100
	ti.Width = 30

	return model{
		textInput: ti,
		arecord:   "",
		errMsg:    "",
	}
}

func configureLogger() func() error {
	file, err := os.OpenFile(
		logFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0664,
	)
	if err != nil {
		panic(err)
	}

	logger = zerolog.New(file).With().Timestamp().Logger()

	return file.Close
}

// getDnsARecord return the A Record for a given domain
func getDnsARecord(domain string) (string, error) {
	var msg dns.Msg
	fqdn := dns.Fqdn(domain)
	msg.SetQuestion(fqdn, dns.TypeA)
	msgResp, err := dns.Exchange(&msg, googleDNSServer)
	if err != nil {
		return "", err
	}
	if len(msgResp.Answer) < 1 {
		return "", errors.New("no DNS A record returned")
	}
	for _, answer := range msgResp.Answer {
		if a, ok := answer.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", errors.New("No A record for domain")
}

func getDnsCNames(fqdn string) ([]string, error) {
	var m dns.Msg
	var fqdns []string
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	in, err := dns.Exchange(&m, googleDNSServer)
	if err != nil {
		return fqdns, err
	}
	if len(in.Answer) < 1 {
		return fqdns, errors.New("no DNS CName records returned")
	}
	for _, answer := range in.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			fqdns = append(fqdns, cname.Target)
		}
	}
	return fqdns, nil
}

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
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

type cnameResult struct {
	IPAddress string
	Hostname  string
}

func (i cnameResult) Title() string {
	return "ugh title"
	// return i.IPAddress
}
func (i cnameResult) Description() string {
	return "ugh descp"
	// return i.Hostname
}
func (i cnameResult) FilterValue() string {
	return "A record baby"
}

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
	textInput   textinput.Model
	displayList list.Model
	arecords    []cnameResult
	cnames      []string
	errMsg      string
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
			arecords, err := getDnsARecord(m.textInput.Value())
			var errMsg strings.Builder
			if err != nil {
				errMsg.WriteString(fmt.Sprintf("%s\n", err.Error()))
			}
			// cnames, err := getDnsCNames(m.textInput.Value())
			// if err != nil {
			// 	errMsg.WriteString(fmt.Sprintf("%s\n", err.Error()))
			// }
			m.arecords = arecords

			var items []list.Item
			for _, arecord := range m.arecords {
				items = append(items, arecord)
			}
			displayList := list.New(items, list.NewDefaultDelegate(), 0, 0)
			displayList.SetFilteringEnabled(false)
			m.displayList = displayList
			// m.cnames = cnames
			m.errMsg = errMsg.String()

			m.displayList, cmd = m.displayList.Update(msg)
			// displayList.FilterInput.Focus()
			return m, cmd
		}
	}
	var cmds []tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	cmds = append(cmds, cmd)
	m.displayList, cmd = m.displayList.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

// View renders the UI
func (m model) View() string {
	// logger.Debug().Msg(fmt.Sprintf("%+v", items))
	if m.errMsg != "" {
		logger.Error().Msg(m.errMsg)
		return fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s\n%s",
			domainPrompt,
			m.textInput.View(),
			aRecordLabel,
			m.displayList.View(),
			// cnamesLabel,
			// m.cnames,
			errLabel,
			strings.TrimRight(m.errMsg, "\n"),
		)
	}
	// arecordsSb := strings.Builder{}
	// for _, arecord := range m.arecords {
	// 	arecordsSb.WriteString(fmt.Sprintf("%s\n", arecord.IPAddress))
	// }
	if len(m.arecords) > 0 {
		logger.Debug().Msg(fmt.Sprintf("height: %+v", m.displayList.Height()))
		// displayList.SetHeight(10)
		return fmt.Sprintf("%s\n%s\n\n%s\n%v\n%s\n%s",
			domainPrompt,
			m.textInput.View(),
			aRecordLabel,
			m.displayList.View(),
			cnamesLabel,
			m.cnames,
		)
	}
	// return fmt.Sprintf("%s%s%s",
	// 	domainPrompt,
	// 	m.textInput.View(),
	// 	m.displayList.View(),
	// )
	return fmt.Sprintf("%s\n%s\n\n%s\n%v\n%s\n%s",
		domainPrompt,
		m.textInput.View(),
		aRecordLabel,
		m.displayList.View(),
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
		textInput:   ti,
		arecords:    []cnameResult{},
		errMsg:      "",
		cnames:      []string{},
		displayList: list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0),
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
func getDnsARecord(domain string) ([]cnameResult, error) {
	var msg dns.Msg
	fqdn := dns.Fqdn(domain)
	msg.SetQuestion(fqdn, dns.TypeA)
	msgResp, err := dns.Exchange(&msg, googleDNSServer)
	if err != nil {
		return []cnameResult{}, err
	}
	if len(msgResp.Answer) < 1 {
		return []cnameResult{}, errors.New("no A record returned")
	}
	var results []cnameResult
	for _, answer := range msgResp.Answer {
		if a, ok := answer.(*dns.A); ok {
			results = append(results, cnameResult{fqdn, a.A.String()})
		}
	}
	return results, nil
}

// getDnsCNames return the CNAMEs for a given domain
func getDnsCNames(fqdn string) ([]string, error) {
	var m dns.Msg
	var fqdns []string
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	in, err := dns.Exchange(&m, googleDNSServer)
	if err != nil {
		return fqdns, err
	}
	if len(in.Answer) < 1 {
		return fqdns, errors.New("no CName records found")
	}
	for _, answer := range in.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			fqdns = append(fqdns, cname.Target)
		}
	}
	return fqdns, nil
}

type empty struct{}

func worker(tracker chan empty, fqdns chan string, gather chan []cnameResult, serverAddr string) {
	for fqdn := range fqdns {
		results, err := getDnsARecord(fqdn)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
		if len(results) > 0 {
			gather <- results
		}
	}
}

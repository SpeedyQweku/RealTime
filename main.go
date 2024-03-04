package main

import (
	"bufio"
	"os"
	"strings"
	"time"

	certstream "github.com/CaliDog/certstream-go"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

type Config struct {
	Chatid      int
	Verbose     bool
	Silent      bool
	All_domain  bool
	Btoken      string
	DomainsFile string
	Org         goflags.StringSlice
	Domain      goflags.StringSlice
	DomainList  map[string]struct{}
	OrgList     map[string]struct{}
}

var cfg Config

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("RealTime,locate subdomains and the subdomains of the targeted organization")
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVar(&cfg.Btoken, "t", "", "Bot token"),
		flagSet.IntVar(&cfg.Chatid, "c", 0, "Chat ID"),
	)
	flagSet.CreateGroup("probes", "PROBES",
		flagSet.StringVarP(&cfg.DomainsFile, "list", "l", "", "File containing domains you want to get their subdomains"),
		flagSet.StringSliceVar(&cfg.Domain, "d", nil, "Domains you want to get their subdomains, (e.g., 'example.com,example.org')", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&cfg.Org, "O", "org", nil, "Organization you are targeting for subdomains, (e.g., 'Let's Encrypt,Amazon')", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVarP(&cfg.Verbose, "verbose", "v", false, "verbose mode"),
		flagSet.BoolVar(&cfg.Silent, "silent", true, "silent mode"),
	)
	_ = flagSet.Parse()
}

func readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func sendMessage(btoken string, chatID int64, message string) {
	bot, err := tgbotapi.NewBotAPI(btoken)
	if err != nil {
		gologger.Fatal().Msgf("Error initializing Telegram bot: %v", err)
	}
	msg := tgbotapi.NewMessage(chatID, message)
	_, err = bot.Send(msg)
	if err != nil {
		silentModeEr(cfg.Silent, err)
	}
}

func domainEndsWith(certDomain string, targetDomain string) bool {
	certDomain = strings.ToLower(certDomain)
	targetDomain = strings.ToLower(targetDomain)
	return strings.HasSuffix(certDomain, "."+targetDomain)
}

func certStreamer(domainList map[string]struct{}) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	msg := "[\033[34mINF:websocket\033[0m] " + currentTime + "- Websocket connected\n[\033[34mINF:certstream\033[0m] " + currentTime + " - Connection established to CertStream! Listening for events..."
	if cfg.Verbose {
		gologger.Print().Msg(msg)
	}
	tch := teleCheck(cfg.Btoken, cfg.Chatid)
	if tch {
		sendMessage(cfg.Btoken, int64(cfg.Chatid), msg)
	}

	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:
			messageType, _ := jq.String("message_type")
			if messageType == "certificate_update" {
				data, _ := jq.Object("data")
				leafCert, ok := data["leaf_cert"].(map[string]interface{})
				if ok {
					allDomains, ok := leafCert["all_domains"].([]interface{})
					if ok {
						for _, domains := range allDomains {
							for trg := range domainList {
								if domainEndsWith(domains.(string), trg) {
									if cfg.Verbose {
										gologger.Print().Msg(domains.(string))
									}
									if tch {
										sendMessage(cfg.Btoken, int64(cfg.Chatid), domains.(string))
									}
								}
							}
						}
					}
				}
			}
		case err := <-errStream:
			silentModeEr(cfg.Silent, err)
		}
	}
}

func orgStreamer(orgList map[string]struct{}) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	msg := "[\033[34mINF:websocket\033[0m] " + currentTime + "- Websocket connected\n[\033[34mINF:certstream\033[0m] " + currentTime + " - Connection established to CertStream! Listening for events..."
	if cfg.Verbose {
		gologger.Print().Msg(msg)
	}
	tch := teleCheck(cfg.Btoken, cfg.Chatid)
	if tch {
		sendMessage(cfg.Btoken, int64(cfg.Chatid), msg)
	}
	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:
			messageType, _ := jq.String("message_type")
			if messageType == "certificate_update" {
				data, _ := jq.Object("data")
				leafCert, ok := data["leaf_cert"].(map[string]interface{})
				if ok {
					issuer, ok := leafCert["issuer"].(map[string]interface{})
					if ok {
						for key, value := range issuer {
							if key == "O" {
								for orgTrg := range orgList {
									if value == orgTrg {
										allDomains, ok := leafCert["all_domains"].([]interface{})
										if ok {
											// fmt.Printf("Value: %v\n", value)
											for _, domains := range allDomains {
												if cfg.Verbose {
													gologger.Print().Msg(domains.(string))
												}
												if tch {
													sendMessage(cfg.Btoken, int64(cfg.Chatid), domains.(string))
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		case err := <-errStream:
			silentModeEr(cfg.Silent, err)
		}
	}
}

func teleCheck(btoken string, chatid int) bool {
	if btoken != "" && chatid != 0 {
		return true
	} else {
		return false
	}
}

func silentModeEr(silent bool, message error) {
	if !silent {
		gologger.Error().Msgf("%v", message)
	}
}

func main() {
	tch := teleCheck(cfg.Btoken, cfg.Chatid)
	if tch {
		gologger.Info().Msg("Telegram Bot Enabled")
	} else {
		gologger.Info().Msg("Telegram Bot Disabled")
	}

	if cfg.Verbose {
		gologger.Info().Msg("Verbose Mode Enabled")
	} else {
		gologger.Info().Msg("Verbose Mode Disabled")
	}

	if cfg.DomainsFile == "" && len(cfg.Domain) == 0 && len(cfg.Org) == 0 {
		gologger.Fatal().Msg("Please specify domains/list or org using -l/-list and -d and -org/-O")
	}

	cfg.DomainList = make(map[string]struct{})
	if cfg.DomainsFile != "" {
		lines, err := readLines(cfg.DomainsFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading domains file: %v", err)
		}
		for _, line := range lines {
			cfg.DomainList[line] = struct{}{}
		}
		certStreamer(cfg.DomainList)
	} else if len(cfg.Domain) > 0 {
		for _, domain := range cfg.Domain {
			cfg.DomainList[domain] = struct{}{}
		}
		certStreamer(cfg.DomainList)
	}

	if len(cfg.Org) > 0 {
		cfg.OrgList = make(map[string]struct{})
		for _, org := range cfg.Org {
			cfg.OrgList[org] = struct{}{}
		}
		orgStreamer(cfg.OrgList)
	}
}

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	certstream "github.com/CaliDog/certstream-go"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

type TeleInfo struct {
	ChatidConf string `json:"chatid"`
	TokenConf  string `json:"token"`
}

type Config struct {
	Chatid         int
	Verbose        bool
	Silent         bool
	SendTeleConfig bool
	Btoken         string
	DomainsFile    string
	FilePath       string
	Org            goflags.StringSlice
	Domain         goflags.StringSlice
	DomainList     map[string]struct{}
	OrgList        map[string]struct{}
}

var cfg Config

func init() {
	// Get the user's home directory
	hDir, err := os.UserHomeDir()
	if err != nil {
		gologger.Error().Msgf("Error getting user's home directory: %s", err)
		return
	}
	// Specify the folder path and file name
	folderPath := hDir + "/.config/RealTime"
	fileName := "config.json"
	cfg.FilePath = folderPath + "/" + fileName
	// Check if the folder exists, and create it if not
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		err := os.MkdirAll(folderPath, 0755)
		if err != nil {
			gologger.Error().Msgf("Error creating folder: %s", err)
			return
		}
	}
	// Check if the file exists
	if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
		// File does not exist, create a default config
		teleinfo := TeleInfo{
			ChatidConf: "",
			TokenConf:  "",
		}
		// Marshal the config to JSON
		configJSON, err := json.MarshalIndent(teleinfo, "", "    ")
		if err != nil {
			gologger.Error().Msgf("Error marshaling config: %s", err)
			return
		}
		// Write the config to the file
		err = os.WriteFile(cfg.FilePath, configJSON, 0644)
		if err != nil {
			gologger.Error().Msgf("Error writing config file: %s", err)
			return
		}
	}
}

func readTeleInfo() (token, chatid string) {
	// Read the config file
	configFile, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		gologger.Fatal().Msgf("Error reading config file: %s", err)
		return "", ""
	}

	// Unmarshal the JSON into a Config struct
	var teleinfo TeleInfo
	err = json.Unmarshal(configFile, &teleinfo)
	if err != nil {
		gologger.Fatal().Msgf("Error unmarshaling config: %s", err)
		return "", ""
	}

	return teleinfo.TokenConf, teleinfo.ChatidConf
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
	msg := "[\033[34mINF:websocket\033[0m] " + currentTime + " - Websocket connected\n[\033[34mINF:certstream\033[0m] " + currentTime + " - Connection established to CertStream! Listening for events..."
	msgtg := "[INF:websocket] " + currentTime + " - Websocket connected\n[INF:certstream] " + currentTime + " - Connection established to CertStream! Listening for events..."
	if cfg.Verbose {
		gologger.Print().Msg(msg)
	}
	infToken, infChatid, tfch := teleFileCheck()
	tch := teleCheck(cfg.Btoken, cfg.Chatid)
	if tch {
		sendMessage(cfg.Btoken, int64(cfg.Chatid), msgtg)
	} else {
		if tfch {
			sendMessage(infToken, infChatid, msgtg)
		}
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
									} else {
										if tfch {
											sendMessage(infToken, infChatid, domains.(string))
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

func orgStreamer(orgList map[string]struct{}) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	msg := "[\033[34mINF:websocket\033[0m] " + currentTime + " - Websocket connected\n[\033[34mINF:certstream\033[0m] " + currentTime + " - Connection established to CertStream! Listening for events..."
	msgtg := "[INF:websocket] " + currentTime + " - Websocket connected\n[INF:certstream] " + currentTime + " - Connection established to CertStream! Listening for events..."
	if cfg.Verbose {
		gologger.Print().Msg(msg)
	}
	tch := teleCheck(cfg.Btoken, cfg.Chatid)
	infToken, infChatid, tfch := teleFileCheck()
	if tch {
		sendMessage(cfg.Btoken, int64(cfg.Chatid), msgtg)
	} else {
		if tfch {
			sendMessage(infToken, infChatid, msgtg)
		}
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
					subOrg, ok := leafCert["subject"].(map[string]interface{})
					if ok {
						for key, value := range subOrg {
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
												} else {
													if tfch {
														sendMessage(infToken, infChatid, domains.(string))
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

func teleFileCheck() (string, int64, bool) {
	if cfg.SendTeleConfig {
		infoToken, infoChatidstr := readTeleInfo()
		infoChatid, _ := strconv.ParseInt(infoChatidstr, 10, 64)
		if infoToken != "" && infoChatid != 0 {
			return infoToken, infoChatid, true
		}
	} else {
		return "", 0, false
	}
	return "", 0, false
}

func silentModeEr(silent bool, message error) {
	if !silent {
		gologger.Error().Msgf("%v", message)
	}
}

func main() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("RealTime, locate domains and subdomains of an organization")
	flagSet.CreateGroup("input", "INPUT",
		flagSet.BoolVar(&cfg.SendTeleConfig, "st", false, "Send results to telegram using the config file (default false)"),
		flagSet.StringVar(&cfg.Btoken, "t", "", "Telegram Bot Token"),
		flagSet.IntVar(&cfg.Chatid, "c", 0, "Telegram Chat ID"),
	)
	flagSet.CreateGroup("probes", "PROBES",
		flagSet.StringVarP(&cfg.DomainsFile, "list", "l", "", "File containing domains you want to get their subdomains"),
		flagSet.StringSliceVar(&cfg.Domain, "d", nil, "Domains you want to get their subdomains, (e.g., 'example.com','example.org')", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&cfg.Org, "O", "org", nil, "Organization you are targeting for subdomains, (e.g., 'Microsoft Corporation,Amazon','Cisco Systems Inc.')", goflags.CommaSeparatedStringSliceOptions),
	)
	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVarP(&cfg.Verbose, "verbose", "v", false, "verbose mode (default false)"),
		flagSet.BoolVar(&cfg.Silent, "silent", true, "silent mode"),
	)
	_ = flagSet.Parse()

	if cfg.Verbose {
		_, _, tfch := teleFileCheck()
		tch := teleCheck(cfg.Btoken, cfg.Chatid)
		if tch {
			gologger.Print().Msgf("[\033[33mWRN\033[0m] Kindly Use The Config File [%s]", cfg.FilePath)
			gologger.Info().Msg("Telegram Bot Enabled")
		} else if tfch {
			gologger.Info().Msg("Telegram Bot Enabled")
		} else {
			gologger.Info().Msg("Telegram Bot Disabled")
		}

		if len(cfg.Org) > 0 {
			gologger.Info().Msgf("Organization: %v", cfg.Org)
		}
		if len(cfg.Domain) > 0 {
			gologger.Info().Msgf("Domain: %v", cfg.Domain)
		}

		if cfg.DomainsFile == "" && len(cfg.Domain) == 0 && len(cfg.Org) == 0 {
			gologger.Fatal().Msg("Please specify domains/list or org using -l/-list and -d and -org/-O")
		} else if (cfg.DomainsFile != "" || len(cfg.Domain) > 0) && len(cfg.Org) > 0 {
			gologger.Fatal().Msg("Can't use -l/-list and -d and -org/-O at the same time")
		}
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

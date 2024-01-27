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

var (
	// log         = logging.MustGetLogger("example")
	domainsFile string
	domain      string
	btoken      string
	chatid      int
	verbose     bool
	silent		bool
)

func init() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("RealTime, uses certstrem to find targeted subdomain")
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVarP(&domainsFile, "list", "l", "", "File containing domains"),
		flagSet.StringVar(&domain, "d", "", "String domain"),
		flagSet.StringVar(&btoken, "t", "", "Bot token"),
		flagSet.IntVar(&chatid, "c", 0, "Chat ID"),
	)
	flagSet.CreateGroup("debug", "DEBUG",
		flagSet.BoolVarP(&verbose, "verbose", "v", false, "verbose mode"),
		flagSet.BoolVar(&silent, "silent", true, "silent mode"),
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
		silentModeEr(silent,err)
	}
}

func domainEndsWith(certDomain string, targetDomain string) bool {
	certDomain = strings.ToLower(certDomain)
	targetDomain = strings.ToLower(targetDomain)
	return strings.HasSuffix(certDomain, "."+targetDomain)
}

func certStreamer(domainList map[string]struct{}) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	msg := "[INFO:websocket] " + currentTime + "- Websocket connected\n[INFO:certstream] " + currentTime + " - Connection established to CertStream! Listening for events..."
	if verbose {
		gologger.Print().Msg(msg)
	}
	tch := teleCheck(btoken, chatid)
	if tch {
		sendMessage(btoken, int64(chatid), msg)
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
									if verbose {
										gologger.Print().Msg(domains.(string))
									}
									if tch {
										sendMessage(btoken, int64(chatid), domains.(string))
									}
								}
							}
						}
					}
				}
			}
		case err := <-errStream:
			silentModeEr(silent,err)
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
	if !silent{
		gologger.Error().Msgf("%v", message)
	}
}

func main() {
	var domainList map[string]struct{}

	tch := teleCheck(btoken, chatid)
	if tch {
		gologger.Info().Msg("Telegram Bot Enabled")
	} else {
		gologger.Info().Msg("Telegram Bot Disabled")
	}

	if verbose {
		gologger.Info().Msg("Verbose Mode Enabled")
	} else {
		gologger.Info().Msg("Verbose Mode Disabled")
	}

	if domainsFile == "" && domain == "" {
		gologger.Fatal().Msg("Please specify domain or list using -l/-list and -d")
	}

	if domainsFile != "" {
		lines, err := readLines(domainsFile)
		if err != nil {
			gologger.Fatal().Msgf("Error reading domains file: %v", err)
		}
		domainList = make(map[string]struct{})
		for _, line := range lines {
			domainList[line] = struct{}{}
		}
		certStreamer(domainList)
	} else if domain != "" {
		domainList = map[string]struct{}{domain: {}}
		certStreamer(domainList)
	}
}

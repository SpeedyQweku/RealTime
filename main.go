package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	certstream "github.com/CaliDog/certstream-go"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	logging "github.com/op/go-logging"
)

var (
	log         = logging.MustGetLogger("example")
	domainsFile string
	domain      string
	btoken      string
	chatid      int64
)

func init() {
	flag.StringVar(&domainsFile, "l", "", "File containing domains")
	flag.StringVar(&domain, "d", "", "String domain")
	flag.StringVar(&btoken, "t", "", "Bot token")
	flag.Int64Var(&chatid, "c", 0, "Chat ID")
	flag.Parse()

	currentTime := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf("[INFO:websocket] %s - Websocket connected\n[INFO:certstream] %s - Connection established to CertStream! Listening for events...", currentTime, currentTime)

	if btoken != "" && chatid != 0 {
		bot, err := tgbotapi.NewBotAPI(btoken)
		if err != nil {
			log.Fatal(err)
		}
		sendMessage(bot, chatid, msg)
	}
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

func sendMessage(bot *tgbotapi.BotAPI, chatID int64, message string) {
	msg := tgbotapi.NewMessage(chatID, message)
	_, err := bot.Send(msg)
	if err != nil {
		log.Info("Error sending message: %v\n", err)
	}
}

func domainEndsWith(certDomain, targetDomain string) bool {
	certDomain = strings.ToLower(certDomain)
	targetDomain = strings.ToLower(targetDomain)
	return strings.HasSuffix(certDomain, "."+targetDomain)
}

func main() {
	var (
		domainList map[string]struct{}
	)

	if domainsFile != "" {
		lines, err := readLines(domainsFile)
		if err != nil {
			log.Fatalf("Error reading domains file: %v", err)
		}
		domainList = make(map[string]struct{})
		for _, line := range lines {
			domainList[line] = struct{}{}
		}
	} else if domain != "" {
		domainList = map[string]struct{}{domain: {}}
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
									if btoken != "" && chatid != 0 {
										bot, err := tgbotapi.NewBotAPI(btoken)
										if err != nil {
											log.Fatal(err)
										}
										sendMessage(bot, chatid, domains.(string))
									}
								}
							}
						}
					}
				}
			}
		case err := <-errStream:
			log.Error(err)
		}
	}
}

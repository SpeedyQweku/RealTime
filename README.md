# RealTime

Uses certstream-go to obtain an updated certificate for a domain, verify if it is included in the target domains, and then send it to Telegram.

## Installation

```bash
go install github.com/SpeedyQweku/RealTime@v0.0.2
```

## Config

- added a json config at ~/.config/RealTime/config.json

It contains chatID and token for telegram to be used with the binary, a default json config file is generated if one doesn't exist.

```bash
{
    "chatid": "",
    "token": ""
}
```

## Usage

```bash
RealTime,locate subdomains and the subdomains of the targeted organization

INPUT:
   -st        Send results to telegram using the config file (default false)
   -t string  Telegram Bot Token
   -c int     Telegram Chat ID

PROBES:
   -l, -list string   File containing domains you want to get their subdomains
   -d string[]        Domains you want to get their subdomains, (e.g., 'example.com','example.org')
   -org, -O string[]  Organization you are targeting for subdomains, (e.g., 'Microsoft Corporation,Amazon','Cisco Systems Inc.')

DEBUG:
   -v, -verbose  verbose mode (default false)
   -silent       silent mode (default true)
```

# RealTime

Uses certstream-go to obtain an updated certificate for a domain, verify if it is included in the target domains, and then send it to Telegram.

## Installation

```bash
    go install github.com/SpeedyQweku/RealTime@latest
```

## Usage

```bash
    ./RealTime -l host.txt -c CHAT_ID -t BOT_TOKEN & disown
```

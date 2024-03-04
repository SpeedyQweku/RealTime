# RealTime

Uses certstream-go to obtain an updated certificate for a domain, verify if it is included in the target domains, and then send it to Telegram.

## Installation

```bash
    go install github.com/SpeedyQweku/RealTime@latest
```

## Usage

```bash
RealTime,locate subdomains and the subdomains of the targeted organization

INPUT:
   -t string  Bot token
   -c int     Chat ID

PROBES:
   -l, -list string   File containing domains you want to get their subdomains
   -d string[]        Domains you want to get their subdomains, (e.g., 'example.com,example.org')
<<<<<<< HEAD
   -org, -O string[]  Organization you are targeting for subdomains, (e.g., "Let's Encrypt","Amazon")
=======
   -org, -O string[]  Organization you are targeting for subdomains, (e.g., 'Let's Encrypt,Amazon')
>>>>>>> ca84f2f379921ee570078fb307d4c68bd7665f58

DEBUG:
   -v, -verbose  verbose mode
   -silent       silent mode (default true)

```

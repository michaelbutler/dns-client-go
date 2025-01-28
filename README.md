# dns-client-go

Command-line DNS querying utility written in Go.

# Usage

```sh
NAME:
   dnsclient - Query DNS records

USAGE:
   dnsclient [global options]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug             Enable debug mode, prints raw bytes (default: false)
   --dns-server value  DNS server to query
   --domain value      Domain name to query
   --port value        Port to use for DNS query (default: "53")
   --type value        Type of DNS record to query (default: "A")
   --help, -h          show help
```
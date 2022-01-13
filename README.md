# authlog-xlsx
Parse auth.log files into an Excel .xlsx file for forensics analysis. Parses authentication events into an Excel sheet by default but can be set to parse all SSH sessions and perform lookups on connected IP addresses.

## Usage

```
usage: main.py [-h] [-s] [-i] logFile sheet

positional arguments:
  logFile     path to the auth.log file
  sheet       path to xlsx file output

options:
  -h, --help  show this help message and exit

  -s, --ssh   parse sshd events to create ssh worksheet (default: False)
  -i, --ip    perform whois lookup on all IPs that connected to ssh (default: False)
```

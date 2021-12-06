#!/usr/bin/python3

import argparse
import os
import sys
import re
import xlsxwriter
import ipwhois
from rich.progress import track

args = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
args.add_argument(
        'logFile', type=argparse.FileType('r'),
        help='path to the auth.log file')
args.add_argument('sheet', type=str, help='path to xlsx file output')
optional_args = args.add_argument_group()
opt_ssh = optional_args.add_argument(
        '-s', '--ssh', dest='ssh',
        action='store_true', help='parse sshd events to create ssh worksheet')
options = args.parse_args()

workbook = xlsxwriter.Workbook(os.path.expanduser(options.sheet))
eventsSheet = workbook.add_worksheet("Events")
eventsSheet.freeze_panes(1, 0)

dateFormat = workbook.add_format({'num_format': 'MMM DD HH:MM:SS'})
bold = workbook.add_format({'bold': True})

eventsSheet.write(0, 0, 'Time', bold)
eventsSheet.set_column(0, 0, 15)
eventsSheet.write(0, 1, 'Hostname', bold)
eventsSheet.set_column(1, 1, 20)
eventsSheet.write(0, 2, 'Process', bold)
eventsSheet.set_column(2, 2, 20)
eventsSheet.write(0, 3, 'Event', bold)
eventsSheet.set_column(3, 3, 100)


if options.ssh:
    sshEventsSheet = workbook.add_worksheet("SSH Connections")
    sshEventsSheet.freeze_panes(1, 0)

    sshEventsSheet.write(0, 0, 'Connect Time', bold)
    sshEventsSheet.set_column(0, 0, 15)
    sshEventsSheet.write(0, 1, 'Disconnect Time', bold)
    sshEventsSheet.set_column(1, 1, 15)
    sshEventsSheet.write(0, 2, 'Process', bold)
    sshEventsSheet.set_column(2, 2, 20)
    sshEventsSheet.write(0, 3, 'User', bold)
    sshEventsSheet.set_column(3, 3, 15)
    sshEventsSheet.write(0, 4, 'Source IP', bold)
    sshEventsSheet.set_column(4, 4, 20)
    sshEventsSheet.write(0, 5, 'Source Port', bold)
    sshEventsSheet.set_column(5, 5, 15)
    sshEventsSheet.write(0, 6, 'State', bold)
    sshEventsSheet.set_column(6, 6, 20)
    sshEventsSheet.write(0, 7, 'Auth Method', bold)
    sshEventsSheet.set_column(7, 7, 15)
    sshEventsSheet.write(0, 8, 'Authentication Key', bold)
    sshEventsSheet.set_column(8, 8, 100)

    sshIPsSheet = workbook.add_worksheet("SSH IPs")
    sshIPsSheet.freeze_panes(1, 0)

    sshIPsSheet.write(0, 0, 'IP Address', bold)
    sshIPsSheet.set_column(0, 0, 20)
    sshIPsSheet.write(0, 1, 'IP Country', bold)
    sshIPsSheet.set_column(1, 1, 10)
    sshIPsSheet.write(0, 2, 'IP ASN', bold)
    sshIPsSheet.set_column(2, 2, 20)
    sshIPsSheet.write(0, 3, 'IP Provider', bold)
    sshIPsSheet.set_column(3, 3, 20)
    sshIPsSheet.write(0, 4, 'Total', bold)
    sshIPsSheet.set_column(4, 4, 7)
    sshIPsSheet.write(0, 5, 'Accepted', bold)
    sshIPsSheet.set_column(5, 5, 7)
    sshIPsSheet.write(0, 6, 'Refused', bold)
    sshIPsSheet.set_column(6, 6, 7)
    sshIPsSheet.write(0, 7, "Invalid User", bold)
    sshIPsSheet.set_column(7, 7, 10)
    sshIPsSheet.write(0, 8, 'Failed Auth', bold)
    sshIPsSheet.set_column(8, 8, 10)


logFile = options.logFile
lineNum = 1
sshLineNum = 1
sshd_processes = {}
sshd_ips = {}

def ipData(ip: str) -> dict:
    return {
            "ip": ip,
            "country": None,
            "asn": None,
            'provider': None,
            'total': 0,
            'accepted': 0,
            'refused': 0,
            'invalid': 0,
            'failed': 0
            }


lineCount = 0
for _ in logFile:
    lineCount += 1
logFile.seek(0)

for line in track(logFile, description="Processing Events", total=lineCount):
    match = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (\S*\S) (\S*\[[0-9]*\]): (.*)", line)
    if match is None:
        continue

    date = match.group(1)
    eventsSheet.write(lineNum, 0, date, dateFormat)
    hostname = match.group(2)
    eventsSheet.write(lineNum, 1, hostname)
    process = match.group(3)
    eventsSheet.write(lineNum, 2, process)
    event = match.group(4)
    eventsSheet.write(lineNum, 3, event)

    if options.ssh and process.startswith('sshd') and any(map(event.startswith, ("Connection", "Accepted", "Disconnected", "refused connect", "pam_unix(sshd:session): session closed", "Invalid user", "Failed "))):
        if process not in sshd_processes:
            sshd_processes[process] = {
                    'connect': None,
                    'disconnect': None,
                    'ip': None,
                    'port': None,
                    'user': None,
                    'state': None,
                    'auth': None,
                    'key': None,
                    'row': sshLineNum
                    }
            sshLineNum += 1

        if event.startswith("Connection from"):
            connectionEvent = re.search(
                    r"Connection from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5}) on ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5})",
                    event
                    )
            if connectionEvent is not None:
                sshd_processes[process]['connect'] = date
                sshd_processes[process]['ip'] = connectionEvent.group(1)
                sshd_processes[process]['port'] = connectionEvent.group(2)
        elif event.startswith("Accepted") or event.startswith("Failed"):
            authEvent = re.search(
                    r"(Accepted|Failed) (password|publickey|none) for (\S*) from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5}) (ssh[0-9]):{0,1}\s{0,1}(.*)",
                    event
                    )
            if authEvent is None:
                authEvent = re.search(
                        r"(Accepted|Failed) (password|publickey|none) for invalid user (\S*) from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5}) (ssh[0-9]):{0,1}\s{0,1}(.*)",
                        event
                        )
            if authEvent is not None:
                if authEvent.group(4) not in sshd_ips:
                    sshd_ips[authEvent.group(4)] = ipData(authEvent.group(4))
                if authEvent.group(1) == "Accepted":
                    sshd_ips[authEvent.group(4)]["accepted"] += 1
                    sshd_ips[authEvent.group(4)]["total"] += 1
                else:
                    sshd_ips[authEvent.group(4)]["failed"] += 1
                    sshd_ips[authEvent.group(4)]["total"] += 1

                if sshd_processes[process]['connect'] is None:
                    sshd_processes[process]['connect'] = date
                sshd_processes[process]['ip'] = authEvent.group(4)
                sshd_processes[process]['port'] = authEvent.group(5)
                if sshd_processes[process]['state'] is None:
                    sshd_processes[process]['state'] = authEvent.group(1)
                sshd_processes[process]['auth'] = authEvent.group(2)
                sshd_processes[process]['user'] = authEvent.group(3)
                if authEvent.group(2) == 'publickey':
                    sshd_processes[process]['key'] = authEvent.group(7)
        elif event.startswith("Disconnected"):
            disconnectEvent = re.search(
                    r"Disconnected from (invalid ){0,1}user (\S*) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5})",
                    event
                    )
            sshd_processes[process]['disconnect'] = date
            if disconnectEvent is not None:
                sshd_processes[process]['user'] = disconnectEvent.group(2)
                sshd_processes[process]['ip'] = disconnectEvent.group(3)
                sshd_processes[process]['port'] = disconnectEvent.group(4)
        elif event.startswith("pam_unix(sshd:session): session closed"):
            sshd_processes[process]['disconnect'] = date
        elif event.startswith("Invalid user"):
            invalidEvent = re.search(
                    r"Invalid user (\S*) from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5})",
                    event
                    )
            if invalidEvent:
                if invalidEvent.group(2) not in sshd_ips:
                    sshd_ips[invalidEvent.group(2)] = ipData(invalidEvent.group(2))
                sshd_ips[invalidEvent.group(2)]['total'] += 1
                sshd_ips[invalidEvent.group(2)]['invalid'] += 1

                if sshd_processes[process]['connect'] is None:
                    sshd_processes[process]['connect'] = date
                sshd_processes[process]['ip'] = invalidEvent.group(2)
                sshd_processes[process]['port'] = invalidEvent.group(3)
                sshd_processes[process]['user'] = invalidEvent.group(1)
                sshd_processes[process]['state'] = "Invalid user"
        elif event.startswith("Connection closed"):
            closeEvent = re.search(
                    r"Connection closed by (invalid ){0,1}user (\S*) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*) port ([0-9]{1,5})",
                    event
                    )
            if closeEvent:
                sshd_processes[process]['disconnect'] = date
                sshd_processes[process]['user'] = closeEvent.group(2)
                sshd_processes[process]['ip'] = closeEvent.group(3)
                sshd_processes[process]['port'] = closeEvent.group(4)
        elif event.startswith("refused connect"):
            refuseEvent = re.search(r"refused connect from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*:*[0-9a-f]*%{0,1}\S*)", event)
            if refuseEvent:
                if refuseEvent.group(1) not in sshd_ips:
                    sshd_ips[refuseEvent.group(1)] = ipData(refuseEvent.group(1))
                sshd_ips[refuseEvent.group(1)]['refused'] += 1
                sshd_ips[refuseEvent.group(1)]['total'] += 1

                sshd_processes[process]['connect'] = date
                sshd_processes[process]['disconnect'] = date
                sshd_processes[process]['state'] = 'refused connect'
                sshd_processes[process]['ip'] = refuseEvent.group(1)

        if sshd_processes[process]['connect']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 0,
                    sshd_processes[process]['connect'], dateFormat
                    )
        if sshd_processes[process]['disconnect']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 1,
                    sshd_processes[process]['disconnect'], dateFormat
                    )
        if sshd_processes[process]['user']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 3,
                    sshd_processes[process]['user']
                    )
        if sshd_processes[process]['ip']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 4,
                    sshd_processes[process]['ip']
                    )
        if sshd_processes[process]['port']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 5,
                    sshd_processes[process]['port']
                    )
        if sshd_processes[process]['state']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 6,
                    sshd_processes[process]['state']
                    )
        if sshd_processes[process]['auth']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 7,
                    sshd_processes[process]['auth']
                    )
        if sshd_processes[process]['key']:
            sshEventsSheet.write(
                    sshd_processes[process]['row'], 8,
                    sshd_processes[process]['key']
                    )
        sshEventsSheet.write(sshd_processes[process]['row'], 2, process)

        if event.startswith("pam_unix(sshd:session): session closed") or event.startswith("refused connect") or event.startswith("Connection closed") or event.startswith("Disconnect"):
            del sshd_processes[process]

    lineNum += 1

ipRow = 1
for ip in track(sshd_ips.keys(), description="Looking Up IPs", total=len(sshd_ips)):
    try:
        lookup = ipwhois.IPWhois(ip)
        data = lookup.lookup_rdap()
        sshd_ips[ip]['country'] = data['asn_country_code']
        if data['asn'] is not None and data['asn_description'] is not None:
            sshd_ips[ip]['asn'] = data['asn'] + ': ' + data['asn_description']
        sshd_ips[ip]['provider'] = data['network']['name']
    except ipwhois.IPDefinedError:
        pass
    except ipwhois.HTTPLookupError:
        pass
    except KeyboardInterrupt:
        sys.exit(130)

    sshIPsSheet.write(ipRow, 0, ip)
    sshIPsSheet.write(ipRow, 1, sshd_ips[ip]['country'])
    sshIPsSheet.write(ipRow, 2, sshd_ips[ip]['asn'])
    sshIPsSheet.write(ipRow, 3, sshd_ips[ip]['provider'])
    sshIPsSheet.write(ipRow, 4, sshd_ips[ip]['total'])
    sshIPsSheet.write(ipRow, 5, sshd_ips[ip]['accepted'])
    sshIPsSheet.write(ipRow, 6, sshd_ips[ip]['refused'])
    sshIPsSheet.write(ipRow, 7, sshd_ips[ip]['invalid'])
    sshIPsSheet.write(ipRow, 8, sshd_ips[ip]['failed'])

    ipRow += 1

workbook.close()

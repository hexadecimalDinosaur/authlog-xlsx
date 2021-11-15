#!/usr/bin/python3

import argparse
import os
import re
import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell

args = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
args.add_argument('logFile', type=argparse.FileType('r'), help='path to the auth.log file')
args.add_argument('sheet', type=str, help='path to xlsx file output')
options = args.parse_args()

workbook = xlsxwriter.Workbook(os.path.expanduser(options.sheet))
eventsSheet = workbook.add_worksheet("Events")

dateFormat = workbook.add_format({'num_format': 'MMM DD HH:MM:SS'})
bold = workbook.add_format({'bold': True})

eventsSheet.write(0, 0, 'Time', bold)
eventsSheet.set_column(0, 0, 15)
eventsSheet.write(0, 1, 'Hostname', bold)
eventsSheet.set_column(1, 1, 20)
eventsSheet.write(0, 2, 'Application', bold)
eventsSheet.set_column(2, 2, 20)
eventsSheet.write(0, 3, 'Event', bold)
eventsSheet.set_column(3, 3, 100)

logFile = options.logFile
lineNum = 1

for line in logFile.readlines():
    match = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (\S*\S) (\S*\S): (.*)", line)
    if match == None:
        continue

    date = match.group(1)
    eventsSheet.write(lineNum, 0, date, dateFormat)
    hostname = match.group(2)
    eventsSheet.write(lineNum, 1, hostname)
    app = match.group(3)
    eventsSheet.write(lineNum, 2, app)
    event = match.group(4)
    eventsSheet.write(lineNum, 3, event)

    lineNum += 1

workbook.close()

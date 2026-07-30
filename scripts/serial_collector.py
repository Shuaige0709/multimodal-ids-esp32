#!/usr/bin/env python3
"""
Simple serial collector that reads RFC5424 syslog lines from a serial port
and writes CSV rows similar to nids_collector.py.

Usage:
  pip install pyserial
  python scripts/serial_collector.py --port COM3 --baud 115200 --out data.csv
"""
import argparse
import re
import csv
import time
import serial

SD_RE = re.compile(
    r"\[meta@(?P<pen>[^ ]+) subtype=\"(?P<subtype>[^\"]*)\" rssi=\"(?P<rssi>[^\"]+)\" "
    r"snr=\"(?P<snr>[^\"]+)\" ipat=\"(?P<ipat>[^\"]+)\" seq=\"(?P<seq>[^\"]+)\" "
    r"heap=\"(?P<heap>[^\"]+)\" minheap=\"(?P<minheap>[^\"]+)\" uptime=\"(?P<uptime>[^\"]+)\" "
    r"reconn=\"(?P<reconn>[^\"]+)\" qpeak=\"(?P<qpeak>[^\"]+)\" udpfail=\"(?P<udpfail>[^\"]+)\" "
    r"backlog=\"(?P<backlog>[^\"]+)\" dropped=\"(?P<dropped>[^\"]+)\""
    r"(?: host_mac=\"(?P<host_mac>[^\"]+)\")?"
    r"(?: attack=\"(?P<attack>[^\"]+)\")?\]"
)

def parse_sd(line):
    m = SD_RE.search(line)
    if not m:
        return None
    return m.groupdict()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--port', required=True, help='Serial port, e.g. COM3 or /dev/ttyUSB0')
    p.add_argument('--baud', type=int, default=115200)
    p.add_argument('--out', default='serial_capture.csv')
    args = p.parse_args()

    ser = serial.Serial(args.port, args.baud, timeout=1)
    print('Opened', ser.portstr)

    with open(args.out, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        header = ['timestamp','pen','subtype','rssi','snr','ipat','seq','heap','minheap','uptime','reconn','qpeak','udpfail','backlog','dropped','host_mac','pred_attack','raw']
        writer.writerow(header)

        try:
            while True:
                line = ser.readline().decode('utf-8', errors='replace').strip()
                if not line:
                    continue
                sd = parse_sd(line)
                if sd:
                    row = [time.time(), sd.get('pen'), sd.get('subtype'), sd.get('rssi'), sd.get('snr'), sd.get('ipat'), sd.get('seq'), sd.get('heap'), sd.get('minheap'), sd.get('uptime'), sd.get('reconn'), sd.get('qpeak'), sd.get('udpfail'), sd.get('backlog'), sd.get('dropped'), sd.get('host_mac'), sd.get('attack'), line]
                    writer.writerow(row)
                    csvfile.flush()
                else:
                    # still write raw for debugging
                    writer.writerow([time.time(), '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', line])
                    csvfile.flush()
        except KeyboardInterrupt:
            print('Stopped')

if __name__ == '__main__':
    main()

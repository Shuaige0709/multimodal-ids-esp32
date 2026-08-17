#!/usr/bin/env python3
"""
Serial collector (Mode S) — RFC5424 syslog over USB-UART.

Standby mode: open the COM port *before* the deauth campaign so the OS does
not re-enumerate / reset the ESP32 when Wi-Fi drops. Keep the port open for
the whole session.

Usage:
  pip install pyserial
  python scripts/serial_collector.py --port COM3 --baud 115200 --out data/raw/serial.csv
  python scripts/serial_collector.py --port COM3 --standby --out data/raw/serial.csv
"""
import argparse
import csv
import os
import re
import sys
import time

try:
    import serial
    from serial import SerialException
except ImportError:
    print("pyserial required: pip install pyserial", file=sys.stderr)
    raise SystemExit(1)

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

SD_RE = re.compile(
    r"\[meta@(?P<pen>[^ ]+) subtype=\"(?P<subtype>[^\"]*)\" rssi=\"(?P<rssi>[^\"]+)\" "
    r"snr=\"(?P<snr>[^\"]+)\" ipat=\"(?P<ipat>[^\"]+)\" seq=\"(?P<seq>[^\"]+)\" "
    r"heap=\"(?P<heap>[^\"]+)\" minheap=\"(?P<minheap>[^\"]+)\" uptime=\"(?P<uptime>[^\"]+)\" "
    r"reconn=\"(?P<reconn>[^\"]+)\" qpeak=\"(?P<qpeak>[^\"]+)\" udpfail=\"(?P<udpfail>[^\"]+)\" "
    r"backlog=\"(?P<backlog>[^\"]+)\" dropped=\"(?P<dropped>[^\"]+)\""
    r"(?: host_mac=\"(?P<host_mac>[^\"]+)\")?"
    r"(?: attack=\"(?P<attack>[^\"]+)\")?"
    r"(?: deauth_tgt=\"(?P<deauth_tgt>[^\"]+)\")?"
    r"(?: seq_jump=\"(?P<seq_jump>[^\"]+)\")?"
    r"(?: ap_bssid=\"(?P<ap_bssid>[^\"]+)\")?"
    r"(?: channel=\"(?P<channel>[^\"]+)\")?"
    r"(?: win_pkts=\"(?P<win_pkts>[^\"]+)\")?"
    r"(?: win_dens=\"(?P<win_dens>[^\"]+)\")?"
    r"(?: pred=\"(?P<pred>[^\"]+)\")?"
    r"(?: calib=\"(?P<calib>[^\"]+)\")?"
    r"(?: thr=\"(?P<thr>[^\"]+)\")?"
    r"(?: gw_mac=\"(?P<gw_mac>[^\"]+)\")?"
    r"(?: gw_flip=\"(?P<gw_flip>[^\"]+)\")?"
    r"\]"
)

HEADER = [
    "timestamp", "pen", "subtype", "rssi", "snr", "ipat", "seq", "heap", "minheap",
    "uptime", "reconn", "qpeak", "udpfail", "backlog", "dropped", "host_mac",
    "pred_attack", "pred_raw", "calib", "calib_thr", "deauth_tgt", "seq_jump",
    "ap_bssid", "channel", "win_pkts", "win_dens", "gw_mac", "gw_flip", "raw",
]


def parse_sd(line):
    m = SD_RE.search(line)
    return m.groupdict() if m else None


def open_serial(port, baud, standby):
    """Open serial; in standby, retry until the port appears (no ESP32 reset dance)."""
    deadline = time.time() + (300 if standby else 15)
    last_err = None
    while time.time() < deadline:
        try:
            ser = serial.Serial(port, baud, timeout=1)
            # Avoid DTR toggle reset on many ESP32 USB-UART bridges when possible
            try:
                ser.dtr = False
                ser.rts = False
            except Exception:
                pass
            print(f"Opened {ser.portstr} (standby={standby})")
            return ser
        except SerialException as e:
            last_err = e
            if not standby:
                break
            print(f"  waiting for {port}: {e}")
            time.sleep(1.0)
    raise SystemExit(f"Could not open {port}: {last_err}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", required=True, help="Serial port, e.g. COM3 or /dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--out", default="serial_capture.csv")
    p.add_argument(
        "--standby",
        action="store_true",
        help="Open early and keep the port open across Wi-Fi disconnects (Mode S)",
    )
    args = p.parse_args()

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    ser = open_serial(args.port, args.baud, args.standby)
    if args.standby:
        print("Standby: leave this running; start deauth when ready. Ctrl+C to stop.")

    with open(args.out, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(HEADER)
        try:
            while True:
                try:
                    line = ser.readline().decode("utf-8", errors="replace").strip()
                except SerialException as e:
                    print(f"Serial error: {e}; reconnecting..." if args.standby else e)
                    if not args.standby:
                        break
                    try:
                        ser.close()
                    except Exception:
                        pass
                    time.sleep(1.0)
                    ser = open_serial(args.port, args.baud, True)
                    continue
                if not line:
                    continue
                sd = parse_sd(line)
                if sd:
                    writer.writerow([
                        time.time(), sd.get("pen"), sd.get("subtype"), sd.get("rssi"),
                        sd.get("snr"), sd.get("ipat"), sd.get("seq"), sd.get("heap"),
                        sd.get("minheap"), sd.get("uptime"), sd.get("reconn"),
                        sd.get("qpeak"), sd.get("udpfail"), sd.get("backlog"),
                        sd.get("dropped"), sd.get("host_mac"), sd.get("attack"),
                        sd.get("pred"), sd.get("calib"), sd.get("thr"),
                        sd.get("deauth_tgt"), sd.get("seq_jump"), sd.get("ap_bssid"),
                        sd.get("channel"), sd.get("win_pkts"), sd.get("win_dens"),
                        sd.get("gw_mac"), sd.get("gw_flip"), line,
                    ])
                else:
                    writer.writerow([time.time()] + [""] * (len(HEADER) - 2) + [line])
                csvfile.flush()
        except KeyboardInterrupt:
            print("Stopped")
        finally:
            try:
                ser.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()

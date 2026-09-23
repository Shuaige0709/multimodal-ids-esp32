#!/usr/bin/env python3
"""
Serial ground-truth collector — one RFC5424 row per inference window.

Standby mode: open the COM port *before* the deauth campaign so the OS does
not re-enumerate / reset the ESP32 when Wi-Fi drops. Keep the port open for
the whole session.

The default label port is 10000 so this can run beside the UDP collector on
9999. On Kali export NIDS_SERIAL_LABEL_PORT=10000 before the attack.

Usage:
  pip install pyserial
  python scripts/serial_collector.py --port COM3 --standby --out data/raw/serial.csv

The ESP-IDF Python environment already includes pyserial on the development PC.
"""
import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta

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
    r"(?: win_deauth=\"(?P<win_deauth>[^\"]+)\")?"
    r"(?: win_probe=\"(?P<win_probe>[^\"]+)\")?"
    r"(?: win_beacon=\"(?P<win_beacon>[^\"]+)\")?"
    r"(?: win_auth=\"(?P<win_auth>[^\"]+)\")?"
    r"(?: win_bssid=\"(?P<win_bssid>[^\"]+)\")?"
    r"(?: win_twin=\"(?P<win_twin>[^\"]+)\")?"
    r"(?: win_rogue=\"(?P<win_rogue>[^\"]+)\")?"
    r"(?: win_mgmt=\"(?P<win_mgmt>[^\"]+)\")?"
    r"(?: win_data=\"(?P<win_data>[^\"]+)\")?"
    r"(?: win_ctrl=\"(?P<win_ctrl>[^\"]+)\")?"
    r"(?: win_bytes=\"(?P<win_bytes>[^\"]+)\")?"
    r"(?: win_len_mean=\"(?P<win_len_mean>[^\"]+)\")?"
    r"(?: win_len_max=\"(?P<win_len_max>[^\"]+)\")?"
    r"(?: win_mgmt_bytes=\"(?P<win_mgmt_bytes>[^\"]+)\")?"
    r"(?: win_data_bytes=\"(?P<win_data_bytes>[^\"]+)\")?"
    r"\]"
)

HEADER = [
    "pen", "subtype", "rssi", "snr", "ipat", "seq", "heap", "minheap",
    "uptime", "reconn", "qpeak", "udpfail", "backlog", "dropped", "host_mac",
    "pred_attack", "pred_raw", "calib", "calib_thr", "deauth_tgt", "seq_jump",
    "ap_bssid", "channel", "win_pkts", "win_dens",
    "win_deauth", "win_probe", "win_beacon", "win_auth", "win_bssid",
    "win_twin", "win_rogue",
    "win_mgmt", "win_data", "win_ctrl", "win_bytes",
    "win_len_mean", "win_len_max", "win_mgmt_bytes", "win_data_bytes",
    "gw_mac", "gw_flip", "label", "attack_type", "timestamp", "raw",
]


def parse_sd(line):
    m = SD_RE.search(line)
    return m.groupdict() if m else None


def _windows_python_processes():
    script = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -match 'python' -and $_.CommandLine } | "
        "Select-Object ProcessId,ParentProcessId,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = (out.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return list(data) if isinstance(data, list) else []


def release_idf_monitor(port):
    """Close an ESP-IDF monitor that is holding this COM port.

    A flash still in progress (esptool) is left alone. Returns 'flashing',
    'closed', or 'idle'.
    """
    if os.name != "nt":
        return "idle"
    port_re = re.compile(re.escape(port), re.I)
    procs = _windows_python_processes()
    if any(
        port_re.search(p.get("CommandLine") or "")
        and re.search(r"esptool|write_flash", p.get("CommandLine") or "", re.I)
        for p in procs
    ):
        return "flashing"

    pids = []
    for proc in procs:
        cmd = proc.get("CommandLine") or ""
        if not port_re.search(cmd):
            continue
        if not re.search(r"idf_monitor|esp_idf_monitor|idf\.py", cmd, re.I):
            continue
        if re.search(r"idf\.py", cmd, re.I) and not re.search(r"\bmonitor\b", cmd, re.I):
            continue
        pid = int(proc.get("ProcessId") or 0)
        if pid and pid != os.getpid():
            pids.append(pid)
    if not pids:
        return "idle"

    for pid in sorted(set(pids), reverse=True):
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        )
    print(f"Closed ESP-IDF monitor on {port}")
    time.sleep(0.5)
    return "closed"


def open_serial(port, baud, standby):
    """Open serial; in standby, retry until the port appears (no ESP32 reset dance)."""
    deadline = time.time() + (300 if standby else 15)
    last_err = None
    told_flashing = False
    while time.time() < deadline:
        state = release_idf_monitor(port)
        if state == "flashing" and not told_flashing:
            print(f"Flash still using {port}; waiting until it finishes")
            told_flashing = True
        try:
            # Set control lines before opening where pyserial permits it. This
            # reduces accidental ESP32 reset through DTR/RTS on UART0 bridges.
            ser = serial.Serial()
            ser.port = port
            ser.baudrate = baud
            ser.timeout = 0.1
            ser.dtr = False
            ser.rts = False
            ser.open()
            print(f"Opened {ser.portstr} (standby={standby})")
            return ser
        except SerialException as e:
            last_err = e
            if not standby:
                break
            print(f"  waiting for {port}: {e}")
            time.sleep(1.0)
    raise SystemExit(f"Could not open {port}: {last_err}")


def open_label_socket(bind_host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    sock.bind((bind_host, port))
    sock.setblocking(False)
    return sock


def drain_labels(sock, state):
    """Apply repeated UDP labels idempotently and keep finished intervals."""
    while True:
        try:
            payload, _ = sock.recvfrom(1024)
        except BlockingIOError:
            return
        raw = payload.decode(errors="ignore").strip()
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            print(f"Ignoring malformed label: {raw!r}")
            continue

        status = event.get("status")
        attack_type = event.get("attack_type", "UNKNOWN")
        now = datetime.now()
        current = state["current"]
        if status == "START":
            if current is not None:
                if current["type"] == attack_type:
                    continue
                print(f"Ignoring START {attack_type}; {current['type']} is active")
                continue
            state["current"] = {"start": now, "type": attack_type}
            print(f"ATTACK START {attack_type}")
        elif status == "STOP":
            if current is None:
                continue
            if current["type"] != attack_type:
                print(f"Ignoring STOP {attack_type}; {current['type']} is active")
                continue
            current["end"] = now
            state["intervals"].append(current)
            state["current"] = None
            print(f"ATTACK STOP {attack_type}")


def label_for_time(generated_at, state):
    for interval in state["intervals"]:
        if interval["start"] <= generated_at <= interval["end"]:
            return 1, interval["type"]
    current = state["current"]
    if current is not None and generated_at >= current["start"]:
        return 1, current["type"]
    return 0, "NONE"


def canonical_row(sd, label, attack_type, timestamp, raw):
    return [
        sd.get("pen"), sd.get("subtype"), sd.get("rssi"), sd.get("snr"),
        sd.get("ipat"), sd.get("seq"), sd.get("heap"), sd.get("minheap"),
        sd.get("uptime"), sd.get("reconn"), sd.get("qpeak"),
        sd.get("udpfail"), sd.get("backlog"), sd.get("dropped"),
        sd.get("host_mac"), sd.get("attack"), sd.get("pred"),
        sd.get("calib"), sd.get("thr"), sd.get("deauth_tgt"),
        sd.get("seq_jump"), sd.get("ap_bssid"), sd.get("channel"),
        sd.get("win_pkts"), sd.get("win_dens"), sd.get("win_deauth"),
        sd.get("win_probe"), sd.get("win_beacon"), sd.get("win_auth"),
        sd.get("win_bssid"), sd.get("win_twin"), sd.get("win_rogue"),
        sd.get("win_mgmt"), sd.get("win_data"), sd.get("win_ctrl"),
        sd.get("win_bytes"), sd.get("win_len_mean"), sd.get("win_len_max"),
        sd.get("win_mgmt_bytes"), sd.get("win_data_bytes"),
        sd.get("gw_mac"), sd.get("gw_flip"), label, attack_type,
        timestamp.isoformat(), raw,
    ]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", required=True, help="Serial port, e.g. COM3 or /dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--out", default="data/raw/serial_capture.csv")
    p.add_argument(
        "--raw-log",
        default=None,
        help="All console lines; defaults to <out>.log for reset/debug evidence",
    )
    p.add_argument("--label-bind", default="0.0.0.0")
    p.add_argument(
        "--label-port", type=int, default=10000,
        help="UDP START/STOP port; use 10000 beside the UDP collector on 9999",
    )
    p.add_argument(
        "--standby",
        action="store_true",
        help="Open early and keep the port open across Wi-Fi disconnects",
    )
    args = p.parse_args()

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    raw_log_path = args.raw_log or f"{args.out}.log"
    raw_log_dir = os.path.dirname(os.path.abspath(raw_log_path))
    if raw_log_dir:
        os.makedirs(raw_log_dir, exist_ok=True)

    ser = open_serial(args.port, args.baud, args.standby)
    label_sock = open_label_socket(args.label_bind, args.label_port)
    label_state = {"current": None, "intervals": []}
    min_offset = None
    last_uptime_sec = 0.0
    print(f"Listening for START/STOP labels on UDP :{args.label_port}")
    print(
        f"On Kali: export NIDS_SERIAL_LABEL_PORT={args.label_port} "
        "before attack_deauth.sh"
    )
    print(f"Raw console log: {raw_log_path}")
    if args.standby:
        print("Standby: leave this running; start deauth when ready. Ctrl+C to stop.")

    with (
        open(args.out, "w", newline="", encoding="utf-8") as csvfile,
        open(raw_log_path, "w", encoding="utf-8") as raw_log,
    ):
        writer = csv.writer(csvfile)
        writer.writerow(HEADER)
        try:
            while True:
                drain_labels(label_sock, label_state)
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
                drain_labels(label_sock, label_state)
                if not line:
                    continue
                received_at = datetime.now()
                raw_log.write(f"{received_at.isoformat()} {line}\n")
                raw_log.flush()
                sd = parse_sd(line)
                if not sd:
                    continue

                try:
                    uptime_sec = float(sd.get("uptime") or 0) / 1000.0
                except (TypeError, ValueError):
                    uptime_sec = 0.0
                offset = received_at - timedelta(seconds=uptime_sec)
                if min_offset is None or uptime_sec < last_uptime_sec - 5.0:
                    min_offset = offset
                elif offset < min_offset:
                    min_offset = offset
                last_uptime_sec = uptime_sec
                generated_at = min_offset + timedelta(seconds=uptime_sec)
                label, attack_type = label_for_time(generated_at, label_state)

                writer.writerow(canonical_row(
                    sd, label, attack_type, generated_at, line
                ))
                csvfile.flush()
        except KeyboardInterrupt:
            print("Stopped")
        finally:
            try:
                ser.close()
            except Exception:
                pass
            label_sock.close()


if __name__ == "__main__":
    main()

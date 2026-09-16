"""Show raw collector state. Never claim that old/stopped state is live."""
import argparse
import json
from pathlib import Path
import shlex
import time


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", default=str(Path(__file__).resolve().parents[1]/"data/raw_live_state.json"))
    a = p.parse_args(argv)
    try:
        state = json.loads(Path(a.state).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Start scripts/bringup.py --port COM3 first. State unavailable: {exc}")
        return 1
    if state.get("mode") != "raw" or not state.get("active") or time.time_ns()-state["updated_ns"] > 30_000_000_000:
        print("Collector state is stopped/stale; restart collector before using it.")
        return 1
    print(f"Raw USB capture: {state['dataset']} (session {state['session_id']})")
    if not state.get("esp32_ip"):
        print("ESP32 IP is not reported over raw protocol; supply --esp32-ip if needed.")
    for source, env in (("esp32_ip", "NIDS_ESP32_IP"), ("esp32_mac", "NIDS_ESP32_MAC")):
        if state.get(source):
            print(f"export {env}={shlex.quote(str(state[source]))}")
    if not state.get("control_port"):
        print("Label listener is disabled (enable --label-port 9999 for START/STOP).")
    elif state.get("label_host") in ("127.0.0.1", "localhost", "0.0.0.0"):
        print("Remote labels need --label-bind <PC-lab-IP> and --label-advertise <PC-lab-IP>.")
    else:
        print(f"export NIDS_LABEL_HOST={shlex.quote(state['label_host'])}")
        print(f"export NIDS_LABEL_PORT={state['control_port']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

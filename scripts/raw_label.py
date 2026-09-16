"""Send a label event (does not generate network attacks). Collector must be running."""
import argparse
import json
import socket


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("START", "STOP"))
    p.add_argument("--attack-type", default="attack")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    a = p.parse_args(argv)
    message = json.dumps({"status": a.action, "attack_type": a.attack_type}).encode()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect((a.host, a.port))
            sock.send(message)
            reply = json.loads(sock.recv(4096))
            print(reply)
            return 0 if reply.get("ok") else 1
    except (OSError, ValueError) as exc:
        print(f"No confirmed label ACK: {exc}. Check collector before continuing.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

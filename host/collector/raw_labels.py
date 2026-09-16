"""Optional bounded UDP label receiver; timestamps are HOST RECEIPT, not attack time.

Use only on a trusted lab network. No authentication and no clock synchronization.
An explicit baseline is restored on STOP; unknown never becomes normal implicitly.
"""
import json
import socket


def normalize_label(value):
    if value is None:
        return None
    value = str(value).strip().lower()
    if value in ("", "unknown", "null", "none"):
        return None
    if len(value) > 80 or not all(c.isalnum() or c in "_-" for c in value):
        raise ValueError("Label must contain at most 80 letters/digits/_/-")
    return value


class LabelReceiver:
    def __init__(self, bind, port, baseline):
        self.baseline = normalize_label(baseline)
        self.active = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((bind, port))
            self.socket.setblocking(False)
        except BaseException:
            self.socket.close()
            raise

    def process(self, raw, dataset):
        text = raw.decode("utf-8").strip()
        obj = {"status": text} if text in ("START", "STOP") else json.loads(text)
        if not isinstance(obj, dict):
            raise ValueError("Expected a JSON object")
        action = str(obj.get("status", "")).upper()
        if action == "START":
            label = normalize_label(obj.get("attack_type", "attack"))
            if label is None or label == "normal":
                raise ValueError("START requires a non-normal attack_type")
            if self.active is not None:
                if self.active == label:
                    return {"ok": True, "label": label, "duplicate": True}
                raise ValueError("An attack is already active; STOP before a new START")
        elif action == "STOP":
            if self.active is None:
                return {"ok": True, "label": self.baseline, "duplicate": True}
            label = self.baseline
        else:
            raise ValueError("status must be START or STOP")
        dataset.event("label_change", json.dumps({
            "label": label, "action": action, "clock": "host_receive_ns",
            "attack_type": self.active if action == "STOP" else label,
        }))
        dataset.flush()  # acknowledge only after the label event has committed
        self.active = label if action == "START" else None
        return {"ok": True, "label": label}

    def poll(self, dataset):
        for _ in range(32):  # label storms must not starve serial reads
            try:
                raw, peer = self.socket.recvfrom(2049)
            except BlockingIOError:
                break
            except ConnectionResetError:
                # Windows may surface an ICMP error when a legacy sender closes
                # its socket before our ACK arrives. It must not stop capture.
                continue
            try:
                if len(raw) > 2048:
                    raise ValueError("Label datagram too large")
                reply = self.process(raw, dataset)
                print(f"Label event: {reply}", flush=True)
            except (ValueError, UnicodeError) as exc:
                reply = {"ok": False, "error": str(exc)}
                dataset.event("label_rejected", str(exc))
            try:
                self.socket.sendto(json.dumps(reply).encode(), peer)
            except OSError:
                pass  # the event is already saved; ACK loss is not a dataset error

    def close(self):
        self.socket.close()

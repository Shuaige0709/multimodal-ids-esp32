"""Version 1 NIDR UART protocol. No third-party modules are needed to decode it.

Wire: NUL + COBS(little-endian header + body + IEEE CRC32) + NUL.
Device timestamps in the header are esp_timer microseconds, NOT rx_ctrl's
wrapping 32-bit hardware receive timestamp. Keep both without substituting one.
"""
from collections import Counter
from dataclasses import dataclass
import json
import struct
import zlib

MAGIC = b"NIDR"
VERSION = 1
HELLO, PACKET, STATUS = 1, 2, 3
FLAG_PAYLOAD_UNAVAILABLE = 1
FLAG_TRUNCATED = 2
HEADER = struct.Struct("<4sBBHIQIQ")
PACKET_FIXED = struct.Struct("<IIHHbb16BH")
STATUS_FIXED = struct.Struct("<15I3H2B")
CRC = struct.Struct("<I")
MAX_CAPTURED_LEN = 4095
MAX_WIRE_BLOCK = 5000
PACKET_FIELDS = (
    "packet_seq", "rx_timestamp_us32", "original_len", "captured_len",
    "rssi", "noise_floor", "pkt_type", "channel", "secondary_channel",
    "rate", "sig_mode", "mcs", "cwb", "smoothing", "not_sounding",
    "aggregation", "stbc", "fec_coding", "sgi", "ampdu_cnt", "ant",
    "rx_state", "rx_ctrl_len",
)
STATUS_FIELDS = (
    "sample_seq", "free_heap", "min_free_heap", "largest_free_internal",
    "free_internal", "reconnect_count", "callback_count", "enqueued_count",
    "drop_pool_count", "invalid_count", "payload_unavailable_count",
    "truncated_count", "tx_fail_count", "status_drop_count", "packets_sent",
    "queue_depth", "queue_peak", "pool_free", "connected", "primary_channel",
)


class ProtocolError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Message:
    kind: int
    flags: int
    boot_id: int
    stream_seq: int
    device_us: int
    body: bytes
    fields: dict


def cobs_encode(data):
    out = bytearray(b"\x00")
    code_at, code = 0, 1
    for value in data:
        if value == 0:
            out[code_at] = code
            code_at = len(out)
            out.append(0)
            code = 1
        else:
            out.append(value)
            code += 1
            if code == 255:
                out[code_at] = code
                code_at = len(out)
                out.append(0)
                code = 1
    out[code_at] = code
    return bytes(out)


def cobs_decode(data):
    out = bytearray()
    pos = 0
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == 0 or pos + code - 1 > len(data):
            raise ProtocolError("cobs_errors")
        out.extend(data[pos:pos + code - 1])
        pos += code - 1
        if code != 255 and pos < len(data):
            out.append(0)
    return bytes(out)


def encode_message(kind, body, *, boot_id=1, stream_seq=0, device_us=0, flags=0):
    """Reference encoder, also used for synthetic end-to-end testing."""
    raw = HEADER.pack(MAGIC, VERSION, kind, flags, len(body), boot_id,
                      stream_seq, device_us) + body
    return b"\0" + cobs_encode(raw + CRC.pack(zlib.crc32(raw))) + b"\0"


def decode_message(block):
    raw = cobs_decode(block)
    if len(raw) < HEADER.size + CRC.size:
        raise ProtocolError("length_errors")
    magic, version, kind, flags, body_len, boot_id, seq, device_us = HEADER.unpack_from(raw)
    if magic != MAGIC:
        raise ProtocolError("magic_errors")
    if version != VERSION:
        raise ProtocolError("version_errors")
    if body_len != len(raw) - HEADER.size - CRC.size:
        raise ProtocolError("length_errors")
    if CRC.unpack_from(raw, len(raw) - CRC.size)[0] != zlib.crc32(raw[:-CRC.size]):
        raise ProtocolError("crc_errors")
    if flags & ~(FLAG_PAYLOAD_UNAVAILABLE | FLAG_TRUNCATED) or (kind != PACKET and flags):
        raise ProtocolError("flag_errors")
    # sqlite INTEGER is signed. A valid esp_timer_get_time() is signed int64 too.
    if device_us >= (1 << 63):
        raise ProtocolError("timestamp_errors")
    body = raw[HEADER.size:-CRC.size]
    if kind == PACKET:
        if len(body) < PACKET_FIXED.size:
            raise ProtocolError("packet_length_errors")
        fields = dict(zip(PACKET_FIELDS, PACKET_FIXED.unpack_from(body)))
        caplen, ctrl_len = fields["captured_len"], fields["rx_ctrl_len"]
        if (caplen > MAX_CAPTURED_LEN or caplen > fields["original_len"]
                or len(body) != PACKET_FIXED.size + ctrl_len + caplen):
            raise ProtocolError("packet_length_errors")
        if flags & FLAG_PAYLOAD_UNAVAILABLE and caplen:
            raise ProtocolError("flag_errors")
        split = PACKET_FIXED.size + ctrl_len
        fields["rx_ctrl_raw"] = body[PACKET_FIXED.size:split]
        fields["payload"] = body[split:]
    elif kind == STATUS:
        if len(body) != STATUS_FIXED.size:
            raise ProtocolError("status_length_errors")
        fields = dict(zip(STATUS_FIELDS, STATUS_FIXED.unpack(body)))
    elif kind == HELLO:
        try:
            fields = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise ProtocolError("hello_errors") from None
        if not isinstance(fields, dict):
            raise ProtocolError("hello_errors")
    else:
        raise ProtocolError("kind_errors")
    return Message(kind, flags, boot_id, seq, device_us, body, fields)


class StreamParser:
    """Bounded streaming parser; damage/boot text is discarded up to a delimiter."""
    def __init__(self, max_block=MAX_WIRE_BLOCK):
        self.max_block = max_block
        self.buffer = bytearray()
        self.discarding = False
        self.stats = Counter()

    def feed(self, data):
        self.stats["wire_bytes"] += len(data)
        messages = []
        for value in data:
            if value == 0:
                if not self.discarding and self.buffer:
                    try:
                        messages.append(decode_message(self.buffer))
                        self.stats["valid_records"] += 1
                    except ProtocolError as exc:
                        self.stats[exc.reason] += 1
                self.buffer.clear()
                self.discarding = False
            elif not self.discarding:
                if len(self.buffer) >= self.max_block:
                    self.stats["oversize_errors"] += 1
                    self.buffer.clear()
                    self.discarding = True
                else:
                    self.buffer.append(value)
        return messages

    def reset_partial(self):
        """Never splice half a message from an old connection onto a new one."""
        if self.buffer or self.discarding:
            self.stats["discarded_partials"] += 1
        self.buffer.clear()
        self.discarding = False


class SequenceTracker:
    """Per-boot uint32 counters; initial attachment is not counted as packet loss."""
    def __init__(self):
        self.last = {}
        self.stats = Counter()

    def observe(self, boot_id, sequence):
        previous = self.last.get(boot_id)
        if previous is None:
            self.last[boot_id] = sequence
            return 0
        delta = (sequence - previous) & 0xffffffff
        if delta == 0:
            self.stats["duplicates"] += 1
            return 0
        if delta >= 0x80000000:
            self.stats["out_of_order"] += 1
            return 0
        self.last[boot_id] = sequence
        self.stats["gaps"] += delta - 1
        return delta - 1

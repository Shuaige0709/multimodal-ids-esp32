"""Loss-aware archive for the raw UART stream and its decoded dataset.

SQLite keeps bytes as BLOBs (no lossy text/hex conversion). Hardware states
remain separate samples. The packet_samples view performs a past-only as-of
join on (boot_id, esp_timer device_us), not arrival time or rx timestamp.
"""
from collections import Counter
from contextlib import suppress
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time
import uuid

from .raw_protocol import (
    HELLO, PACKET, STATUS, PACKET_FIELDS, STATUS_FIELDS, SequenceTracker,
    StreamParser,
)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class DatasetWriter:
    def __init__(self, output, *, port=None, baud=921600, label=None,
                 max_status_age_ms=250):
        if max_status_age_ms < 0:
            raise ValueError("max_status_age_ms must be nonnegative")
        self.path = Path(output)
        # An existing directory is never reused, even if it appears empty.
        self.path.mkdir(parents=True, exist_ok=False)
        self.session_id = str(uuid.uuid4())
        self.parser = StreamParser()
        self.stream_sequences = SequenceTracker()
        self.packet_sequences = SequenceTracker()
        self.counts = Counter()
        self.latest_status = None
        self.latest_hello = None
        self.latest_hello_ns = 0
        self.offset = 0
        self.closed = False
        self.manifest = {
            "dataset_schema_version": 1, "protocol_version": 1,
            "session_id": self.session_id, "started_at_utc": _utc_now(),
            "port": port, "baud": baud, "label": label,
            "label_semantics": "constant experiment label; null means unknown",
            "max_status_age_ms": max_status_age_ms,
            "clock": "esp_timer_callback_us", "rx_timestamp_bits": 32,
            "raw_wire": "wire.bin", "database": "dataset.sqlite3",
            "note": "Driver-visible frames only; capture and transport may drop records.",
        }
        with (self.path / "manifest.json").open("x", encoding="utf-8") as out:
            json.dump(self.manifest, out, ensure_ascii=False, indent=2)
        self.wire = self.db = None
        try:
            self.wire = (self.path / "wire.bin").open("xb")
            self.db = sqlite3.connect(self.path / "dataset.sqlite3")
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self._create_schema()
            self.db.execute("INSERT INTO sessions VALUES (?, ?, NULL, ?, ?, ?, ?, NULL)",
                            (self.session_id, self.manifest["started_at_utc"], port,
                             baud, label, int(max_status_age_ms * 1000)))
            self.flush()
        except BaseException:
            # Preserve the original failure and the partial archive for diagnosis.
            # __exit__ is not called if construction itself raises.
            if self.db is not None:
                with suppress(sqlite3.Error):
                    self.db.close()
            if self.wire is not None:
                with suppress(OSError):
                    self.wire.close()
            self.closed = True
            raise

    def _create_schema(self):
        packet_cols = ",\n".join(f"{name} INTEGER NOT NULL" for name in PACKET_FIELDS)
        status_cols = ",\n".join(f"{name} INTEGER NOT NULL" for name in STATUS_FIELDS)
        joined_status = ",\n".join(f"s.{name} AS status_{name}" for name in STATUS_FIELDS)
        self.db.executescript(f"""
            PRAGMA user_version=1;
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY, started_at_utc TEXT NOT NULL,
                ended_at_utc TEXT, port TEXT, baud INTEGER NOT NULL, label TEXT,
                max_status_age_us INTEGER NOT NULL, end_reason TEXT);
            CREATE TABLE records (
                record_id INTEGER PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions,
                boot_id TEXT NOT NULL, stream_seq INTEGER NOT NULL,
                device_us INTEGER NOT NULL, host_arrival_ns INTEGER NOT NULL,
                kind INTEGER NOT NULL, flags INTEGER NOT NULL,
                stream_gap_before INTEGER NOT NULL, body BLOB NOT NULL);
            CREATE INDEX records_time ON records(kind, boot_id, device_us, record_id);
            CREATE TABLE packets (
                record_id INTEGER PRIMARY KEY REFERENCES records,
                {packet_cols}, rx_ctrl_raw BLOB NOT NULL, payload BLOB NOT NULL,
                packet_gap_before INTEGER NOT NULL);
            CREATE TABLE statuses (
                record_id INTEGER PRIMARY KEY REFERENCES records, {status_cols});
            CREATE TABLE hellos (
                record_id INTEGER PRIMARY KEY REFERENCES records, metadata_json TEXT NOT NULL);
            CREATE TABLE wire_chunks (
                chunk_id INTEGER PRIMARY KEY, byte_offset INTEGER NOT NULL,
                byte_length INTEGER NOT NULL, host_arrival_ns INTEGER NOT NULL);
            CREATE TABLE events (
                event_id INTEGER PRIMARY KEY, host_time_ns INTEGER NOT NULL,
                wire_offset INTEGER NOT NULL, name TEXT NOT NULL, detail TEXT);
            CREATE VIEW packet_samples AS
            SELECT r.session_id, r.boot_id, r.stream_seq, r.device_us,
                   r.host_arrival_ns, r.flags, r.stream_gap_before,
                   p.*, session.label, s.record_id AS status_record_id,
                   sr.device_us AS status_device_us,
                   r.device_us - sr.device_us AS status_age_us,
                   CASE WHEN sr.record_id IS NULL THEN 1 ELSE 0 END AS status_missing,
                   CASE WHEN sr.record_id IS NOT NULL AND
                        r.device_us - sr.device_us > session.max_status_age_us
                        THEN 1 ELSE 0 END AS status_stale,
                   CASE WHEN sr.record_id IS NOT NULL AND
                        r.device_us - sr.device_us <= session.max_status_age_us
                        THEN 1 ELSE 0 END AS status_valid,
                   {joined_status}
              FROM packets p JOIN records r USING(record_id)
              JOIN sessions session ON session.session_id = r.session_id
              LEFT JOIN records sr ON sr.record_id = (
                  SELECT past.record_id FROM records past
                   WHERE past.kind = 3 AND past.boot_id = r.boot_id
                     AND past.session_id = r.session_id AND past.device_us <= r.device_us
                   ORDER BY past.device_us DESC, past.record_id DESC LIMIT 1)
              LEFT JOIN statuses s ON s.record_id = sr.record_id;
        """)

    def ingest(self, data, host_arrival_ns=None):
        if self.closed:
            raise ValueError("dataset is closed")
        if not data:
            return 0
        arrival = time.time_ns() if host_arrival_ns is None else host_arrival_ns
        # Preserve the exact bytes first, including startup text and failed CRCs.
        if self.wire.write(data) != len(data):
            raise OSError("Short write to wire.bin; capture stopped to avoid silent data loss")
        self.db.execute("INSERT INTO wire_chunks(byte_offset, byte_length, host_arrival_ns) "
                        "VALUES (?, ?, ?)", (self.offset, len(data), arrival))
        self.offset += len(data)
        messages = self.parser.feed(data)
        for message in messages:
            self.add_message(message, arrival)
        return len(messages)

    def add_message(self, message, host_arrival_ns):
        # Header and typed body must commit together. On disk/SQL errors never
        # leave a status header that the as-of view could mistake for a sample.
        self.db.execute("SAVEPOINT record_write")
        try:
            self._add_message(message, host_arrival_ns)
        except BaseException:
            with suppress(sqlite3.Error):
                self.db.execute("ROLLBACK TO record_write")
                self.db.execute("RELEASE record_write")
            raise
        else:
            self.db.execute("RELEASE record_write")

    def _add_message(self, message, host_arrival_ns):
        gap = self.stream_sequences.observe(message.boot_id, message.stream_seq)
        # u64 random boot IDs need text; SQLite integers are signed 64-bit.
        boot_id = f"{message.boot_id:016x}"
        result = self.db.execute(
            "INSERT INTO records(session_id, boot_id, stream_seq, device_us, host_arrival_ns, "
            "kind, flags, stream_gap_before, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (self.session_id, boot_id, message.stream_seq, message.device_us,
             host_arrival_ns, message.kind, message.flags, gap, message.body))
        record_id = result.lastrowid
        if message.kind == PACKET:
            fields = message.fields
            packet_gap = self.packet_sequences.observe(message.boot_id, fields["packet_seq"])
            values = [record_id] + [fields[name] for name in PACKET_FIELDS]
            values += [fields["rx_ctrl_raw"], fields["payload"], packet_gap]
            self.db.execute("INSERT INTO packets VALUES (" + ",".join("?" for _ in values) + ")",
                            values)
            self.counts["packets"] += 1
        elif message.kind == STATUS:
            values = [record_id] + [message.fields[name] for name in STATUS_FIELDS]
            self.db.execute("INSERT INTO statuses VALUES (" + ",".join("?" for _ in values) + ")",
                            values)
            self.counts["statuses"] += 1
            self.latest_status = {"boot_id": boot_id, "device_us": message.device_us,
                                  **message.fields}
        elif message.kind == HELLO:
            self.db.execute("INSERT INTO hellos VALUES (?, ?)",
                            (record_id, message.body.decode("utf-8")))
            self.counts["hellos"] += 1
            self.latest_hello = message.fields
            self.latest_hello_ns = time.time_ns()

    def event(self, name, detail=None):
        self.db.execute("INSERT INTO events(host_time_ns, wire_offset, name, detail) "
                        "VALUES (?, ?, ?, ?)", (time.time_ns(), self.offset, name, detail))

    def connection_break(self, reason):
        self.latest_hello = None
        self.latest_hello_ns = 0
        self.parser.reset_partial()
        self.event("serial_disconnect", str(reason))
        self.flush()

    def statistics(self):
        return {"records": dict(self.counts), "parser": dict(self.parser.stats),
                "stream_sequence": dict(self.stream_sequences.stats),
                "packet_sequence": dict(self.packet_sequences.stats),
                "latest_status": self.latest_status}

    def flush(self):
        self.wire.flush()
        self.db.commit()

    def close(self, reason="completed"):
        if self.closed:
            return
        self.parser.reset_partial()
        ended = _utc_now()
        try:
            self.db.execute("UPDATE sessions SET ended_at_utc=?, end_reason=? WHERE session_id=?",
                            (ended, reason, self.session_id))
            self.flush()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            summary = {"session_id": self.session_id, "ended_at_utc": ended,
                       "end_reason": reason, **self.statistics()}
            with (self.path / "summary.json").open("x", encoding="utf-8") as out:
                json.dump(summary, out, ensure_ascii=False, indent=2)
        finally:
            try:
                self.db.close()
            finally:
                try:
                    self.wire.close()
                finally:
                    self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close("completed" if exc_type is None else str(exc_type.__name__))

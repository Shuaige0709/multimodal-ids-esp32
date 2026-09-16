"""Run with: python -m unittest discover -s tests -p test_raw_capture.py -v"""
import contextlib
import io
import json
from pathlib import Path
import random
import sqlite3
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

from host.collector.raw_protocol import (
    CRC, HEADER, HELLO, MAGIC, PACKET, PACKET_FIELDS, PACKET_FIXED, STATUS,
    STATUS_FIELDS, STATUS_FIXED, VERSION, ProtocolError, SequenceTracker,
    StreamParser, cobs_decode, cobs_encode, decode_message, encode_message,
)
from host.collector.raw_dataset import DatasetWriter
from scripts import serial_collector
from scripts.export_raw_dataset import export_dataset


def packet_body(seq=0, payload=b"\x80\x00\x01\x02\xff", rx_ctrl=bytes(range(28)),
                rx_timestamp=0xfffffffe):
    fields = dict(zip(PACKET_FIELDS, [seq, rx_timestamp, len(payload), len(payload),
                                     -57, -96] + list(range(16)) + [len(rx_ctrl)]))
    return PACKET_FIXED.pack(*(fields[name] for name in PACKET_FIELDS)) + rx_ctrl + payload


def status_body(seq=0):
    return STATUS_FIXED.pack(seq, *range(70001, 70015), 4, 8, 12, 1, 3)


def hello_wire(**kwargs):
    return encode_message(HELLO, b'{"target":"esp32","baud":921600}', **kwargs)


class ProtocolTests(unittest.TestCase):
    def test_binary_layout_independent_offsets(self):
        self.assertEqual(HEADER.size, 32)
        self.assertEqual(PACKET_FIXED.size, 32)
        self.assertEqual(STATUS_FIXED.size, 68)
        raw = bytearray(32)
        raw[:4] = MAGIC
        raw[4], raw[5] = VERSION, PACKET
        struct.pack_into("<H", raw, 6, 3)
        struct.pack_into("<I", raw, 8, 100)
        struct.pack_into("<Q", raw, 12, 0xfedcba9876543210)
        struct.pack_into("<I", raw, 20, 0xfffffffe)
        struct.pack_into("<Q", raw, 24, 123456789)
        self.assertEqual(bytes(raw), HEADER.pack(MAGIC, VERSION, PACKET, 3, 100,
                         0xfedcba9876543210, 0xfffffffe, 123456789))
        body = packet_body(seq=0x12345678)
        self.assertEqual(body[:4], b"\x78\x56\x34\x12")
        self.assertEqual(body[12:14], bytes([199, 160]))
        self.assertEqual(body[14:30], bytes(range(16)))
        self.assertEqual(body[30:32], b"\x1c\x00")

    def test_all_fields_roundtrip(self):
        packet = decode_message(encode_message(PACKET, packet_body(42), boot_id=2**64-1,
                                stream_seq=9, device_us=2**32+100, flags=2)[1:-1])
        self.assertEqual((packet.boot_id, packet.stream_seq, packet.device_us, packet.flags),
                         (2**64-1, 9, 2**32+100, 2))
        expected = dict(zip(PACKET_FIELDS, [42, 0xfffffffe, 5, 5, -57, -96]
                            + list(range(16)) + [28]))
        self.assertEqual({name: packet.fields[name] for name in PACKET_FIELDS}, expected)
        self.assertEqual(packet.fields["rx_ctrl_raw"], bytes(range(28)))
        self.assertEqual(packet.fields["payload"], b"\x80\0\x01\x02\xff")
        status = decode_message(encode_message(STATUS, status_body(5))[1:-1])
        self.assertEqual(list(status.fields), list(STATUS_FIELDS))
        self.assertEqual(list(status.fields.values()), [5] + list(range(70001, 70015))
                         + [4, 8, 12, 1, 3])
        self.assertEqual(decode_message(hello_wire()[1:-1]).fields["baud"], 921600)

    def test_cobs_all_byte_values_and_boundaries(self):
        for data in (b"", b"\0", b"\0" * 100, bytes(range(256)), b"x" * 254,
                     b"x" * 255, b"x" * 508, bytes(range(256)) * 18):
            encoded = cobs_encode(data)
            self.assertNotIn(0, encoded)
            self.assertEqual(cobs_decode(encoded), data)
        with self.assertRaises(ProtocolError):
            cobs_decode(b"\x05\x01")

    def test_fragmentation_boot_noise_crc_and_resync(self):
        good = encode_message(PACKET, packet_body(1))
        raw = bytearray(cobs_decode(good[1:-1]))
        raw[-5] ^= 1
        bad = b"\0" + cobs_encode(raw) + b"\0"
        stream = b"boot garbage\xff\xfe\n" + good + bad + hello_wire(stream_seq=2)
        parser = StreamParser()
        messages = []
        for value in stream:
            messages.extend(parser.feed(bytes([value])))
        self.assertEqual([m.kind for m in messages], [PACKET, HELLO])
        self.assertEqual(parser.stats["crc_errors"], 1)
        self.assertEqual(parser.stats["wire_bytes"], len(stream))

    def test_random_chunks_and_maximum_payload(self):
        rng = random.Random(7)
        payload = bytes(rng.randrange(256) for _ in range(4095))
        wire = encode_message(PACKET, packet_body(payload=payload)) * 3
        parser, messages, offset = StreamParser(), [], 0
        while offset < len(wire):
            length = rng.randrange(1, 100)
            messages.extend(parser.feed(wire[offset:offset + length]))
            offset += length
        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[0].fields["payload"], payload)
        self.assertEqual(parser.stats["oversize_errors"], 0)

    def test_oversize_bounded_and_reconnect(self):
        parser = StreamParser()
        self.assertEqual(parser.feed(b"x" * 20000), [])
        self.assertLessEqual(len(parser.buffer), 5000)
        self.assertEqual(parser.stats["oversize_errors"], 1)
        self.assertEqual(len(parser.feed(hello_wire())), 1)
        wire = hello_wire()
        parser.feed(wire[:10])
        parser.reset_partial()
        self.assertEqual(parser.stats["discarded_partials"], 1)
        messages = parser.feed(wire[10:] + wire)
        self.assertEqual(len(messages), 1)

    def test_invalid_version_length_type_and_body(self):
        cases = [(PACKET, b"short", "packet_length_errors"),
                 (STATUS, b"short", "status_length_errors"),
                 (HELLO, b"[]", "hello_errors"),
                 (HELLO, b"\xff", "hello_errors"),
                 (99, b"", "kind_errors")]
        for kind, body, reason in cases:
            with self.subTest(reason=reason):
                parser = StreamParser()
                self.assertEqual(parser.feed(encode_message(kind, body)), [])
                self.assertEqual(parser.stats[reason], 1)
        wire = hello_wire()
        for offset, value, reason in [(4, 9, "version_errors"), (8, 255, "length_errors"),
                                      (0, 42, "magic_errors")]:
            raw = bytearray(cobs_decode(wire[1:-1]))
            raw[offset] = value
            parser = StreamParser()
            self.assertEqual(parser.feed(b"\0" + cobs_encode(raw) + b"\0"), [])
            self.assertEqual(parser.stats[reason], 1)
        fields = list(PACKET_FIXED.unpack(packet_body()[:32]))
        fields[3] = 4000
        parser = StreamParser()
        parser.feed(encode_message(PACKET, PACKET_FIXED.pack(*fields)))
        self.assertEqual(parser.stats["packet_length_errors"], 1)

    def test_misc_payload_unavailable(self):
        body = PACKET_FIXED.pack(4, 8, 2000, 0, -40, -90, *([0] * 16), 28) + bytes(28)
        message = decode_message(encode_message(PACKET, body, flags=1)[1:-1])
        self.assertEqual(message.fields["payload"], b"")
        self.assertEqual(message.fields["original_len"], 2000)

    def test_invalid_flags_are_rejected(self):
        for kind, body, flags in [(HELLO, b"{}", 1), (PACKET, packet_body(), 4),
                                  (PACKET, packet_body(), 1)]:
            parser = StreamParser()
            self.assertEqual(parser.feed(encode_message(kind, body, flags=flags)), [])
            self.assertEqual(parser.stats["flag_errors"], 1)

    def test_sequence_wrap_loss_reboot_duplicate_out_of_order(self):
        tracker = SequenceTracker()
        self.assertEqual([tracker.observe(1, n) for n in (0xfffffffe, 0xffffffff, 0, 3)],
                         [0, 0, 0, 2])
        self.assertEqual(tracker.observe(1, 3), 0)
        self.assertEqual(tracker.observe(1, 2), 0)
        self.assertEqual(tracker.observe(1, 4), 0)
        self.assertEqual(tracker.observe(2, 1000), 0)
        self.assertEqual(dict(tracker.stats), {"gaps": 2, "duplicates": 1, "out_of_order": 1})


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name) / "session"

    def tearDown(self):
        self.temp.cleanup()

    def test_raw_wire_metadata_unknown_label_and_sqlite_persistence(self):
        wire = b"ROM noise\xff" + hello_wire(boot_id=2**64-1) + encode_message(
            PACKET, packet_body(100), boot_id=2**64-1, stream_seq=2, device_us=2**32+10)
        with DatasetWriter(self.output) as dataset:
            dataset.ingest(wire[:17], 123)
            dataset.ingest(wire[17:], 456)
            row = dataset.db.execute("SELECT * FROM packet_samples").fetchone()
            self.assertIsNone(row["label"])
            self.assertEqual(row["boot_id"], "ffffffffffffffff")
            self.assertEqual(row["device_us"], 2**32+10)
            self.assertEqual(row["rx_timestamp_us32"], 0xfffffffe)
            self.assertEqual(row["host_arrival_ns"], 456)
            self.assertEqual(row["rssi"], -57)
            self.assertEqual(row["rx_ctrl_raw"], bytes(range(28)))
            self.assertEqual(row["payload"], b"\x80\0\x01\x02\xff")
            self.assertEqual(row["stream_gap_before"], 1)
            self.assertEqual(row["packet_gap_before"], 0)
            self.assertEqual(row["status_missing"], 1)
        self.assertEqual((self.output / "wire.bin").read_bytes(), wire)
        with contextlib.closing(sqlite3.connect(self.output / "dataset.sqlite3")) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT end_reason FROM sessions").fetchone()[0], "completed")
            self.assertEqual(db.execute("SELECT count(*) FROM wire_chunks").fetchone()[0], 2)
        self.assertEqual(json.loads((self.output / "summary.json").read_text())["records"]["packets"], 1)

    def test_asof_no_future_no_other_boot_stale_and_order_independent(self):
        with DatasetWriter(self.output, label="attack", max_status_age_ms=250) as dataset:
            messages = [
                encode_message(STATUS, status_body(9), boot_id=2, device_us=50),
                encode_message(STATUS, status_body(2), stream_seq=2, device_us=200000),
                encode_message(PACKET, packet_body(3), stream_seq=3, device_us=150000),
                encode_message(STATUS, status_body(1), stream_seq=4, device_us=100000),
                encode_message(PACKET, packet_body(4), stream_seq=5, device_us=50000),
                encode_message(PACKET, packet_body(5), stream_seq=6, device_us=450001),
                encode_message(PACKET, packet_body(6), stream_seq=7, device_us=450000),
                encode_message(PACKET, packet_body(7), boot_id=3, device_us=500000),
            ]
            for message in messages:
                dataset.ingest(message)
            rows = {row["packet_seq"]: row for row in dataset.db.execute("SELECT * FROM packet_samples")}
            self.assertEqual(rows[3]["status_sample_seq"], 1)
            self.assertEqual(rows[3]["status_age_us"], 50000)
            self.assertEqual(rows[3]["status_valid"], 1)
            self.assertEqual(rows[3]["label"], "attack")
            self.assertEqual(rows[4]["status_missing"], 1)
            self.assertIsNone(rows[4]["status_free_heap"])
            self.assertEqual(rows[5]["status_stale"], 1)
            self.assertEqual(rows[5]["status_valid"], 0)
            self.assertEqual(rows[6]["status_stale"], 0)
            self.assertEqual(rows[6]["status_valid"], 1)
            self.assertEqual(rows[7]["status_missing"], 1)

    def test_nonoverwrite(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_text("keep")
        with self.assertRaises(FileExistsError):
            DatasetWriter(self.output)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_reconnect_event_and_partial_discard(self):
        wire = hello_wire()
        with DatasetWriter(self.output) as dataset:
            dataset.ingest(wire[:12])
            dataset.connection_break("USB removed")
            dataset.ingest(wire[12:] + wire)
            self.assertEqual(dataset.counts["hellos"], 1)
            self.assertEqual(dataset.parser.stats["discarded_partials"], 1)
            event = dataset.db.execute("SELECT * FROM events").fetchone()
            self.assertEqual(event["wire_offset"], 12)
        self.assertEqual((self.output / "wire.bin").read_bytes(), wire + wire)

    def test_jsonl_export_asof_override_and_nonoverwrite(self):
        with DatasetWriter(self.output) as dataset:
            dataset.ingest(encode_message(STATUS, status_body(), device_us=100))
            dataset.ingest(encode_message(PACKET, packet_body(), device_us=200100, stream_seq=1))
        target = Path(self.temp.name) / "packets.jsonl"
        self.assertEqual(export_dataset(self.output, target, max_status_age_ms=100), 1)
        row = json.loads(target.read_text())
        self.assertEqual(row["payload_hex"], "80000102ff")
        self.assertEqual(row["rx_ctrl_raw_hex"], bytes(range(28)).hex())
        self.assertEqual(row["status_stale"], 1)
        self.assertEqual(row["status_valid"], 0)
        self.assertIsNone(row["label"])
        with self.assertRaises(FileExistsError):
            export_dataset(self.output, target)
        with contextlib.closing(sqlite3.connect(self.output / "dataset.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT status_valid FROM packet_samples").fetchone()[0], 1)

    def test_export_omit_payload_and_missing_source_is_not_created(self):
        with DatasetWriter(self.output) as dataset:
            dataset.ingest(encode_message(PACKET, packet_body()))
        target = Path(self.temp.name) / "metadata.jsonl"
        export_dataset(self.output, target, omit_payload=True)
        row = json.loads(target.read_text())
        self.assertNotIn("payload_hex", row)
        self.assertIn("rx_ctrl_raw_hex", row)
        missing = Path(self.temp.name) / "missing.sqlite3"
        with self.assertRaises(sqlite3.OperationalError):
            export_dataset(missing, Path(self.temp.name) / "no.jsonl")
        self.assertFalse(missing.exists())

    def test_constructor_failure_closes_partial_resources(self):
        writer = DatasetWriter.__new__(DatasetWriter)
        with patch.object(DatasetWriter, "_create_schema", side_effect=sqlite3.OperationalError("full")):
            with self.assertRaises(sqlite3.OperationalError):
                writer.__init__(self.output)
        self.assertTrue(writer.closed)
        self.assertTrue(writer.wire.closed)
        with self.assertRaises(sqlite3.ProgrammingError):
            writer.db.execute("SELECT 1")

    def test_constructor_db_open_failure_closes_wire(self):
        writer = DatasetWriter.__new__(DatasetWriter)
        with patch("host.collector.raw_dataset.sqlite3.connect", side_effect=sqlite3.OperationalError("full")):
            with self.assertRaises(sqlite3.OperationalError):
                writer.__init__(self.output)
        self.assertTrue(writer.closed)
        self.assertTrue(writer.wire.closed)

    def test_flush_failure_still_closes_both_handles(self):
        writer = DatasetWriter(self.output)
        with patch.object(writer, "flush", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                writer.close("collector_error")
        self.assertTrue(writer.closed)
        self.assertTrue(writer.wire.closed)
        with self.assertRaises(sqlite3.ProgrammingError):
            writer.db.execute("SELECT 1")

    def test_typed_body_failure_does_not_leave_orphan_record(self):
        with DatasetWriter(self.output) as dataset:
            dataset.db.execute("CREATE TRIGGER reject_status BEFORE INSERT ON statuses "
                               "BEGIN SELECT RAISE(FAIL, 'simulated storage failure'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                dataset.ingest(encode_message(STATUS, status_body()))
            self.assertEqual(dataset.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)
            self.assertEqual(dataset.db.execute("SELECT count(*) FROM wire_chunks").fetchone()[0], 1)
            self.assertEqual(dataset.counts["statuses"], 0)

    def test_short_wire_write_stops_before_decoding(self):
        with DatasetWriter(self.output) as dataset:
            original_wire = dataset.wire
            class ShortWriter:
                def write(self, data):
                    return original_wire.write(data[:1])
                def flush(self):
                    original_wire.flush()
                def close(self):
                    original_wire.close()
            dataset.wire = ShortWriter()
            with self.assertRaises(OSError):
                dataset.ingest(hello_wire())
            self.assertEqual(dataset.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)
            self.assertEqual(dataset.offset, 0)


class FakeSerialError(Exception):
    pass


class FakeConnection:
    def __init__(self, chunks, **kwargs):
        self.chunks = list(chunks)
        self.closed = False
        self.kwargs = kwargs
        self.dtr = self.rts = True

    def open(self):
        if self.dtr or self.rts or self.kwargs["port"] is not None:
            raise AssertionError("DTR/RTS must be configured before open")

    @property
    def in_waiting(self):
        return 65536

    def read(self, count):
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def close(self):
        self.closed = True


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name) / "session"
        self.connections = []

    def tearDown(self):
        self.temp.cleanup()

    def module(self, connection_chunks):
        batches = list(connection_chunks)
        def factory(**kwargs):
            connection = FakeConnection(batches.pop(0), **kwargs)
            self.connections.append(connection)
            return connection
        return types.SimpleNamespace(Serial=factory, SerialException=FakeSerialError)

    def run_cli(self, module, *extra):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return serial_collector.main(["--port", "COM_TEST", "--out", str(self.output), *extra],
                                         serial_module=module)

    def test_ctrl_c_flush_and_default_baud(self):
        wire = hello_wire() + encode_message(PACKET, packet_body())
        self.assertEqual(self.run_cli(self.module([[wire, KeyboardInterrupt()]])), 0)
        self.assertTrue(self.connections[0].closed)
        self.assertEqual(self.connections[0].kwargs["baudrate"], 921600)
        self.assertEqual((self.output / "wire.bin").read_bytes(), wire)
        with contextlib.closing(sqlite3.connect(self.output / "dataset.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM packets").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT end_reason FROM sessions").fetchone()[0], "user_interrupt")

    def test_serial_failure_exits_nonzero(self):
        self.assertEqual(self.run_cli(self.module([[hello_wire(), FakeSerialError("gone")]])), 1)
        with contextlib.closing(sqlite3.connect(self.output / "dataset.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT end_reason FROM sessions").fetchone()[0], "serial_error")
        self.assertTrue(self.connections[0].closed)

    def test_standby_reconnects_with_parser_reset(self):
        wire = hello_wire()
        module = self.module([[wire[:10], FakeSerialError("gone")], [wire, KeyboardInterrupt()]])
        with patch.object(serial_collector.time, "sleep"):
            self.assertEqual(self.run_cli(module, "--standby"), 0)
        self.assertTrue(all(connection.closed for connection in self.connections))
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(summary["records"]["hellos"], 1)
        self.assertEqual(summary["parser"]["discarded_partials"], 1)

    def test_existing_output_cli_rejected_before_serial_open(self):
        self.output.mkdir()
        with self.assertRaises(SystemExit) as exc:
            self.run_cli(self.module([]))
        self.assertEqual(exc.exception.code, 2)
        self.assertEqual(self.connections, [])

    def test_help_without_pyserial(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exc:
            serial_collector.main(["--help"])
        self.assertEqual(exc.exception.code, 0)

    def test_final_statistics_failure_still_flushes_and_closes(self):
        with patch.object(serial_collector, "_print_stats", side_effect=OSError("output closed")):
            self.assertEqual(self.run_cli(self.module([[hello_wire(), KeyboardInterrupt()]])), 1)
        self.assertTrue(self.connections[0].closed)
        with contextlib.closing(sqlite3.connect(self.output / "dataset.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM hellos").fetchone()[0], 1)
        self.assertTrue((self.output / "summary.json").exists())

    def test_disk_failure_is_not_reported_as_serial_failure(self):
        with patch.object(DatasetWriter, "ingest", side_effect=OSError("disk full")):
            self.assertEqual(self.run_cli(self.module([[hello_wire()]])), 1)
        self.assertTrue(self.connections[0].closed)
        with contextlib.closing(sqlite3.connect(self.output / "dataset.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT end_reason FROM sessions").fetchone()[0], "collector_error")


if __name__ == "__main__":
    unittest.main()

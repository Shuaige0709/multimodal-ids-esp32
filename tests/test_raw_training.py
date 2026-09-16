"""Offline fixtures only: no COM access, flashing, attacks, or real dataset relabeling."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import socket
import tempfile
import unittest
from unittest.mock import patch

from host.collector.raw_dataset import DatasetWriter
from host.collector.raw_labels import LabelReceiver, normalize_label
from host.collector.raw_protocol import PACKET, STATUS, PACKET_FIELDS, PACKET_FIXED, STATUS_FIELDS, STATUS_FIXED, encode_message
from host.train.raw_features import parse_header
from host.train.raw_windows import archive_windows, build_windows, label_for_interval
from host.train.train_raw import train, load_rows
from scripts import bringup, serial_collector


def header(fc=0x80, extra=b""):
    return (fc.to_bytes(2, "little") + b"\0\0" + b"\xff"*6
            + bytes.fromhex("001122334455") + bytes.fromhex("aabbccddeeff") + b"\x10\0" + extra)


def make_archive(path, label="normal", *, bad=False, drop=False, empty=False, stale=False):
    writer = DatasetWriter(path, label=label)
    seq = pkt = 0
    for t in range(0, 1_100_000, 100_000):
        if stale and t == 400_000:
            continue
        state = dict.fromkeys(STATUS_FIELDS, 0)
        state.update(sample_seq=t//100_000, free_heap=123000+t//1000,
                     min_free_heap=120000, largest_free_internal=100000,
                     free_internal=123000, pool_free=16, connected=1, primary_channel=3,
                     drop_pool_count=int(drop and t >= 500_000))
        writer.ingest(encode_message(STATUS, STATUS_FIXED.pack(*(state[k] for k in STATUS_FIELDS)),
                                     stream_seq=seq, device_us=t), 1_000_000_000+t*1000)
        seq += 1
        if empty or t == 1_000_000:
            continue
        for delay in (10000, 20000, 30000):
            payload = b"x" if bad else header(0xc0 if label != "normal" else 0x80)
            fields = dict.fromkeys(PACKET_FIELDS, 0)
            fields.update(packet_seq=pkt, original_len=len(payload), captured_len=len(payload),
                          rssi=-55, noise_floor=-95, channel=3)
            body = PACKET_FIXED.pack(*(fields[k] for k in PACKET_FIELDS)) + payload
            writer.ingest(encode_message(PACKET, body, stream_seq=seq, device_us=t+delay),
                          1_000_000_000+(t+delay)*1000)
            seq += 1
            pkt += 1
    writer.close()
    return writer.session_id


class HeaderTests(unittest.TestCase):
    def test_management_data_and_ds_mapping(self):
        self.assertEqual(parse_header(header())["subtype"], 8)
        self.assertEqual(parse_header(header(0x0108))["bssid"], b"\xff"*6)
        self.assertEqual(parse_header(header(0x0208))["bssid"], bytes.fromhex("001122334455"))
        self.assertIsNone(parse_header(header(0x0308)))
        self.assertIsNone(parse_header(header(0x0308, b"123456"))["bssid"])

    def test_qos_and_ht_minimum_lengths(self):
        self.assertIsNone(parse_header(header(0x0388, b"123456")))
        self.assertIsNotNone(parse_header(header(0x0388, b"12345678")))
        self.assertIsNone(parse_header(header(0x8388, b"12345678")))
        self.assertIsNotNone(parse_header(header(0x8388, b"123456789012")))

    def test_control_and_invalid(self):
        self.assertIsNotNone(parse_header(b"\xd4\0"+b"\0"*8))
        self.assertIsNone(parse_header(b"\xb4\0"+b"\0"*8))
        self.assertIsNone(parse_header(b"\x80"))
        self.assertIsNone(parse_header(header(0x81)))
        self.assertIsNone(parse_header(header(0x180)))


class LauncherTests(unittest.TestCase):
    def test_raw_is_default_and_explicit_state_is_preserved(self):
        with patch.object(serial_collector, "main", return_value=0) as collect:
            self.assertEqual(bringup.main(["--port", "COM_TEST"]), 0)
            self.assertIn("--live-state", collect.call_args.args[0])
            bringup.main(["--port", "COM_TEST", "--live-state=custom.json"])
            self.assertNotIn("--live-state", collect.call_args.args[0])

    def test_live_file_stopped_state_and_no_inferred_ip(self):
        import types
        with tempfile.TemporaryDirectory() as tmp, DatasetWriter(Path(tmp)/"archive") as writer:
            args = types.SimpleNamespace(live_state=str(Path(tmp)/"state.json"), port="TEST",
                baud=921600, esp32_ip=None, label_advertise=None, label_bind="127.0.0.1", label_port=0)
            serial_collector.publish_live(writer, args, active=False)
            state = json.loads(Path(args.live_state).read_text())
            self.assertFalse(state["active"])
            self.assertIsNone(state["esp32_ip"])

    def test_live_path_cannot_overwrite_archive(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                serial_collector.main(["--port", "TEST", "--out", str(Path(tmp)/"archive"),
                    "--live-state", str(Path(tmp)/"archive/manifest.json")], serial_module=object())


class LabelsTests(unittest.TestCase):
    def test_unknown_and_guard(self):
        self.assertIsNone(normalize_label("unknown"))
        events = [(100, "deauth"), (200, "normal")]
        self.assertEqual(label_for_interval("normal", events, 110, 120, 0), ("deauth", False))
        self.assertEqual(label_for_interval("normal", events, 90, 110, 0), (None, True))
        self.assertEqual(label_for_interval("normal", events, 210, 220, 20), (None, True))
        self.assertEqual(label_for_interval(None, [], 0, 10, 0), (None, False))

    def test_receiver_start_stop_and_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp, DatasetWriter(Path(tmp)/"data") as writer:
            receiver = LabelReceiver("127.0.0.1", 0, None)
            try:
                self.assertEqual(receiver.process(b'{"status":"START","attack_type":"deauth"}', writer)["label"], "deauth")
                self.assertTrue(receiver.process(b'{"status":"START","attack_type":"deauth"}', writer)["duplicate"])
                with self.assertRaises(ValueError):
                    receiver.process(b'{"status":"START","attack_type":"different"}', writer)
                self.assertIsNone(receiver.process(b"STOP", writer)["label"])
                self.assertEqual(writer.db.execute("SELECT count(*) FROM events WHERE name='label_change'").fetchone()[0], 2)
            finally:
                receiver.close()

    def test_udp_ack_and_rejection(self):
        with tempfile.TemporaryDirectory() as tmp, DatasetWriter(Path(tmp)/"data", label="normal") as writer:
            receiver = LabelReceiver("127.0.0.1", 0, "normal")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(b"START", receiver.socket.getsockname())
                    with contextlib.redirect_stdout(io.StringIO()):
                        receiver.poll(writer)
                    self.assertTrue(json.loads(client.recv(4096))["ok"])
                    client.sendto(b"not JSON", receiver.socket.getsockname())
                    receiver.poll(writer)
                    self.assertFalse(json.loads(client.recv(4096))["ok"])
            finally:
                receiver.close()


class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_full_windows_counts_and_past_state(self):
        make_archive(self.root/"normal")
        rows = list(archive_windows(self.root/"normal"))
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(r["quality_ok"] for r in rows))
        self.assertEqual(rows[0]["features"]["packet_count"], 3)
        self.assertEqual(rows[0]["features"]["beacon_count"], 3)
        self.assertEqual(rows[0]["features"]["packets_per_second"], 30)
        self.assertEqual(rows[0]["features"]["heap"], 123000)  # not future 100ms state
        self.assertEqual(rows[0]["features"]["snr_mean"], 40)

    def test_unknown_empty_and_invalid(self):
        make_archive(self.root/"empty", label=None, empty=True)
        rows = list(archive_windows(self.root/"empty"))
        self.assertEqual(len(rows), 10)
        self.assertIsNone(rows[0]["label"])
        self.assertEqual(rows[0]["features"]["packet_count"], 0)
        self.assertIsNone(rows[0]["features"]["rssi_mean"])
        make_archive(self.root/"bad", bad=True)
        self.assertTrue(all(not r["quality_ok"] for r in archive_windows(self.root/"bad")))

    def test_loss_and_stale_flags(self):
        make_archive(self.root/"drop", drop=True)
        rows = list(archive_windows(self.root/"drop"))
        self.assertIn("drop_pool_count", rows[4]["quality_reasons"])
        make_archive(self.root/"stale", stale=True)
        rows = list(archive_windows(self.root/"stale", status_age_ms=50))
        self.assertTrue(any("status_gap" in r["quality_reasons"] for r in rows))

    def test_events_applied_and_boundaries_excluded(self):
        make_archive(self.root/"event")
        with contextlib.closing(sqlite3.connect(self.root/"event/dataset.sqlite3")) as db:
            db.execute("INSERT INTO events(host_time_ns,wire_offset,name,detail) VALUES(?,?,?,?)",
                       (1_500_000_000, 0, "label_change", json.dumps({"label": "deauth"})))
            db.commit()
        rows = list(archive_windows(self.root/"event", guard_ms=0))
        self.assertEqual(rows[2]["label"], "normal")
        self.assertIsNone(rows[4]["label"])
        self.assertIsNone(rows[5]["label"])
        self.assertEqual(rows[6]["label"], "deauth")

    def test_readonly_nonoverwrite_and_duplicate_session(self):
        import shutil
        make_archive(self.root/"normal")
        db = self.root/"normal/dataset.sqlite3"
        original = db.read_bytes()
        result = build_windows([self.root/"normal"], self.root/"features")
        self.assertEqual(result["counts"]["windows"], 10)
        self.assertEqual(db.read_bytes(), original)
        with self.assertRaises(FileExistsError):
            build_windows([self.root/"normal"], self.root/"features")
        shutil.copytree(self.root/"normal", self.root/"copy")
        with self.assertRaisesRegex(ValueError, "Duplicate session"):
            build_windows([self.root/"normal", self.root/"copy"], self.root/"dupe")

    def test_open_archive_refused(self):
        with DatasetWriter(self.root/"open"):
            with self.assertRaisesRegex(ValueError, "still open"):
                build_windows([self.root/"open"], self.root/"features")

    def test_sequence_gap_marks_spanned_windows(self):
        make_archive(self.root/"gap")
        with contextlib.closing(sqlite3.connect(self.root/"gap/dataset.sqlite3")) as db:
            db.execute("UPDATE packets SET packet_gap_before=2 WHERE packet_seq=12")
            db.commit()
        rows = list(archive_windows(self.root/"gap"))
        self.assertIn("sequence_gap", rows[3]["quality_reasons"])
        self.assertIn("sequence_gap", rows[4]["quality_reasons"])
        self.assertTrue(rows[5]["quality_ok"])

    def test_reboots_never_share_windows(self):
        make_archive(self.root/"boot")
        with contextlib.closing(sqlite3.connect(self.root/"boot/dataset.sqlite3")) as db:
            db.execute("UPDATE records SET boot_id='0000000000000002', device_us=device_us-500000 WHERE device_us>=500000")
            db.commit()
        rows = list(archive_windows(self.root/"boot"))
        self.assertEqual(len({r["boot_id"] for r in rows}), 2)
        self.assertEqual(len({(r["boot_id"], r["window_start_us"]) for r in rows}), len(rows))

    def test_label_clock_rollback_is_not_silently_accepted(self):
        make_archive(self.root/"clock")
        with contextlib.closing(sqlite3.connect(self.root/"clock/dataset.sqlite3")) as db:
            db.execute("UPDATE records SET host_arrival_ns=0 WHERE record_id=5")
            db.execute("INSERT INTO events(host_time_ns,wire_offset,name,detail) VALUES(?,?,?,?)",
                       (1_500_000_000, 0, "label_change", json.dumps({"label": "deauth"})))
            db.commit()
        rows = list(archive_windows(self.root/"clock", guard_ms=0))
        self.assertTrue(all(r["label"] is None and not r["quality_ok"] for r in rows))

    def test_checksum_tamper(self):
        make_archive(self.root/"normal")
        build_windows([self.root/"normal"], self.root/"features")
        with (self.root/"features/windows.jsonl").open("ab") as out:
            out.write(b" ")
        with self.assertRaises(ValueError):
            load_rows(self.root/"features")


@unittest.skipUnless(importlib.util.find_spec("sklearn"), "install requirements-raw.txt for training tests")
class TrainingTests(unittest.TestCase):
    def test_end_to_end_group_split_model_and_prediction(self):
        from host.train.predict_raw import main as predict
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = []
            for name, label in (("n1", "normal"), ("n2", "normal"), ("a1", "deauth"), ("a2", "deauth")):
                paths.append(root/name)
                make_archive(paths[-1], label)
            build_windows(paths, root/"windows")
            report = train(root/"windows", root/"model", feature_set="multimodal")
            self.assertFalse(set(report["train_sessions"]) & set(report["test_sessions"]))
            self.assertEqual(report["rows_used"], 40)
            self.assertTrue((root/"model/model.joblib").exists())
            self.assertEqual(predict(["--model", str(root/"model/model.joblib"), "--dataset", str(root/"windows"), "--out", str(root/"predictions.jsonl")]), 0)
            self.assertEqual(len((root/"predictions.jsonl").read_text().splitlines()), 40)
            with self.assertRaises(FileExistsError):
                train(root/"windows", root/"model")
            wireless = train(root/"windows", root/"wireless", model_kind="forest",
                             test_sessions=report["test_sessions"])
            self.assertEqual(wireless["test_sessions"], report["test_sessions"])
            with self.assertRaisesRegex(ValueError, "Unknown/empty"):
                train(root/"windows", root/"invalid", test_sessions=["missing-session"])

    def test_unknown_and_single_session_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_archive(root/"u", None)
            build_windows([root/"u"], root/"uw")
            with self.assertRaisesRegex(ValueError, "No labeled"):
                train(root/"uw", root/"um")
            make_archive(root/"n", "normal")
            make_archive(root/"a", "deauth")
            build_windows([root/"n", root/"a"], root/"w")
            with self.assertRaisesRegex(ValueError, "TWO independent"):
                train(root/"w", root/"m")


if __name__ == "__main__":
    unittest.main()

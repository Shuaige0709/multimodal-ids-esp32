"""Compile the firmware's portable C encoder and consume it with the real host."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from host.collector.raw_protocol import StreamParser
from host.collector.raw_dataset import DatasetWriter


class FirmwareInteropTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("gcc"), "native GCC is required for C/Python interop")
    def test_firmware_encoder_to_dataset(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "protocol_fixture.exe"
            subprocess.run([
                shutil.which("gcc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-static",
                "-I", str(root / "main"), str(root / "main/raw_capture_protocol.c"),
                str(root / "tests/raw_protocol_fixture.c"), "-o", str(binary),
            ], check=True, capture_output=True)
            wire = subprocess.run([str(binary)], check=True, capture_output=True).stdout
            parser = StreamParser()
            messages = []
            for start in range(0, len(wire), 13):
                messages.extend(parser.feed(wire[start:start + 13]))
            self.assertEqual(len(messages), 3)
            self.assertEqual(messages[2].boot_id, 0xf123456789abcdef)
            self.assertEqual(messages[1].fields["free_heap"], 81234)
            fields = messages[2].fields
            self.assertEqual(fields["rssi"], -57)
            self.assertEqual(fields["noise_floor"], -96)
            self.assertEqual(fields["rx_timestamp_us32"], 0xfffffff0)
            self.assertEqual(fields["stbc"], 2)
            self.assertEqual(fields["ampdu_cnt"], 9)
            self.assertEqual(fields["rx_ctrl_raw"], bytes([0xa5]) * 28)
            self.assertEqual(fields["payload"], bytes(i % 256 for i in range(4095)))
            with DatasetWriter(Path(tmp) / "dataset") as writer:
                writer.ingest(wire)
                row = writer.db.execute("SELECT * FROM packet_samples").fetchone()
                self.assertEqual(row["status_free_heap"], 81234)
                self.assertEqual(row["status_age_us"], 1234)
                self.assertEqual(row["status_valid"], 1)
                self.assertIsNone(row["label"])


if __name__ == "__main__":
    unittest.main()

import contextlib
from datetime import datetime
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.demo_dashboard import DashboardState, save_dashboard_snapshot
from scripts.recover_dashboard import recover


class RecoveryTests(unittest.TestCase):
    def test_replay_preserves_recorded_clock_and_skips_partial_tail(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'capture.csv.log'
            output = Path(folder) / 'recovered.json'
            source.write_text(
                '2026-11-18T01:00:00 I [NIDS_LINK] connected=1 channel=11\n'
                '2026-11-18T01:00:01 I [ARP_GUARD] mode=off action=watch repairs=0 err=0\n'
                '2026-11-18T01:00:02 W [ARP_GUARD_EVENT] mismatch=1 observed=AA:BB:CC:DD:EE:FF\n'
                '2026-11-18T01:00:03 [meta@45917 subtype="BEACON" rssi="-40" snr="40" '
                'ipat="100" seq="1" heap="170000" minheap="160000" uptime="3000" '
                'reconn="0" qpeak="1" udpfail="0" backlog="0" dropped="0" attack="1" m3src="4"]\n'
                '2026-11-18T01:00:04 [ARP_PROBE] target=192.168.0.1 result=timeout sent=1 received=0 repair=0\n'
                '2026-11-18T01:00:05 I [ARP_GUARD] mode=on action=locked', encoding='utf-8')
            original = source.read_bytes()
            result = recover(source, output)
            self.assertEqual(result['started'], '2026-11-18T01:00:00')
            self.assertEqual(result['events'][0]['start'], '2026-11-18T01:00:02')
            self.assertEqual(result['events'][0]['last'], '2026-11-18T01:00:03')
            self.assertEqual(result['protection']['mode'], 'off')
            self.assertEqual(result['export']['parsed_windows'], 1)
            self.assertEqual(result['export']['as_of'], '2026-11-18T01:00:04')
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['total'], 1)
            with self.assertRaises(FileExistsError):
                recover(source, output)

    def test_snapshot_does_not_clear_verification(self):
        state = DashboardState(clock=lambda: 100, wall_clock=lambda: datetime(2026, 11, 18, 1))
        state.transport(True)
        state.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        for i in (1,2,3):
            state.ingest(f'[ARP_PROBE] target=192.168.0.1 result=ok sent={i} received={i} repair=1')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'snapshot.json'
            save_dashboard_snapshot(state, path, {'recording_ended': True})
            self.assertEqual(state.snapshot()['protection']['communication'], 'reachable')
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['protection']['action'], 'locked')
            self.assertFalse(path.with_name(path.name + '.tmp').exists())

    @unittest.skipUnless(importlib.util.find_spec('serial'), 'Collector integration requires pyserial')
    def test_ctrl_c_saves_snapshot_before_closing_server(self):
        from scripts import serial_collector as collector
        serial_port = Mock()
        serial_port.readline.side_effect = [b'I [ARP_GUARD] mode=off action=watch repairs=0 err=0\n', KeyboardInterrupt]
        server = Mock()
        with tempfile.TemporaryDirectory() as folder:
            csv = Path(folder) / 'recording.csv'
            snapshot = Path(str(csv) + '.dashboard.json')
            def shutdown():
                self.assertTrue(snapshot.exists())
            server.shutdown.side_effect = shutdown
            with (patch.object(collector, 'open_serial', return_value=serial_port),
                  patch.object(collector, 'open_label_socket', return_value=Mock()),
                  patch.object(collector, 'drain_labels'),
                  patch('scripts.demo_dashboard.start_dashboard', return_value=server),
                  patch('sys.argv', ['collector', '--port', 'TEST', '--web', '--out', str(csv)]),
                  contextlib.redirect_stdout(io.StringIO())):
                collector.main()
            data = json.loads(snapshot.read_text(encoding='utf-8'))
            self.assertTrue(data['export']['recording_ended'])
            self.assertEqual(data['protection']['mode'], 'off')
            self.assertTrue(Path(str(csv) + '.log').exists())
            serial_port.close.assert_called_once()
            server.server_close.assert_called_once()


if __name__ == '__main__':
    unittest.main()

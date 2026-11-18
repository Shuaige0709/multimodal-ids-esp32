from datetime import datetime
from pathlib import Path
import tempfile
import unittest
from scripts.replay_demo_dashboard import ReplayState, log_segment


class ReplayTests(unittest.TestCase):
    def test_segment_excludes_unselected_time_and_partial_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'old.log'
            source.write_text('2026-11-18T11:00:00 a\n2026-11-18T11:00:01 b\n'
                              '2026-11-18T11:00:02 c\n2026-11-18T11:00:03 unfinished', encoding='utf-8')
            original = source.read_bytes()
            records = list(log_segment(source, datetime(2026, 11, 18, 11, 0, 1), 5))
            self.assertEqual([line for _, line in records], ['b', 'c'])
            self.assertEqual(source.read_bytes(), original)

    def test_history_is_marked_recorded_and_retains_actual_recovery(self):
        current = [100.0]
        state = ReplayState('old.csv.log', datetime(2026, 11, 18, 11), clock=lambda: current[0])
        state.transport(True)
        state.ingest('[NIDS_LINK] connected=1')
        current[0] += 1
        state.ingest('WiFi disconnected (reason=7)')
        current[0] += 1
        state.ingest('[NIDS_RECONNECT] attempt result=ESP_OK')
        current[0] += 2
        state.ingest('Got IP: 192.168.0.10')
        result = state.snapshot()
        self.assertEqual(result['connection']['outages'][0]['duration'], 3)
        self.assertEqual(result['presentation']['mode'], 'recorded')
        self.assertEqual(result['presentation']['source'], 'old.csv.log')
        state.finish()
        current[0] += 20
        self.assertTrue(state.snapshot()['presentation']['finished'])
        self.assertEqual(state.snapshot()['presentation']['time'], '2026-11-18T11:00:04')


if __name__ == '__main__':
    unittest.main()

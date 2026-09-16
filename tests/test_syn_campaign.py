"""No SSH, serial hardware, or traffic generator is executed by these tests."""
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import syn_campaign, serial_collector
from host.collector.raw_dataset import DatasetWriter
from host.train.raw_windows import archive_windows


class CampaignTests(unittest.TestCase):
    def test_remote_error_is_visible(self):
        a = SimpleNamespace(kali_user='hao', kali_host='192.168.56.101')
        result = SimpleNamespace(returncode=1, stderr='FileNotFoundError: scripts/raw_label.py', stdout='')
        with patch.object(syn_campaign.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'FileNotFoundError: scripts/raw_label.py'):
                syn_campaign.run_check(a, 'true', 'Kali project/files')

    def test_remote_arguments_quoted(self):
        a = SimpleNamespace(ssid="lab'; touch /tmp/oops", label_host='192.168.56.1')
        command = syn_campaign.remote_env(a, '192.168.0.2')
        self.assertIn('NIDS_REQUIRE_LABEL_ACK=1', command)
        self.assertIn("'\"'\"'", command)

    def test_fresh_state_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'live.json'
            process = Mock(); process.poll.return_value = None
            state = dict(active=True, updated_ns=time.time_ns(), hello_received_ns=0,
                         esp32_ip='192.168.0.2', statistics={'records': {'packets': 2}})
            path.write_text(json.dumps(state))
            self.assertIsNone(syn_campaign.read_live(path, process))
            state['hello_received_ns'] = time.time_ns()
            path.write_text(json.dumps(state))
            self.assertEqual(syn_campaign.read_live(path, process)['esp32_ip'], '192.168.0.2')

    def test_ip_disconnect_expiration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'live.json'
            args = SimpleNamespace(live_state=str(path), esp32_ip='192.168.0.99',
                port='mock', baud=921600, label_advertise=None, label_bind='127.0.0.1', label_port=9999)
            dataset = Mock(path=Path(directory), session_id='fixture',
                latest_hello={'ipv4': '192.168.0.2', 'connected': True},
                latest_hello_ns=time.time_ns(), latest_status={'connected': 1})
            dataset.statistics.return_value = {}
            serial_collector.publish_live(dataset, args)
            self.assertEqual(json.loads(path.read_text())['esp32_ip'], '192.168.0.2')
            dataset.latest_status = {'connected': 0}
            serial_collector.publish_live(dataset, args)
            self.assertIsNone(json.loads(path.read_text())['esp32_ip'])
            dataset.latest_status = {'connected': 1}; dataset.latest_hello_ns = 0
            serial_collector.publish_live(dataset, args)
            self.assertIsNone(json.loads(path.read_text())['esp32_ip'])

    def test_incomplete_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'capture'
            writer = DatasetWriter(path)
            writer.close('campaign_incomplete')
            with self.assertRaisesRegex(ValueError, 'Incomplete campaign'):
                list(archive_windows(path))

    def test_preflight_default_never_starts_collector(self):
        with patch.object(syn_campaign, 'preflight'), patch.object(syn_campaign.subprocess, 'Popen') as start:
            self.assertEqual(syn_campaign.main([]), 0)
            start.assert_not_called()

    def test_simulated_campaign_closes_without_kill(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = Mock(returncode=0); collector.poll.return_value = None
            remote = Mock(returncode=0); remote.poll.return_value = 0
            with patch.object(syn_campaign, 'ROOT', root), patch.object(syn_campaign, 'preflight'), \
                 patch.object(syn_campaign.subprocess, 'Popen', side_effect=[collector, remote]), \
                 patch.object(syn_campaign, 'read_live', return_value={'esp32_ip':'192.168.0.2'}), \
                 patch.object(syn_campaign, 'verify_events') as verify, patch.object(syn_campaign.time, 'sleep'):
                self.assertEqual(syn_campaign.main(['--run']), 0)
            verify.assert_called_once()
            collector.terminate.assert_not_called()
            self.assertEqual(next((root/'data').glob('*/stop')).read_text(), 'controller_stop')
            report = json.loads(next((root/'data').glob('*/campaign.json')).read_text())
            self.assertEqual(report['result'], 'completed')

    def test_simulated_failure_marks_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = Mock(returncode=0); collector.poll.return_value = None
            remote = Mock(returncode=1); remote.poll.return_value = 1
            with patch.object(syn_campaign, 'ROOT', root), patch.object(syn_campaign, 'preflight'), \
                 patch.object(syn_campaign.subprocess, 'Popen', side_effect=[collector, remote]), \
                 patch.object(syn_campaign, 'read_live', return_value={'esp32_ip':'192.168.0.2'}), \
                 patch.object(syn_campaign.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'Remote experiment failed'):
                    syn_campaign.main(['--run'])
            self.assertEqual(next((root/'data').glob('*/stop')).read_text(), 'campaign_incomplete')


if __name__ == '__main__':
    unittest.main()

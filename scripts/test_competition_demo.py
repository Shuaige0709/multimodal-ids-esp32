import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from host.attacks.competition_demo import ROOT, environment, load_profile, monitor_name, validate_live


class CompetitionDemoTests(unittest.TestCase):
    def setUp(self):
        self.c = load_profile(ROOT / 'demo/competition/network.json')
        self.d = {'serial': True, 'age': .1, 'wifi': 'up', 'wifi_fresh': True,
                  'latest': {'host_mac': self.c['esp32_mac'], 'channel': self.c['channel']},
                  'protection': {'fresh': True, 'mode': 'on', 'wireless_fresh': True,
                                 'wireless': {'binding': 'on', 'bssid': self.c['ap_bssid']},
                                 'device_ip': self.c['esp32_ip'], 'target': self.c['gateway_ip'],
                                 'communication': 'reachable', 'action': 'watch', 'repairs': 0}}

    def test_fixed_configuration_passes_and_routes_labels_only_to_windows(self):
        validate_live(self.d, self.c, require_unlocked=True)
        env = environment(self.c)
        self.assertEqual(env['NIDS_LABEL_PORT'], '10000')
        self.assertEqual(env['NIDS_LABEL_HOST'], env['NIDS_SERIAL_LABEL_HOST'])
        self.assertEqual(env['NIDS_DEAUTH_BATCHES'], '3')

    def test_replay_cannot_be_used_as_live_evidence(self):
        self.d['presentation'] = {'mode': 'recorded'}
        with self.assertRaisesRegex(ValueError, 'playback'):
            validate_live(self.d, self.c)

    def test_off_stale_wrong_target_and_link_down_are_rejected(self):
        for change in ('off', 'stale', 'target', 'down'):
            d = copy.deepcopy(self.d)
            if change == 'off': d['protection']['mode'] = 'off'
            if change == 'stale': d['age'] = 6
            if change == 'target': d['protection']['device_ip'] = '192.168.0.20'
            if change == 'down': d['wifi'] = 'down'
            with self.assertRaises(ValueError): validate_live(d, self.c)

    def test_old_lock_requires_restart_only_before_first_arp(self):
        self.d['protection'].update(action='locked', repairs=1)
        with self.assertRaisesRegex(ValueError, 'already repaired'):
            validate_live(self.d, self.c, require_unlocked=True)
        validate_live(self.d, self.c)

    def test_network_configuration_is_bounded(self):
        for key, value in [('esp32_ip', '8.8.8.8'), ('deauth_batches', 100), ('arp_seconds', 600), ('ap_bssid', 'FF:FF:FF:FF:FF:FF')]:
            c = {**self.c, key: value}
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'profile.json'
                path.write_text(json.dumps(c), encoding='utf-8')
                with self.assertRaises(ValueError): load_profile(path)

    def test_monitor_mode_can_keep_the_station_interface_name(self):
        self.assertEqual(monitor_name('phy#0\n Interface wlan0\n  type monitor\n', self.c), 'wlan0')
        self.assertEqual(monitor_name('phy#0\n Interface wlan0mon\n  type monitor\n', self.c), 'wlan0mon')
        with self.assertRaises(RuntimeError): monitor_name('Interface wlan0\n type managed\n', self.c)


if __name__ == '__main__':
    unittest.main()

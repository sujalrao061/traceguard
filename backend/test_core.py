import json
import unittest
from pathlib import Path
from backend.core import LabStore, validate_events, detect

class LabTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((Path(__file__).parent / 'fixtures.json').read_text())
        self.store = LabStore()

    def tearDown(self):
        self.store.close()

    def test_import_and_detect(self):
        self.assertEqual(self.store.replace(self.fixture), 162)
        self.assertEqual(len(detect(self.store.events())), 8)

    def test_sql_filter_and_injection(self):
        self.store.replace(self.fixture)
        self.assertEqual(len(self.store.events('demo-alex')), 11)
        self.assertEqual(self.store.events("' OR 1=1 --"), [])

    def test_invalid_import_is_atomic(self):
        self.store.replace(self.fixture)
        with self.assertRaises(ValueError):
            self.store.replace([{**self.fixture[0], 'password': 'secret'}])
        self.assertEqual(len(self.store.events()), 162)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            validate_events([self.fixture[0], self.fixture[0]])

    def test_real_data_rejected(self):
        for patch in [{'account': 'person@example.com'}, {'ip': '8.8.8.8'}, {'timestamp': '2026-02-31T00:00:00Z'}]:
            with self.assertRaises(ValueError):
                validate_events([{**self.fixture[0], **patch}])

    def test_disabled_rules(self):
        self.assertEqual(detect(self.fixture, []), [])

    def test_source_separation(self):
        failures = [e for e in self.fixture if e['type'] == 'login_failed'][:5]
        for i, e in enumerate(failures):
            e['ip'] = f'192.0.2.{i}'
        self.assertEqual(detect(failures), [])

    def test_clear(self):
        self.store.replace(self.fixture)
        self.store.clear()
        self.assertEqual(self.store.events(), [])

if __name__ == '__main__':
    unittest.main()

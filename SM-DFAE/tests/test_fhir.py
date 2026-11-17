"""FHIR input validation and statistics tests."""

import json
import tempfile
import unittest
from pathlib import Path

from smdfae.fhir import (
    discover_fhir_files, parse_fhir_bundle, read_fhir_record,
)


class FHIRTests(unittest.TestCase):
    def test_resource_counts(self):
        payload = json.dumps({'resourceType': 'Bundle', 'entry': [
            {'resource': {'resourceType': 'Patient'}},
            {'resource': {'resourceType': 'Observation'}},
            {'resource': {'resourceType': 'Observation'}},
        ]}).encode('utf-8')
        summary = parse_fhir_bundle(payload)
        self.assertEqual(summary.entry_count, 3)
        self.assertEqual(summary.count('Observation'), 2)
        self.assertEqual(summary.to_row()['observations'], 2)
        self.assertEqual(summary.size_bytes, len(payload))

    def test_invalid_documents(self):
        for payload in (b'[]', b'{}', b'not-json',
                        b'{"resourceType":"Bundle","entry":[{}]}'):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    parse_fhir_bundle(payload)

    def test_real_samples(self):
        directory = Path(__file__).resolve().parents[1] / 'data' / 'ehr'
        files = discover_fhir_files(directory)
        self.assertEqual(len(files), 4)
        self.assertEqual(len(set(p.name for p in files)), 4)
        for filename in files:
            data, summary = read_fhir_record(filename)
            self.assertEqual(summary.entry_count, sum(summary.resource_counts.values()))
            self.assertEqual(len(summary.sha256), 64)
            self.assertGreater(summary.count('Patient'), 0)
            self.assertGreater(len(data), 1000)

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                discover_fhir_files(directory)


if __name__ == '__main__':
    unittest.main()

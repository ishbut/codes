"""Tests for AES encryption and FHIR input handling."""

import os
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from smdfae.fhir import load_fhir_bundle
from smdfae.hybrid import derive_key, encrypt_payload, decrypt_payload


class HybridTests(unittest.TestCase):
    def test_aes_roundtrip(self):
        key = derive_key(os.urandom(64), os.urandom(16))
        word = ['0', '1', '0']
        data = b'{"resourceType":"Bundle","entry":[]}'
        payload = encrypt_payload(data, key, word)
        self.assertEqual(decrypt_payload(payload, key, word), data)

    def test_authentication(self):
        key = derive_key(os.urandom(64), os.urandom(16))
        payload = encrypt_payload(b'hello', key, ['0', '1'])
        with self.assertRaises(InvalidTag):
            decrypt_payload(payload, key, ['1', '0'])

    def test_fhir_samples(self):
        root = Path(__file__).resolve().parents[1]
        files = list((root / 'data' / 'ehr').glob('*.json'))
        self.assertEqual(len(files), 4)
        for path in files:
            content, counts = load_fhir_bundle(path)
            self.assertGreater(len(content), 0)
            self.assertGreater(sum(counts.values()), 0)


if __name__ == '__main__':
    unittest.main()

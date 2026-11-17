"""FHIR Bundle ingestion, validation, and metadata for EHR workloads."""

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FHIRSummary:
    filename: str
    size_bytes: int
    sha256: str
    resource_counts: Counter
    entry_count: int

    @property
    def size_kb(self):
        return self.size_bytes / 1024.0

    def count(self, resource_type):
        return self.resource_counts.get(resource_type, 0)

    def to_row(self):
        return {
            'ehr_kb': round(self.size_kb, 2),
            'resources': self.entry_count,
            'observations': self.count('Observation'),
            'encounters': self.count('Encounter'),
            'conditions': self.count('Condition'),
            'medications': (self.count('Medication')
                            + self.count('MedicationRequest')
                            + self.count('MedicationStatement')),
            'diagnostic_reports': self.count('DiagnosticReport'),
        }


def parse_fhir_bundle(raw, filename='<memory>'):
    """Inspect an input Bundle without rewriting any plaintext bytes."""
    if not isinstance(raw, bytes):
        raise TypeError('FHIR payload must be bytes')
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid FHIR JSON: {}'.format(filename)) from exc
    if not isinstance(document, dict) or document.get('resourceType') != 'Bundle':
        raise ValueError('Expected a FHIR Bundle: {}'.format(filename))
    entries = document.get('entry')
    if not isinstance(entries, list):
        raise ValueError('FHIR Bundle entry must be a list: {}'.format(filename))
    counts = Counter()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('resource'), dict):
            raise ValueError('Malformed FHIR Bundle entry: {}'.format(filename))
        kind = entry['resource'].get('resourceType')
        if not isinstance(kind, str) or not kind:
            raise ValueError('FHIR resourceType is missing: {}'.format(filename))
        counts[kind] += 1
    return FHIRSummary(
        filename=str(filename),
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        resource_counts=counts,
        entry_count=len(entries),
    )


def read_fhir_record(path):
    """Return the unchanged input bytes and their metadata."""
    path = Path(path)
    raw = path.read_bytes()
    return raw, parse_fhir_bundle(raw, path.name)


def load_fhir_bundle(path):
    """Compatibility helper: return raw bytes and resource counts."""
    raw, summary = read_fhir_record(path)
    return raw, summary.resource_counts


def discover_fhir_files(directory):
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError('FHIR directory not found: {}'.format(directory))
    files = sorted(directory.glob('*.json'))
    if not files:
        raise FileNotFoundError('No FHIR JSON files in {}'.format(directory))
    return files

"""Scenario-driven SM-DFAE experiment with Synthea FHIR records.

The four measurements follow the EHR case study:
(a) user authorization, (b) data publishing, (c) ciphertext sanitization,
(d) authorized data access. AES-256-GCM encrypts the original JSON bytes;
SM-DFAE protects the randomly selected GT session secret.
"""

import argparse
from pathlib import Path

from experiments.metrics import aggregate_results, timed_call
from experiments.reporting import print_table, save_csv
from smdfae.fhir import discover_fhir_files, read_fhir_record
from smdfae.hybrid import decrypt_ehr, encrypt_ehr, sanitize_ehr
from smdfae.workflow import EVENT_ALPHABET, make_authority_policies, make_clinical_workflow


DEFAULT_N_VALUES = (2, 4, 6, 8, 10, 12, 14, 16)
DEFAULT_LENGTH_VALUES = (5, 10, 15, 20, 25, 30, 35, 40)
TIMING_FIELDS = (
    'setup_ms', 'center_keygen_ms', 'authority_keygen_ms',
    'publishing_ms', 'checking_ms', 'sanitization_ms', 'access_ms',
)


class EHRSharingSession:
    """Run the EHR sharing protocol for one user and a set of authorities."""

    def __init__(self, group, authority_count, access_length, uid='researcher-01'):
        if authority_count < 1 or access_length < 1:
            raise ValueError('Authority count and access length must be positive')
        self.group = group
        self.authority_count = authority_count
        self.uid = uid
        self.word = make_clinical_workflow(access_length)
        self.policies = make_authority_policies(self.word, authority_count)

    def execute(self, ehr_bytes):
        """Execute setup, multi-authority authorization and a full EHR roundtrip."""
        from smdfae.scheme import SMDFAE

        scheme = SMDFAE(self.group)
        setup_ms, (public_key, center_master, authority_masters) = timed_call(
            lambda: scheme.setup(EVENT_ALPHABET, self.authority_count))
        center_ms, center_key = timed_call(
            lambda: scheme.center_keygen(
                public_key, center_master, authority_masters, self.uid))

        def issue_authority_keys():
            return [scheme.authority_keygen(public_key, eta, dfa, self.uid)
                    for eta, dfa in zip(authority_masters, self.policies)]

        authority_ms, authority_keys = timed_call(issue_authority_keys)
        publishing_ms, envelope = timed_call(
            lambda: encrypt_ehr(self.group, scheme, public_key,
                                self.word, ehr_bytes))

        checking_ms, valid = timed_call(
            lambda: scheme.check(public_key, envelope['wrapped_key']))
        if not valid:
            raise ValueError('Ciphertext checking failed before sanitization')

        sanitization_ms, sanitized = timed_call(
            lambda: sanitize_ehr(scheme, public_key, envelope))
        if (sanitized['ciphertext'] != envelope['ciphertext'] or
                sanitized['nonce'] != envelope['nonce']):
            raise AssertionError('Sanitization unexpectedly changed the AES payload')
        if not scheme.check(public_key, sanitized['wrapped_key']):
            raise ValueError('Sanitized ciphertext failed validation')

        access_ms, recovered = timed_call(
            lambda: decrypt_ehr(self.group, scheme, public_key, center_key,
                                authority_keys, sanitized))
        if recovered != ehr_bytes:
            raise AssertionError('Decrypted EHR bytes do not match the source')
        return {
            'setup_ms': setup_ms,
            'center_keygen_ms': center_ms,
            'authority_keygen_ms': authority_ms,
            'publishing_ms': publishing_ms,
            'checking_ms': checking_ms,
            'sanitization_ms': sanitization_ms,
            'access_ms': access_ms,
            'ciphertext_bytes': len(sanitized['ciphertext']),
            'verified': True,
        }


def repeat_scenario(group, ehr_bytes, authority_count, access_length, repeats):
    """Use fresh key material and fresh AES nonces for each repetition."""
    if repeats < 1:
        raise ValueError('Repeat count must be positive')
    measurements = []
    for _ in range(repeats):
        session = EHRSharingSession(group, authority_count, access_length)
        measurements.append(session.execute(ehr_bytes))
    averages = aggregate_results(measurements, TIMING_FIELDS)
    averages['ciphertext_bytes'] = measurements[-1]['ciphertext_bytes']
    averages['verified'] = all(item['verified'] for item in measurements)
    return averages


def benchmark_records(group, records, authority_count, access_length, repeats):
    """Compare the publishing costs of the four original FHIR documents."""
    profiles = []
    for index, (_, _, summary) in enumerate(records, 1):
        profiles.append({'sample': 'EHR-{:02d}'.format(index),
                         **summary.to_row()})
    print_table('Synthea FHIR dataset profile', profiles, [
        ('sample', 'Sample', 8, ''),
        ('ehr_kb', 'Size(KB)', 10, '.1f'),
        ('resources', 'Resources', 10, ''),
        ('observations', 'Observations', 13, ''),
        ('encounters', 'Encounters', 12, ''),
        ('conditions', 'Conditions', 12, ''),
        ('medications', 'Medications', 13, ''),
    ])

    rows = []
    for index, (path, ehr_bytes, summary) in enumerate(records, 1):
        result = repeat_scenario(
            group, ehr_bytes, authority_count, access_length, repeats)
        row = {
            'sample': 'EHR-{:02d}'.format(index),
            'filename': path.name,
            **summary.to_row(),
            'authorities': authority_count,
            'access_length': access_length,
            **result,
        }
        rows.append(row)
    print_table('EHR data publishing and authorized access', rows, [
        ('sample', 'Sample', 8, ''),
        ('ehr_kb', 'Size(KB)', 10, '.1f'),
        ('resources', 'Resources', 10, ''),
        ('publishing_ms', 'Publish(ms)', 12, '.3f'),
        ('sanitization_ms', 'Sanitize(ms)', 13, '.3f'),
        ('access_ms', 'Access(ms)', 12, '.3f'),
        ('verified', 'Correct', 9, ''),
    ])
    return rows


def benchmark_authority_scaling(group, representative_ehr, n_values,
                                access_length, repeats):
    """Measure user registration and decryption against authority count."""
    rows = []
    for n in n_values:
        measurements = repeat_scenario(
            group, representative_ehr, n, access_length, repeats)
        row = {
            'experiment': 'authority_scaling',
            'variable': 'N',
            'value': n,
            'setup_ms': measurements['setup_ms'],
            'center_keygen_ms': measurements['center_keygen_ms'],
            'authority_keygen_ms': measurements['authority_keygen_ms'],
            'total_authorization_ms': round(
                measurements['setup_ms']
                + measurements['center_keygen_ms']
                + measurements['authority_keygen_ms'], 3),
            'checking_ms': measurements['checking_ms'],
            'sanitization_ms': measurements['sanitization_ms'],
            'access_ms': measurements['access_ms'],
            'verified': measurements['verified'],
        }
        rows.append(row)
    print_table('User authorization and access vs. authority count', rows, [
        ('value', 'N', 5, ''),
        ('setup_ms', 'Setup', 10, '.3f'),
        ('center_keygen_ms', 'CenterKG', 11, '.3f'),
        ('authority_keygen_ms', 'AuthorityKG', 13, '.3f'),
        ('total_authorization_ms', 'Total(ms)', 12, '.3f'),
        ('access_ms', 'Access(ms)', 12, '.3f'),
    ])
    return rows


def benchmark_length_scaling(group, representative_ehr, authority_count,
                             length_values, repeats):
    """Measure ciphertext checking and sanitization against string length."""
    rows = []
    for ell in length_values:
        measurements = repeat_scenario(
            group, representative_ehr, authority_count, ell, repeats)
        row = {
            'experiment': 'length_scaling',
            'variable': 'ell',
            'value': ell,
            'setup_ms': measurements['setup_ms'],
            'center_keygen_ms': measurements['center_keygen_ms'],
            'authority_keygen_ms': measurements['authority_keygen_ms'],
            'total_authorization_ms': round(
                measurements['setup_ms']
                + measurements['center_keygen_ms']
                + measurements['authority_keygen_ms'], 3),
            'checking_ms': measurements['checking_ms'],
            'sanitization_ms': measurements['sanitization_ms'],
            'access_ms': measurements['access_ms'],
            'verified': measurements['verified'],
        }
        rows.append(row)
    print_table('Ciphertext checking and sanitization vs. access length', rows, [
        ('value', 'ell', 6, ''),
        ('checking_ms', 'Check(ms)', 13, '.3f'),
        ('sanitization_ms', 'Sanitize(ms)', 14, '.3f'),
        ('access_ms', 'Access(ms)', 12, '.3f'),
    ])
    return rows


def parse_positive_integers(value):
    """Parse a comma-separated parameter sweep such as 2,4,6,8."""
    try:
        values = [int(item.strip()) for item in value.split(',')]
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Enter comma-separated integers') from exc
    if not values or any(number < 1 for number in values):
        raise argparse.ArgumentTypeError('Every value must be positive')
    if len(set(values)) != len(values):
        raise argparse.ArgumentTypeError('Values must not repeat')
    return values


def build_parser():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description='SM-DFAE EHR sharing: multi-authority and hybrid encryption experiments')
    parser.add_argument('--mode', choices=['records', 'scaling', 'all'],
                        default='records')
    parser.add_argument('--input-dir', default=str(root / 'data' / 'ehr'))
    parser.add_argument('--authorities', type=int, default=4)
    parser.add_argument('--length', type=int, default=7)
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--n-values', type=parse_positive_integers,
                        default=list(DEFAULT_N_VALUES))
    parser.add_argument('--length-values', type=parse_positive_integers,
                        default=list(DEFAULT_LENGTH_VALUES))
    parser.add_argument('--curve', default='SS512')
    parser.add_argument('--csv', default='results/ehr_sharing.csv')
    parser.add_argument('--scaling-csv', default='results/ehr_scaling.csv')
    return parser


def run(args):
    # Keep Charm initialization local so argument parsing and dataset checks
    # work independently of the pairing backend.
    from charm.toolbox.pairinggroup import PairingGroup

    if min(args.authorities, args.length, args.iterations) < 1:
        raise ValueError('--authorities, --length, --iterations must be positive')
    filenames = discover_fhir_files(args.input_dir)
    records = [(path, *read_fhir_record(path)) for path in filenames]
    group = PairingGroup(args.curve)
    print('SM-DFAE / AES-256-GCM EHR sharing experiment')
    print('FHIR records: {} | authorities: {} | length: {} | repetitions: {}'.format(
        len(records), args.authorities, args.length, args.iterations))

    if args.mode in ('records', 'all'):
        rows = benchmark_records(group, records, args.authorities,
                                 args.length, args.iterations)
        save_csv(args.csv, rows)

    if args.mode in ('scaling', 'all'):
        # The smallest EHR is sufficient for fixed-size parameter sweeps.
        _, representative, _ = min(records, key=lambda item: len(item[1]))
        n_rows = benchmark_authority_scaling(
            group, representative, args.n_values, args.length, args.iterations)
        ell_rows = benchmark_length_scaling(
            group, representative, args.authorities,
            args.length_values, args.iterations)
        save_csv(args.scaling_csv, n_rows + ell_rows)


def main():
    parser = build_parser()
    args = parser.parse_args()
    if min(args.authorities, args.length, args.iterations) < 1:
        parser.error('--authorities, --length, --iterations must be positive')
    run(args)


if __name__ == '__main__':
    main()

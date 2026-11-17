"""Experiment argument and measurement helper tests."""

import argparse
import unittest

from experiments.ehr_sharing import build_parser, parse_positive_integers
from experiments.metrics import aggregate_results, average_measurement


class ExperimentTests(unittest.TestCase):
    def test_sweep_arguments(self):
        self.assertEqual(parse_positive_integers('2,4,8'), [2, 4, 8])
        for bad in ('0,1', '2,2', '', 'abc'):
            with self.assertRaises(argparse.ArgumentTypeError):
                parse_positive_integers(bad)

    def test_parser(self):
        args = build_parser().parse_args(['--mode', 'all', '--iterations', '2'])
        self.assertEqual(args.mode, 'all')
        self.assertEqual(args.iterations, 2)
        self.assertEqual(len(args.n_values), 8)

    def test_metrics(self):
        ms, value = average_measurement(lambda: 'ok', 2)
        self.assertGreaterEqual(ms, 0)
        self.assertEqual(value, 'ok')
        summary = aggregate_results([{'x': 1.0}, {'x': 3.0}], ['x'])
        self.assertEqual(summary['x'], 2)


if __name__ == '__main__':
    unittest.main()

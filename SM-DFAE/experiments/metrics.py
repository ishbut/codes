"""Timing and aggregation helpers for the EHR case study."""

import statistics
import time


def timed_call(fn):
    start = time.perf_counter()
    result = fn()
    return (time.perf_counter() - start) * 1000.0, result


def average_measurement(fn, repeats):
    if repeats < 1:
        raise ValueError('Repeat count must be positive')
    samples = []
    last = None
    for _ in range(repeats):
        elapsed, last = timed_call(fn)
        samples.append(elapsed)
    return statistics.mean(samples), last


def aggregate_results(rows, fields):
    if not rows:
        raise ValueError('Cannot aggregate an empty result set')
    return {field: round(statistics.mean(row[field] for row in rows), 3)
            for field in fields}

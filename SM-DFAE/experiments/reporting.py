"""Tabular console output and CSV export for experiment results."""

import csv
from pathlib import Path


def save_csv(path, rows):
    if not rows or not path:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print('Results saved to {}'.format(destination))


def print_table(title, rows, columns):
    """Columns contain (field_name, label, width, format_spec)."""
    print('\n' + title)
    print('-' * (sum(width for _, _, width, _ in columns) + len(columns) - 1))
    print(' '.join('{:>{width}}'.format(label, width=width)
                   for _, label, width, _ in columns))
    for row in rows:
        cells = []
        for field, _, width, spec in columns:
            value = row[field]
            value = format(value, spec) if spec else str(value)
            cells.append('{:>{width}}'.format(value, width=width))
        print(' '.join(cells))

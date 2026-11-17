# SM-DFAE

Python implementation of **Sanitizable Multi-Authority DFA-Based Encryption (SM-DFAE)** for electronic health record (EHR) sharing.

The repository includes multi-authority DFA access control, ciphertext sanitization, AES-256-GCM hybrid encryption, and experiments on four Synthea FHIR JSON records.

## Structure

- `smdfae/` — SM-DFAE scheme, DFA policies, clinical workflows, FHIR processing, and AES-GCM
- `experiments/` — EHR sharing experiments, timing, and CSV reporting
- `data/ehr/` — four synthetic FHIR patient records
- `examples/` — basic usage examples
- `tests/` — unit tests

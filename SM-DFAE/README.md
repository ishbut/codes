# SM-DFAE

Python implementation of **Sanitizable Multi-Authority DFA-Based Encryption (SM-DFAE)** for electronic health record (EHR) sharing.

SM-DFAE combines multi-authority access control with DFA-based access policies. Each authority independently defines its own DFA policy and issues user keys bound to a common identity. An EHR ciphertext can be decrypted only when all required DFA policies accept the associated access string. Identity binding prevents collusion among keys issued to different users. The scheme also supports ciphertext sanitization while preserving policy-based access control.

## Structure

```text
SM-DFAE/
├── smdfae/
├── experiments/
├── examples/
├── data/
└── tests/
```

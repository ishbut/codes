"""AES-256-GCM payload encryption with a pairing-group KEM secret.

The SM-DFAE scheme encrypts a random GT element, not the EHR JSON itself.
HKDF derives a 256-bit AES key from the serialized GT element, and AES-GCM
protects the complete original FHIR JSON bytes with authenticated encryption.
"""

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_KEY_INFO = b'SM-DFAE-EHR-hybrid-v1'


def _associated_data(access_string):
    return json.dumps([str(x) for x in access_string],
                      separators=(',', ':'), ensure_ascii=True).encode('ascii')


def derive_key(gt_serialized, salt):
    """Derive a 256-bit AES key from a serialized GT element."""
    return HKDF(algorithm=SHA256(), length=32, salt=salt,
                info=_KEY_INFO).derive(gt_serialized)


def encrypt_payload(plaintext, key, access_string):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, plaintext, _associated_data(access_string)
    )
    return {'nonce': nonce, 'ciphertext': ciphertext}


def decrypt_payload(payload, key, access_string):
    return AESGCM(key).decrypt(
        payload['nonce'], payload['ciphertext'],
        _associated_data(access_string)
    )


def encrypt_ehr(group, scheme, public_key, access_string, ehr_bytes):
    """Encrypt a FHIR file with AES; protect its session material with SM-DFAE."""
    from charm.toolbox.pairinggroup import GT

    session_secret = group.random(GT)
    salt = os.urandom(16)
    aes_key = derive_key(group.serialize(session_secret), salt)
    payload = encrypt_payload(ehr_bytes, aes_key, access_string)
    return {
        'wrapped_key': scheme.encrypt(public_key, access_string, session_secret),
        'salt': salt,
        'nonce': payload['nonce'],
        'ciphertext': payload['ciphertext'],
    }


def sanitize_ehr(scheme, public_key, envelope):
    """Check and sanitize KEM ciphertext; AES ciphertext stays unchanged."""
    cleaned = dict(envelope)
    cleaned['wrapped_key'] = scheme.sanitize(
        public_key, envelope['wrapped_key'])
    return cleaned


def decrypt_ehr(group, scheme, public_key, center_key, authority_keys, envelope):
    kem_ct = envelope['wrapped_key']
    secret = scheme.decrypt(public_key, center_key, authority_keys, kem_ct)
    if secret is None:
        raise PermissionError('At least one DFA policy rejected the access string')
    aes_key = derive_key(group.serialize(secret), envelope['salt'])
    return decrypt_payload(envelope, aes_key, kem_ct['w'])

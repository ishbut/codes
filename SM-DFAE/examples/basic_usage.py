"""Minimal authorized SM-DFAE example."""

from charm.toolbox.pairinggroup import GT, PairingGroup
from smdfae.dfa import make_equality_dfa, make_prefix_dfa, make_workflow
from smdfae.scheme import SMDFAE


def main():
    group = PairingGroup('SS512')
    scheme = SMDFAE(group)
    word = make_workflow(7)
    uid = 'example-user'
    pk, mskc, authority_secrets = scheme.setup(['0', '1'], 2)
    center_key = scheme.center_keygen(pk, mskc, authority_secrets, uid)
    # Independent DFA policies accept the same ciphertext access string.
    policies = [make_equality_dfa(word), make_prefix_dfa(word[:3], ['0', '1'])]
    keys = [scheme.authority_keygen(pk, eta, policy, uid)
            for eta, policy in zip(authority_secrets, policies)]
    message = group.random(GT)
    original = scheme.encrypt(pk, word, message)
    sanitized = scheme.sanitize(pk, original)
    recovered = scheme.decrypt(pk, center_key, keys, sanitized)
    assert recovered == message
    print('Sanitized ciphertext decrypted successfully')


if __name__ == '__main__':
    main()

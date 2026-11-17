"""SM-DFAE construction (Section VI)."""

from charm.toolbox.pairinggroup import G1, GT, ZR, pair


class SMDFAE:
    """Multi-authority DFA access control with ciphertext sanitization.

    API names mirror the six algorithms in the manuscript:
    setup, center_keygen (CKeyGen), authority_keygen (KeyGen),
    encrypt, sanitize, and decrypt. A separate `check` method performs
    the public validity checks used at the beginning of sanitization.
    """

    def __init__(self, group):
        self.group = group

    def _identity_value(self, eta, uid):
        # Hash-to-field mapping for F_eta(UID).
        # Domain separation avoids ambiguity in concatenated values.
        return self.group.hash('SM-DFAE|{}|{}'.format(eta, uid), ZR)

    def setup(self, alphabet, num_authorities):
        if num_authorities < 1:
            raise ValueError('At least one authority is required')
        symbols = [str(s) for s in alphabet]
        if not symbols or len(set(symbols)) != len(symbols):
            raise ValueError('Alphabet must contain distinct symbols')
        g = self.group.random(G1)
        alpha = self.group.random(ZR)
        pk = {
            'g': g,
            'z': self.group.random(G1),
            'h_start': self.group.random(G1),
            'h_end': self.group.random(G1),
            'h': {symbol: self.group.random(G1) for symbol in symbols},
            'egg_alpha': pair(g, g) ** alpha,
        }
        msk_center = g ** alpha
        msk_authorities = [self.group.random(ZR)
                           for _ in range(num_authorities)]
        return pk, msk_center, msk_authorities

    def center_keygen(self, pk, msk_center, msk_authorities, uid):
        total = self.group.init(ZR, 0)
        for eta in msk_authorities:
            total += self._identity_value(eta, uid)
        return msk_center / (pk['g'] ** total)

    def authority_keygen(self, pk, eta, dfa, uid):
        identity_value = self._identity_value(eta, uid)
        state_blinds = {state: self.group.random(G1) for state in dfa.Q}

        r0 = self.group.random(ZR)
        k0 = (
            state_blinds[dfa.q0] * (pk['h_start'] ** r0),
            pk['g'] ** r0,
        )
        k_trans = {}
        for transition in dfa.T:
            source, target, symbol = transition
            rt = self.group.random(ZR)
            k_trans[transition] = (
                (state_blinds[source] ** -1) * (pk['z'] ** rt),
                pk['g'] ** rt,
                state_blinds[target] * (pk['h'][str(symbol)] ** rt),
            )
        k_accept = {}
        for final_state in dfa.F:
            rf = self.group.random(ZR)
            k_accept[final_state] = (
                (pk['g'] ** (-identity_value)) * state_blinds[final_state]
                * (pk['h_end'] ** rf),
                pk['g'] ** rf,
            )
        return {'dfa': dfa, 'k0': k0,
                'k_trans': k_trans, 'k_accept': k_accept}

    def encrypt(self, pk, access_string, message):
        w = [str(symbol) for symbol in access_string]
        if not w:
            raise ValueError('Access string must be nonempty')
        if any(symbol not in pk['h'] for symbol in w):
            raise ValueError('Access string contains a symbol outside the alphabet')
        ell = len(w)
        secrets = [self.group.random(ZR) for _ in range(ell + 1)]
        path = []
        for i, symbol in enumerate(w, 1):
            path.append((
                pk['g'] ** secrets[i],
                (pk['h'][symbol] ** secrets[i]) * (pk['z'] ** secrets[i - 1]),
            ))
        return {
            'w': w,
            'cm': message * (pk['egg_alpha'] ** secrets[-1]),
            'c0': (pk['g'] ** secrets[0], pk['h_start'] ** secrets[0]),
            'path': path,
            'c_end': (pk['g'] ** secrets[-1], pk['h_end'] ** secrets[-1]),
        }

    def check(self, pk, ct):
        try:
            w = ct['w']
            path = ct['path']
            if len(w) == 0 or len(w) != len(path):
                return False
            if any(str(symbol) not in pk['h'] for symbol in w):
                return False
            c0_1, c0_2 = ct['c0']
            if pair(c0_2, pk['g']) != pair(pk['h_start'], c0_1):
                return False
            if ct['c_end'][0] != path[-1][0]:
                return False
            prev = c0_1
            for i, symbol in enumerate(w):
                ci_1, ci_2 = path[i]
                if (pair(ci_2, pk['g']) !=
                        pair(pk['h'][str(symbol)], ci_1) * pair(pk['z'], prev)):
                    return False
                prev = ci_1
            return (pair(ct['c_end'][1], pk['g']) ==
                    pair(pk['h_end'], ct['c_end'][0]))
        except (KeyError, IndexError, TypeError, ValueError):
            return False

    def sanitize(self, pk, ciphertext):
        """Reject invalid ciphertext and rerandomize every path component."""
        if not self.check(pk, ciphertext):
            raise ValueError('Ciphertext validation failed')
        w = ciphertext['w']
        ell = len(w)
        delta = [self.group.random(ZR) for _ in range(ell + 1)]
        c0 = (
            ciphertext['c0'][0] * (pk['g'] ** delta[0]),
            ciphertext['c0'][1] * (pk['h_start'] ** delta[0]),
        )
        path = []
        for i, symbol in enumerate(w, 1):
            ci_1, ci_2 = ciphertext['path'][i - 1]
            path.append((
                ci_1 * (pk['g'] ** delta[i]),
                ci_2 * (pk['h'][str(symbol)] ** delta[i])
                * (pk['z'] ** delta[i - 1]),
            ))
        return {
            'w': list(w),
            'cm': ciphertext['cm'] * (pk['egg_alpha'] ** delta[-1]),
            'c0': c0,
            'path': path,
            'c_end': (path[-1][0],
                      ciphertext['c_end'][1] * (pk['h_end'] ** delta[-1])),
        }

    def decrypt(self, pk, sk_center, sk_authorities, ciphertext):
        if not sk_authorities:
            raise ValueError('At least one authority key is required')
        shares = self.group.init(GT, 1)
        for authority_key in sk_authorities:
            dfa = authority_key['dfa']
            if not dfa.accept(ciphertext['w']):
                return None
            path, states = dfa.get_transitions(ciphertext['w'])
            aggregate = (
                pair(ciphertext['c0'][0], authority_key['k0'][0]) /
                pair(ciphertext['c0'][1], authority_key['k0'][1])
            )
            for i, transition in enumerate(path, 1):
                kt1, kt2, kt3 = authority_key['k_trans'][transition]
                prev = (ciphertext['c0'][0] if i == 1
                        else ciphertext['path'][i - 2][0])
                ci1, ci2 = ciphertext['path'][i - 1]
                aggregate *= (pair(prev, kt1) * (pair(ci2, kt2) ** -1)
                              * pair(ci1, kt3))
            kf1, kf2 = authority_key['k_accept'][states[-1]]
            aggregate *= (pair(ciphertext['c_end'][0], kf1) ** -1)
            aggregate *= pair(ciphertext['c_end'][1], kf2)
            shares *= aggregate
        mask = pair(sk_center, ciphertext['c_end'][0]) * shares
        return ciphertext['cm'] / mask

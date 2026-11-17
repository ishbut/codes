"""DFA representation and policies for access strings."""

class DFAUtils:
    def __init__(self, states, transitions, start_state, accept_states):
        self.Q = states
        # Normalize transition symbols so path tuples match key-table entries.
        self.T = [(u, v, str(symbol)) for u, v, symbol in transitions]
        self.q0 = start_state
        self.F = accept_states
        self._transition_map = {(u, str(sigma)): v for (u, v, sigma) in self.T}
        self._edge_map = {(u, str(sigma)): (u, v, str(sigma)) for (u, v, sigma) in self.T}

    def accept(self, w):
        current = self.q0
        for char in w:
            current = self._transition_map.get((current, str(char)))
            if current is None:
                return False
        return current in self.F

    def get_transitions(self, w):
        path = []
        states = [self.q0]
        current = self.q0
        for char in w:
            edge = self._edge_map.get((current, str(char)))
            if edge is None:
                raise ValueError("The given string is not accepted by this DFA.")
            path.append(edge)
            current = edge[1]
            states.append(current)
        return path, states


def make_workflow(ell):
    return ["0" if i % 2 == 0 else "1" for i in range(ell)]


def make_equality_dfa(w):
    states = [f"q{i}" for i in range(len(w) + 1)]
    transitions = [(f"q{i}", f"q{i + 1}", w[i]) for i in range(len(w))]
    return DFAUtils(states, transitions, "q0", {f"q{len(w)}"})


def make_prefix_dfa(prefix, alphabet):
    """Accept strings beginning with `prefix`, including longer strings."""
    prefix = [str(x) for x in prefix]
    alphabet = [str(x) for x in alphabet]
    if not prefix or not alphabet or any(x not in alphabet for x in prefix):
        raise ValueError("Prefix must be nonempty and use the supplied alphabet")
    states = ["p{}".format(i) for i in range(len(prefix) + 1)]
    transitions = [
        (states[i], states[i + 1], symbol)
        for i, symbol in enumerate(prefix)
    ]
    transitions += [(states[-1], states[-1], symbol) for symbol in alphabet]
    return DFAUtils(states, transitions, states[0], {states[-1]})

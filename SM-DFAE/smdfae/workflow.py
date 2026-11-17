"""Clinical workflow strings and DFA policies for EHR sharing."""

from smdfae.dfa import DFAUtils, make_equality_dfa, make_prefix_dfa


EVENT_ALPHABET = (
    'outpatient',
    'diagnosis',
    'medication',
    'follow_up',
    'anonymized',
    'requester_verified',
    'project_approved',
)


def make_clinical_workflow(length=7):
    """Construct an event sequence using the workflow of the EHR case study."""
    if length < 1:
        raise ValueError('Workflow length must be positive')
    return [EVENT_ALPHABET[index % len(EVENT_ALPHABET)]
            for index in range(length)]


def make_subsequence_dfa(required_events, alphabet=EVENT_ALPHABET):
    """Accept words containing the required events in the given order.

    Other events may appear before, between, or after the required events.
    """
    required = [str(event) for event in required_events]
    alphabet = [str(event) for event in alphabet]
    if not required or len(set(alphabet)) != len(alphabet):
        raise ValueError('Required events must be nonempty and alphabet distinct')
    if any(event not in alphabet for event in required):
        raise ValueError('Required events must belong to the alphabet')

    states = ['s{}'.format(i) for i in range(len(required) + 1)]
    transitions = []
    for index, symbol in enumerate(required):
        for event in alphabet:
            next_state = states[index + 1] if event == symbol else states[index]
            transitions.append((states[index], next_state, event))
    transitions.extend((states[-1], states[-1], event) for event in alphabet)
    return DFAUtils(states, transitions, states[0], {states[-1]})


def make_authority_policies(word, count):
    """Create independent DFA policies that accept the reference workflow.

    Policies represent exact clinical workflow, clinical entry, de-identification,
    and research approval. Additional authorities use progressively longer
    prefix constraints. The same encrypted word must satisfy every policy.
    """
    if count < 1 or not word:
        raise ValueError('Authority count and access string must be positive')
    word = list(map(str, word))
    if any(event not in EVENT_ALPHABET for event in word):
        raise ValueError('Unknown workflow event')

    policies = [make_equality_dfa(word)]
    if count >= 2:
        policies.append(make_prefix_dfa(word[:min(2, len(word))], EVENT_ALPHABET))
    if count >= 3:
        required = [word[0], word[-1]] if len(word) > 1 else [word[0]]
        policies.append(make_subsequence_dfa(required, EVENT_ALPHABET))
    if count >= 4:
        # All the authorization steps included in the string are required.
        approvals = [event for event in EVENT_ALPHABET[-3:] if event in word]
        policies.append(make_subsequence_dfa(approvals or word[:1], EVENT_ALPHABET))
    for authority_index in range(4, count):
        prefix_length = min(len(word), 1 + authority_index % len(word))
        policies.append(make_prefix_dfa(word[:prefix_length], EVENT_ALPHABET))
    if not all(policy.accept(word) for policy in policies):
        raise AssertionError('Generated policy does not accept the workflow')
    return policies

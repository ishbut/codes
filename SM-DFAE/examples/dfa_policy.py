"""Demonstrate one exact-match regular-language policy."""

from smdfae.dfa import make_equality_dfa, make_workflow


def main():
    word = make_workflow(7)
    policy = make_equality_dfa(word)
    print('Access string:', ''.join(word))
    print('Accepted:', policy.accept(word))
    print('Rejected altered input:', not policy.accept(['1'] + word[1:]))


if __name__ == '__main__':
    main()

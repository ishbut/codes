"""Tests for DFA policies and transitions."""

import unittest

from smdfae.dfa import DFAUtils, make_equality_dfa, make_prefix_dfa, make_workflow


class DFATests(unittest.TestCase):
    def test_matching_workflow(self):
        word = make_workflow(5)
        automaton = make_equality_dfa(word)
        self.assertTrue(automaton.accept(word))
        self.assertFalse(automaton.accept(["1"] + word[1:]))

    def test_accepting_path(self):
        automaton = make_equality_dfa(["0", "1"])
        path, states = automaton.get_transitions(["0", "1"])
        self.assertEqual(path, [("q0", "q1", "0"), ("q1", "q2", "1")])
        self.assertEqual(states, ["q0", "q1", "q2"])

    def test_prefix_policy(self):
        dfa = make_prefix_dfa(["0", "1"], ["0", "1"])
        self.assertTrue(dfa.accept(["0", "1", "1", "0"]))
        self.assertFalse(dfa.accept(["1", "0", "1"]))

    def test_simple_cycle(self):
        automaton = DFAUtils(["s0", "s1"], [("s0", "s1", "a"), ("s1", "s1", "b")], "s0", {"s1"})
        self.assertTrue(automaton.accept(["a", "b", "b"]))
        self.assertFalse(automaton.accept(["b", "a"]))


if __name__ == "__main__":
    unittest.main()

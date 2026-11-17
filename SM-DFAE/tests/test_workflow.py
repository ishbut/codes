"""Clinical workflow and multi-authority DFA tests."""

import unittest

from smdfae.workflow import (
    EVENT_ALPHABET, make_authority_policies,
    make_clinical_workflow, make_subsequence_dfa,
)


class WorkflowTests(unittest.TestCase):
    def test_clinical_events(self):
        self.assertEqual(make_clinical_workflow(7), list(EVENT_ALPHABET))
        self.assertEqual(make_clinical_workflow(9)[7:], list(EVENT_ALPHABET[:2]))
        with self.assertRaises(ValueError):
            make_clinical_workflow(0)

    def test_subsequence_policy(self):
        policy = make_subsequence_dfa(['diagnosis', 'project_approved'])
        self.assertTrue(policy.accept(make_clinical_workflow(7)))
        self.assertFalse(policy.accept(['project_approved', 'diagnosis']))
        self.assertTrue(policy.accept(['diagnosis', 'diagnosis', 'project_approved']))

    def test_authorities_share_accepting_workflow(self):
        for n in (1, 2, 4, 8, 16):
            for ell in (1, 5, 7, 20, 40):
                word = make_clinical_workflow(ell)
                policies = make_authority_policies(word, n)
                self.assertEqual(len(policies), n)
                self.assertTrue(all(policy.accept(word) for policy in policies))
                self.assertFalse(policies[0].accept(['unknown'] + word[1:]))


if __name__ == '__main__':
    unittest.main()

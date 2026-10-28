import tempfile
import unittest
from pathlib import Path

from policy_engine.agent_sca import ProposalError, validate
from policy_engine.apply import apply_proposal, rollback_proposal
from policy_engine.proposals import ProposalStore

OWNER = 'a' * 64
SETTINGS = {'enabled': 'yes', 'scan_on_start': 'yes', 'skip_nfs': 'yes', 'interval': '12h'}


class PolicyApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.shared = self.root / 'shared'
        self.group = self.shared / 'default'
        self.group.mkdir(parents=True)
        self.config = self.group / 'agent.conf'
        self.before = '<agent_config>\n</agent_config>\n'
        self.config.write_text(self.before)
        self.verifier = self.root / 'verify-agent-conf'
        self.verifier.write_text('#!/bin/sh\necho "verify-agent-conf: OK"\n')
        self.verifier.chmod(0o700)
        self.store = ProposalStore(str(self.root / 'private' / 'proposals.sqlite3'))
        self.backups = self.root / 'private' / 'backups'

    def tearDown(self):
        self.temp.cleanup()

    def proposal(self):
        result = validate('default', SETTINGS, base=self.shared, verifier=str(self.verifier))
        self.assertTrue(result['valid'])
        return self.store.save(OWNER, '001', result)

    def test_apply_and_rollback_use_exact_hashes(self):
        proposal_id = self.proposal()
        applied = apply_proposal(self.store, proposal_id, OWNER, base=self.shared,
                                 verifier=str(self.verifier), backup_root=self.backups)
        self.assertEqual(applied['status'], 'applied')
        self.assertIn('<sca>', self.config.read_text())
        self.assertEqual(self.store.get(proposal_id, OWNER)['status'], 'applied')
        self.assertEqual(rollback_proposal(self.store, proposal_id, OWNER, base=self.shared,
                                          backup_root=self.backups)['status'], 'rolled_back')
        self.assertEqual(self.config.read_text(), self.before)
        self.assertEqual(self.store.get(proposal_id, OWNER)['status'], 'rolled_back')

    def test_stale_or_foreign_proposal_cannot_apply(self):
        proposal_id = self.proposal()
        with self.assertRaises(ProposalError):
            apply_proposal(self.store, proposal_id, 'b' * 64, base=self.shared,
                           verifier=str(self.verifier), backup_root=self.backups)
        self.config.write_text('<agent_config>\n  <syscheck/>\n</agent_config>\n')
        with self.assertRaisesRegex(ProposalError, 'changed'):
            apply_proposal(self.store, proposal_id, OWNER, base=self.shared,
                           verifier=str(self.verifier), backup_root=self.backups)
        self.assertNotIn('<sca>', self.config.read_text())

    def test_rollback_rejects_intervening_edit(self):
        proposal_id = self.proposal()
        apply_proposal(self.store, proposal_id, OWNER, base=self.shared,
                       verifier=str(self.verifier), backup_root=self.backups)
        self.config.write_text(self.config.read_text() + '\n<!-- intervening edit -->\n')
        with self.assertRaisesRegex(ProposalError, 'changed'):
            rollback_proposal(self.store, proposal_id, OWNER, base=self.shared, backup_root=self.backups)


if __name__ == '__main__':
    unittest.main()

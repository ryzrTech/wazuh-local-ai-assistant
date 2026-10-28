"""Proposal generation and native validation boundary tests."""

import tempfile
import unittest
from pathlib import Path

from policy_engine.agent_sca import ProposalError, build_candidate, validate


SETTINGS = {"enabled": "yes", "scan_on_start": "yes", "skip_nfs": "yes", "interval": "12h"}


class AgentScaProposalTests(unittest.TestCase):
    def test_native_validator_checks_candidate_without_changing_active_file(self):
        with tempfile.TemporaryDirectory() as root:
            shared = Path(root) / "shared"
            group = shared / "default"
            group.mkdir(parents=True)
            active = group / "agent.conf"
            original = "<agent_config>\n  <!-- existing -->\n</agent_config>\n"
            active.write_text(original)
            verifier = Path(root) / "verify-agent-conf"
            verifier.write_text("#!/bin/sh\ntest \"$1\" = -f || exit 2\ngrep -q '<sca>' \"$2\" || exit 3\nprintf 'verify-agent-conf: OK\\n'\n")
            verifier.chmod(0o700)
            result = validate("default", SETTINGS, base=shared, verifier=str(verifier))
            self.assertTrue(result["valid"])
            self.assertFalse(result["applied"])
            self.assertIn("+  <sca>", result["diff"])
            self.assertEqual(active.read_text(), original)

    def test_rejects_unsupported_or_ambiguous_edits(self):
        with self.assertRaises(ProposalError):
            build_candidate("<agent_config/>\n", {**SETTINGS, "interval": "1s"})
        with self.assertRaises(ProposalError):
            build_candidate("<agent_config></agent_config><agent_config></agent_config>", SETTINGS)
        with self.assertRaises(ProposalError):
            build_candidate("<agent_config name='agent1'></agent_config>", SETTINGS)
        with self.assertRaises(ProposalError):
            build_candidate("<agent_config><sca enabled='yes'></sca></agent_config>", SETTINGS)

    def test_existing_policy_declarations_survive(self):
        active = "<agent_config><sca><policies><policy>custom.yml</policy></policies></sca></agent_config>"
        candidate = build_candidate(active, SETTINGS)
        self.assertIn("<policy>custom.yml</policy>", candidate)
        self.assertIn("<interval>12h</interval>", candidate)


if __name__ == "__main__":
    unittest.main()

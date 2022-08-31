from lib.iamcheck_AccessAnalyzer import AccessAnalyzer
import pytest
import json
from lib import iamPolicy

class TestAccessAnalyzer:
    def test_a2_check(self):
        policy = iamPolicy.Policy(file = "lib/tests/test_policy_accessanalyzer.json")
        arn = "arn:aws:iam::123456789012:role/test_role"
        check = AccessAnalyzer()
        result = check.run(policy, arn)
        file = "lib/tests/accessanalyzer_findings.json"
        with open(file, 'r') as f:
            findings = json.loads(f)
        assert(result == finding)
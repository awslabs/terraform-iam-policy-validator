from lib import _load_json_file
from lib.reporter import Reporter
from lib.tfPlan import TerraformPlan
from lib.iamcheck_AccessAnalyzer import Comparator, Validator, PublicAccessChecker, AccessChecker
from iam_check.config import load_config_yaml
import pytest
import json

class TestAccessAnalyzer:

    load_config_yaml("config/default.yaml", exclude_resource_type = [])

    def test_a2_policy_validation(self):
        file = _load_json_file("test/iam_policy/test_plan.json")
        plan = TerraformPlan(**file)
        check = Validator("123456789012", "us-west-2", "aws")
        check.run(plan)
        findings = _load_json_file("test/iam_policy/findings.json")
        assert(Reporter(None, None, None).build_report_from(check.findings).to_json() == findings)

    def test_a2_policy_check_no_new_access_mixed_policies(self):
        for dir_name in ["multiple_policies", "role_inline_assume_policy"]:
            file = _load_json_file(f"test/{dir_name}/test_plan.json")
            plan = TerraformPlan(**file)
            for policy_type in ["resource", "identity"]:
                reference_policy = _load_json_file(f"test/{dir_name}/{policy_type}_reference_policy.json")
                check = Comparator("us-west-2", json.dumps(reference_policy), reference_policy_type=f'{policy_type}')
                check.run(plan)
                test_findings = _load_json_file(f"test/{dir_name}/{policy_type}_findings.json")
                assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == test_findings)
    
    def test_a2_policy_check_no_new_access_identity_policies(self):
        for dir_name in ["identity_policies"]:
            file = _load_json_file(f"test/{dir_name}/test_plan.json")
            plan = TerraformPlan(**file)
            for policy_type in ["identity"]:
                reference_policy = _load_json_file(f"test/{dir_name}/{policy_type}_reference_policy.json")
                check = Comparator("us-west-2", json.dumps(reference_policy), reference_policy_type=f'{policy_type}')
                check.run(plan)
                test_findings = _load_json_file(f"test/{dir_name}/{policy_type}_findings.json")
                assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == test_findings)


    # Integration tests for check-no-public-access command
    # Test template includes a variety of resource types with policies that should
    # cause public access findings, and one private S3 bucket that should not generate a finding.

    def test_a2_policy_check_no_public_access(self):
        # should check resources of all types when not excluding resources
        file = _load_json_file(f"test/public_access/test_plan.json")
        plan = TerraformPlan(**file)
        check = PublicAccessChecker("us-west-2")
        check.run(plan)
        test_findings = _load_json_file(f"test/public_access/public_access_findings.json")
        assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == test_findings)


    def test_a2_check_no_access_granted_actions(self):
        file = _load_json_file("test/no_access_granted/test_plan.json")
        plan = TerraformPlan(**file)
        check = AccessChecker("us-west-2", ['s3:ListBucket'], None)
        check.run(plan)
        findings = _load_json_file("test/no_access_granted/actions_findings.json")
        assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == findings)

    def test_a2_check_no_access_granted_resources(self):
        file = _load_json_file("test/no_access_granted/test_plan.json")
        plan = TerraformPlan(**file)
        check = AccessChecker("us-west-2", None, ['arn:aws:s3:::example'])
        check.run(plan)
        findings = _load_json_file("test/no_access_granted/resources_findings.json")
        assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == findings)

    def test_a2_check_no_access_granted_actions_and_resources(self):
        file = _load_json_file("test/no_access_granted/test_plan.json")
        plan = TerraformPlan(**file)
        check = AccessChecker("us-west-2", ['s3:ListBucket'], ['arn:aws:s3:::example'])
        check.run(plan)
        findings = _load_json_file("test/no_access_granted/resources_and_actions_findings.json")
        assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == findings)

    def test_a2_check_no_access_granted_put_object_actions_and_resources(self):
        file = _load_json_file("test/no_access_granted/test_plan.json")
        plan = TerraformPlan(**file)
        check = AccessChecker("us-west-2", ['s3:PutObject'], ['arn:aws:s3:::example'])
        check.run(plan)
        findings = _load_json_file("test/no_access_granted/empty_findings.json")
        assert(Reporter(None, ['ERROR', 'SECURITY_WARNING'], None).build_report_from(check.findings).to_json() == findings)


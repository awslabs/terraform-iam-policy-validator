"""Regression tests for the check-no-public-access resource-type mapping.

These guard against a class of defect where a malformed key in
``RESOURCE_TYPE_MAP`` (for example a stray trailing colon) causes the exact
lookup in ``PublicAccessChecker.run`` to miss, so the resource silently falls
into the unsupported-resource path and ``CheckNoPublicAccess`` is never
dispatched. When that happens a public resource policy produces no finding and
the command exits 0, defeating a preventive policy gate.

The original defect was the key ``"aws_secretsmanager_secret_policy:"`` (note
the trailing colon) instead of ``"aws_secretsmanager_secret_policy"``.

The tests are fully local: no AWS account, credentials, or API calls. The
Access Analyzer client on the checker is replaced with a mock so the
``CheckNoPublicAccess`` response is controlled in-process.
"""

from unittest.mock import MagicMock

import pytest

from iam_check.lib.iamcheck_AccessAnalyzer import (
    RESOURCE_TYPE_MAP,
    PublicAccessChecker,
)
from iam_check.lib.reporter import Reporter


# The documented Terraform resource types that carry a resource-based policy
# and are extracted by the plan parser use this exact spelling (no trailing
# punctuation, no whitespace). RESOURCE_TYPE_MAP is looked up by exact match,
# so every key must be a clean Terraform resource-type identifier.
_VALID_KEY_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


class _FakePlan:
    """Minimal stand-in for TerraformPlan exposing only what the checker uses.

    ``PublicAccessChecker.run`` calls ``findPolicies()`` (ref -> policy string)
    and ``getResourceName(policy_name)``. A ref is constructed as
    ``<resource_type>.<name>.<attribute>`` (see TerraformPlan.findPolicies), so
    the resource type the checker derives is ``ref.split(".")[0]``.
    """

    def __init__(self, policies):
        self._policies = policies

    def findPolicies(self):
        return self._policies

    def getResourceName(self, policy_name):
        return policy_name


def _make_checker(api_response):
    """Build a PublicAccessChecker with its Access Analyzer client mocked."""
    checker = PublicAccessChecker("us-west-2")
    checker.client = MagicMock()
    checker.client.check_no_public_access.return_value = api_response
    return checker


# A non-PASS CheckNoPublicAccess response (public access granted) that
# _handle_response turns into a blocking SECURITY_WARNING finding.
_PUBLIC_FINDING_RESPONSE = {
    "result": "FAIL",
    "message": "The policy grants public access.",
    "ResponseMetadata": {"HTTPStatusCode": 200},
}

_PASS_RESPONSE = {
    "result": "PASS",
    "message": "",
    "ResponseMetadata": {"HTTPStatusCode": 200},
}


class TestSecretsManagerSecretPolicyMapping:
    def test_secret_policy_type_is_mapped(self):
        # Regression: the key must be the exact Terraform resource type with no
        # trailing colon, or the exact-match lookup in run() misses it.
        assert (
            RESOURCE_TYPE_MAP.get("aws_secretsmanager_secret_policy")
            == "AWS::SecretsManager::Secret"
        )
        assert "aws_secretsmanager_secret_policy:" not in RESOURCE_TYPE_MAP

    def test_public_secret_policy_is_dispatched_and_blocks(self):
        # A public Secrets Manager resource policy must reach CheckNoPublicAccess
        # and become a blocking finding (this failed before the mapping fix:
        # 0 analyzer calls, 0 findings).
        ref = "aws_secretsmanager_secret_policy.example.policy"
        checker = _make_checker(_PUBLIC_FINDING_RESPONSE)
        checker.run(_FakePlan({ref: '{"Version":"2012-10-17"}'}))

        checker.client.check_no_public_access.assert_called_once()
        _, kwargs = checker.client.check_no_public_access.call_args
        assert kwargs["resourceType"] == "AWS::SecretsManager::Secret"
        assert len(checker.findings.security_warnings) == 1

    def test_non_public_secret_policy_is_dispatched_and_passes(self):
        # A dispatched-but-clean policy calls the analyzer and yields no finding,
        # distinguishing the fix from the accidental-skip behavior.
        ref = "aws_secretsmanager_secret_policy.example.policy"
        checker = _make_checker(_PASS_RESPONSE)
        checker.run(_FakePlan({ref: '{"Version":"2012-10-17"}'}))

        checker.client.check_no_public_access.assert_called_once()
        assert len(checker.findings.security_warnings) == 0
        assert len(checker.findings.errors) == 0

    def test_genuinely_unsupported_resource_is_skipped_without_a_call(self):
        # Contrast control: a truly unmapped resource type must still be skipped
        # without an analyzer call. This confirms the fix did not turn the
        # unsupported-resource path into a spurious dispatch.
        ref = "aws_not_a_real_resource.example.policy"
        checker = _make_checker(_PUBLIC_FINDING_RESPONSE)
        checker.run(_FakePlan({ref: '{"Version":"2012-10-17"}'}))

        checker.client.check_no_public_access.assert_not_called()
        assert len(checker.findings.security_warnings) == 0


class TestResourceTypeMapConsistency:
    @pytest.mark.parametrize("key", sorted(RESOURCE_TYPE_MAP.keys()))
    def test_map_keys_are_well_formed(self, key):
        # RESOURCE_TYPE_MAP is looked up by exact string match, so a single
        # stray character in a key silently disables the check for that
        # resource. Every key must be a clean identifier: no surrounding
        # whitespace and only Terraform resource-type characters
        # ([A-Za-z0-9_]). This catches the trailing-colon class of typo.
        assert key == key.strip(), f"{key!r} has surrounding whitespace"
        bad = sorted(set(key) - _VALID_KEY_CHARS)
        assert not bad, f"{key!r} contains unexpected characters: {bad}"

    @pytest.mark.parametrize("value", sorted(set(RESOURCE_TYPE_MAP.values())))
    def test_map_values_look_like_cfn_types(self, value):
        # Values are IAM Access Analyzer / CloudFormation resource types of the
        # form AWS::Service::Resource. A malformed value would be rejected by
        # the API rather than silently skipped, but assert the shape anyway.
        parts = value.split("::")
        assert len(parts) == 3, f"{value!r} is not AWS::Service::Resource"
        assert parts[0] == "AWS", f"{value!r} does not start with AWS::"
        assert all(parts), f"{value!r} has an empty segment"

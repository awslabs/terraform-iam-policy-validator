"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json

from . import default_to_json
from iam_check.tools import regex_patterns

default_finding_types_that_are_blocking = ['ERROR', 'SECURITY_WARNING']


class Reporter:
	"""
	Determines what findings should be reported to the end user based on parameters provided when starting validation.
	"""

	def __init__(self, findings_to_ignore, finding_types_that_are_blocking, allowed_external_principals):
		self.blocking_findings = []
		self.nonblocking_findings = []
		self.findings_to_ignore = findings_to_ignore
		self.finding_types_that_are_blocking = finding_types_that_are_blocking
		self.allowed_external_principals = allowed_external_principals

	def build_report_from(self, findings):
		self._filter_overridden_findings(findings)
		return Report(self.blocking_findings, self.nonblocking_findings)

	def _filter_overridden_findings(self, findings):
		for finding in findings.errors + findings.security_warnings + findings.warnings + findings.suggestions:
			overridden = self._is_finding_ignored(finding)
			if overridden:
				continue

			overridden = self._is_external_principal_allowed(finding)
			if overridden:
				continue

			self._classify_as_blocking_or_non_blocking(finding)

	def _is_finding_ignored(self, finding):
		if self.findings_to_ignore is None:
			return False

		is_ignored = any([finding_to_ignore.matches(finding) for finding_to_ignore in self.findings_to_ignore])
		if is_ignored:
			return True

		return False

	def _is_external_principal_allowed(self, finding):
		if self.allowed_external_principals is None:
			return False

		is_allowed = any([principal_to_allow.matches(finding) for principal_to_allow in self.allowed_external_principals])
		if is_allowed:
			return True

		return False

	def _classify_as_blocking_or_non_blocking(self, finding):
		# if none is present it overrides all others
		if 'NONE' in self.finding_types_that_are_blocking:
			self.nonblocking_findings.append(finding)
			return

		if finding.findingType.upper() in self.finding_types_that_are_blocking:
			self.blocking_findings.append(finding)
		else:
			self.nonblocking_findings.append(finding)


class ResourceOrCodeFindingToIgnore:
	def __init__(self, value):
		self.value = value

	def matches(self, finding):
		return finding.resourceName.lower() == self.value.lower() or \
				finding.code.lower() == self.value.lower()

	def __eq__(self, other):
		if not isinstance(other, ResourceOrCodeFindingToIgnore):
			return False

		return self.value == other.value


class ResourceAndCodeFindingToIgnore:
	def __init__(self, resource_name, code):
		self.resource_name = resource_name
		self.code = code

	def matches(self, finding):
		return finding.resourceName.lower() == self.resource_name.lower() and \
				finding.code.lower() == self.code.lower()

	def __eq__(self, other):
		if not isinstance(other, ResourceAndCodeFindingToIgnore):
			return False

		return self.resource_name == other.resource_name and \
				self.code == other.code


def _get_principal_from_finding(finding):
	if finding.code != 'EXTERNAL_PRINCIPAL':
		return None

	principal = finding.details.get('principal', {})
	aws_principal = principal.get('AWS')
	if aws_principal is not None:
		return aws_principal

	federated_principal = principal.get('Federated')
	if federated_principal is not None:
		return federated_principal

	return principal.get('CanonicalUser')


class AllowedExternalPrincipal:
	def __init__(self, principal):
		self.principal = principal

	def matches(self, finding):
		principal = _get_principal_from_finding(finding)
		if principal is None:
			return False

		match = regex_patterns.generic_arn_pattern.match(principal)
		if match is None:
			# the principal may or may not be an ARN, if it's not an ARN, compare the raw values
			return principal == self.principal

		# if principal is an ARN, grab the account ID from the ARN to compare
		account_id = match.group(1)
		return account_id == self.principal

	def __eq__(self, other):
		if not isinstance(other, AllowedExternalPrincipal):
			return False

		return self.principal == other.principal


class AllowedExternalArn:
	def __init__(self, arn):
		self.arn = arn

	def matches(self, finding):
		principal = _get_principal_from_finding(finding)
		if principal is None:
			return False

		return principal == self.arn

	def __eq__(self, other):
		if not isinstance(other, AllowedExternalArn):
			return False

		return self.arn == other.arn


class Report:
	def __init__(self, blocking_findings, nonblocking_findings):
		self.blocking_findings = blocking_findings
		self.nonblocking_findings = nonblocking_findings

	def has_blocking_findings(self):
		return len(self.blocking_findings) > 0

	def to_json(self):
		return {
			'BlockingFindings': [vars(finding) for finding in self.blocking_findings],
			'NonBlockingFindings': [vars(finding) for finding in self.nonblocking_findings]
		}

	def print(self):
		report = self.to_json()
		report_as_json_string = self._to_json_string(report)
		print(report_as_json_string)

	@staticmethod
	def _to_json_string(obj):
		return json.dumps(obj, default=default_to_json, indent=4)
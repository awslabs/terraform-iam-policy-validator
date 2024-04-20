"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json

from . import default_to_json


class Finding:
	def __init__(self, message, finding_type, policy_name, resource_name, details, code):
		self.findingType = finding_type
		self.code = code
		self.message = message
		self.resourceName = resource_name
		self.policyName = policy_name
		self.details = details


class Findings:
	"""
	Build a findings object from the Access Analyzer response, wrapping the raw findings from Access Analyzer so that
	consumers can parse the output in a standardized manner.
	"""

	def __init__(self):
		self.errors = []
		self.security_warnings = []
		self.warnings = []
		self.suggestions = []

	def add_trust_policy_finding(self, findings, resource_name):
		for raw_finding in findings:
			message = 'Trust policy allows access from external principals.'
			finding = Finding(
				message=message,
				finding_type='SECURITY_WARNING',
				policy_name='TrustPolicy',
				resource_name=resource_name,
				details=raw_finding,
				code='EXTERNAL_PRINCIPAL'
			)

			self.security_warnings.append(finding)

	def add_validation_finding(self, findings, resource_name, policy_name):
		for raw_finding in findings:
			finding_type = raw_finding['findingType']

			finding = Finding(
				message=raw_finding['findingDetails'],
				finding_type=finding_type,
				policy_name=policy_name,
				resource_name=resource_name,
				details=raw_finding,
				code=raw_finding['issueCode']
			)

			if finding_type == 'ERROR':
				self.errors.append(finding)
			elif finding_type == 'SECURITY_WARNING':
				self.security_warnings.append(finding)
			elif finding_type == 'SUGGESTION':
				self.suggestions.append(finding)
			elif finding_type == 'WARNING':
				self.warnings.append(finding)

	def add_policy_analysis_finding(self, findings, resource_name, policy_name):
		for raw_finding in findings:
			finding_type = raw_finding.get('findingType')
			finding = Finding(
				message=raw_finding.get('message'),
				finding_type=finding_type,
				policy_name=policy_name,
				resource_name=resource_name,
				details=raw_finding.get('response'),
				code=raw_finding.get('code')
			)
			if finding_type == 'ERROR':
				self.errors.append(finding)
			elif finding_type == 'SECURITY_WARNING':
				self.security_warnings.append(finding)

	def add_external_principal_finding(self, findings, resource_name, policy_name):
		for raw_finding in findings:
			finding = Finding(
				message='Resource policy allows access from external principals.',
				finding_type='SECURITY_WARNING',
				policy_name=policy_name,
				resource_name=resource_name,
				details=raw_finding,
				code='EXTERNAL_PRINCIPAL'
			)

			self.security_warnings.append(finding)

	def to_json(self):
		return json.dumps(self, default=default_to_json, indent=4)
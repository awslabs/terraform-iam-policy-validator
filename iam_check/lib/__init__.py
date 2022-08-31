"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import datetime
import json


def default_to_json(value):
	if isinstance(value, datetime.date):
		return value.isoformat()
	else:
		return value.__dict__


class InvalidPolicyException(Exception):
	def __init__(self, message, policy):
		self.message = message
		self.policy = policy

	def to_string(self):
		return f'{self.message}\n{json.dumps(self.policy, default=default_to_json, indent=4)}'
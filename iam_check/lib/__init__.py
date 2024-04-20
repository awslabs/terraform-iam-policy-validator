"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import datetime
import json
import logging
from iam_check.application_error import ApplicationError

LOGGER = logging.getLogger('iam-check')

def default_to_json(value):
	if isinstance(value, datetime.date):
		return value.isoformat()
	else:
		return value.__dict__

def _load_json_file(file_path):
    try:
        with open(file_path, 'r') as stream:
            data = stream.read()
            try:
                ret = json.loads(data)
            except Exception:
                logging.exception('Unable to parse json file. Invalid JSON detected.')
                raise ApplicationError('Unable to parse json file. Invalid JSON detected.')
    except FileNotFoundError:
        raise ApplicationError(f'File not found: {file_path}')

    return ret


class InvalidPolicyException(Exception):
	def __init__(self, message, policy):
		self.message = message
		self.policy = policy

	def to_string(self):
		return f'{self.message}\n{json.dumps(self.policy, default=default_to_json, indent=4)}'
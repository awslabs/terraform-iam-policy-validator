"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import boto3
from botocore.config import Config

config = Config(
	retries={
		# this number was chosen arbitrarily, tweak as necessary
		'max_attempts': 30,
		'mode': 'standard'
	}
)


def get_account_and_partition(region):
	"""
	Pull the account and partition from the credentials used to execute the validator
	"""

	sts_client = build('sts', region)
	identity = sts_client.get_caller_identity()
	account_id = identity['Account']

	parts = identity['Arn'].split(':')
	partition = parts[1]

	return account_id, partition


def build(service_name, region_name, client_config=None):
	if client_config is None:
		client_config = config
	session = boto3.Session(profile_name=profile_name, region_name=region_name)
	return session.client(service_name, config=client_config)


profile_name = None


def set_profile(profile):
	global profile_name
	profile_name = profile
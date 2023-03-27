"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from argparse import ArgumentTypeError
from botocore.config import Config
from botocore.exceptions import InvalidRegionError
from botocore.utils import validate_region_name

from .client import build
# from cfn_policy_validator.application_error import ApplicationError

def validate_region(region):
	try:
		# this call validates that the region name is valid, but does not validate that the region actually exists
		validate_region_name(region)
	except InvalidRegionError:
		raise ArgumentTypeError(f'Invalid region name: {region}.')
	return region

def validate_credentials(region):
	# run a test to validate the provided credentials
	# create our own config here to control retries and fail fast if credentials are invalid
	sts_client = build('sts', region, client_config=Config(retries={'mode': 'standard', 'max_attempts': 2}))
	sts_client.get_caller_identity

def validate_finding_types_from_cli(value):
	"""
	Validate that the finding types provided are valid finding types.
	"""

	finding_types = value.split(',')
	finding_types = validate_finding_types(finding_types)

	return finding_types


def validate_finding_types(finding_types):
	if finding_types is None:
		return finding_types

	finding_types = [finding_type.strip() for finding_type in finding_types]
	finding_types = [finding_type.upper() for finding_type in finding_types]

	for finding_type in finding_types:
		if finding_type not in ['ERROR', 'SECURITY_WARNING', 'SUGGESTION', 'WARNING', 'NONE']:
			raise ArgumentTypeError(f"Invalid finding type: {finding_type}.")

	return finding_types
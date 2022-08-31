"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
class AccountConfig:
	def __init__(self, partition, region, account_id):
		self.Account = account_id
		self.Region = region
		self.Partition = partition
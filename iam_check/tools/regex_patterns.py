"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import re

# matches an ARN generically and roughly answers "is this an ARN or not?"
# captures the account ID
generic_arn_pattern = re.compile(r"^arn:aws[a-z0-9-]*:.*:.*:(.*):.*$")


# this looks for values within a string that are surrounded by dollar signs and brackets
# the values must not start with ! (!${}) - as this represents a raw value
# used by Fn::Sub
# e.g. ${MyValue} -> MyValue
fn_sub_variables = re.compile(r'\$\{([^!].*?)\}')


# looks for dynamic ssm regex of the form {{resolve:ssm:reference-key:version}} or {{resolve:ssm:reference-key}}
# captures reference-key and version (if it exists)
dynamic_ssm_reference_regex = re.compile(r'({{resolve:ssm:([a-zA-Z0-9_\.\-\/]+):?(\d+)?}})')
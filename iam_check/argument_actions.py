"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import argparse

from .lib.reporter import ResourceOrCodeFindingToIgnore, ResourceAndCodeFindingToIgnore, \
    AllowedExternalArn, AllowedExternalPrincipal
from .tools import regex_patterns


class DictionaryArgument(argparse.Action):
    """
    Converts key/value pairs in the format of Key=Value to a dictionary
    """

    def __call__(self, _, namespace, values, option_string=None):
        dictionary = {}
        for key_and_value in values:
            key, value = key_and_value.split("=", 1)
            dictionary[key] = value
        setattr(namespace, self.dest, dictionary)


class ParseFindingsToIgnoreFromCLI(argparse.Action):
    """
    Parses comma delimited list of findings to be ignored.  This is either a resource name or a finding code name, or
    a combination of both in the form MyResource.FindingA
    """

    def __call__(self,  _, namespace, values, option_string=None):
        values = values.split(',')

        findings_to_ignore = parse_findings_to_ignore(values)

        setattr(namespace, self.dest, findings_to_ignore)


def parse_findings_to_ignore(values_as_list):
    if values_as_list is None:
        return values_as_list

    values_as_list = [value.strip() for value in values_as_list]

    findings_to_ignore = []
    for value in values_as_list:
        if "." in value:
            resource_and_code = value.split(".", 1)
            # a split must have at least two members of the array, so no need to validate
            finding_to_ignore = ResourceAndCodeFindingToIgnore(resource_and_code[0], resource_and_code[1])
        else:
            finding_to_ignore = ResourceOrCodeFindingToIgnore(value)

        findings_to_ignore.append(finding_to_ignore)

    return findings_to_ignore


class ParseAllowExternalPrincipalsFromCLI(argparse.Action):
    """
    Parse a comma delimieted list of external principals that are allowed.  These are either principal ARNs or values
    (account IDs, canonical user, etc)
    """

    def __call__(self, _, namespace, values, option_string=None):
        values = values.split(',')

        allowed_external_principals = parse_allow_external_principals(values)

        setattr(namespace, self.dest, allowed_external_principals)


def parse_allow_external_principals(values_as_list):
    if values_as_list is None:
        return values_as_list

    values_as_list = [value.strip() for value in values_as_list]

    allowed_external_principals = []
    for value in values_as_list:
        match = regex_patterns.generic_arn_pattern.match(value)
        if match is None:
            allowed_external_principal = AllowedExternalPrincipal(value)
        else:
            allowed_external_principal = AllowedExternalArn(value)

        allowed_external_principals.append(allowed_external_principal)

    return allowed_external_principals

class ParseListFromCLI(argparse.Action):
    def __call__(self, _, namespace, values, option_string=None):
        values = values.split(',')
        if values is None:
            setattr(namespace, self.dest, None)
        values = [value.strip() for value in values]
        setattr(namespace, self.dest, values)
#!/usr/bin/env python3

import argparse
import logging
import json
import sys
import traceback

import iam_check.config as config
from .client import get_account_and_partition, set_profile
from .parameters import validate_region, validate_finding_types_from_cli, validate_credentials
from .argument_actions import ParseFindingsToIgnoreFromCLI, ParseAllowExternalPrincipalsFromCLI, ParseListFromCLI
from .lib import _load_json_file, iamcheck_AccessAnalyzer, account_config, tfPlan
from .lib.reporter import default_finding_types_that_are_blocking, Reporter
from iam_check.application_error import ApplicationError as ApplicationError

# Global Variables
LOGGER = logging.getLogger('iam-policy-validator-for-terraform')

def main():
    global policy_checks
    opts = cli_parse_opts()
    validate_from_cli(opts)

def validate_from_cli(opts):
    account_id, partition = get_account_and_partition(opts.region)
    account = account_config.AccountConfig(partition, opts.region, account_id)
    findings = []
    LOGGER.debug(f'Validating terraform plan file: {opts.template_path}')
    with open(opts.template_path, 'r') as fh:
        data = fh.read()
        try:
            data = json.loads(data)
            plan = tfPlan.TerraformPlan(**data)
        except Exception as e:
            if opts.plan.endswith('.json'):
                print(f'Failed to load plan file from: {opts.template_path}')
                raise e
            plan = tfPlan.plan_from_stdout(data)

    if opts.subparser == 'check-no-new-access':
        checker=iamcheck_AccessAnalyzer.Comparator(account.Region, json.dumps(_load_json_file(opts.reference_policy)), opts.reference_policy_type)
        checker.run(plan)
        findings = checker.findings
    elif opts.subparser == 'check-access-not-granted':
        if opts.actions is None and opts.resources is None:
            raise ApplicationError("ERROR: At least one of --actions or --resources must be specified.")
        else :
            checker=iamcheck_AccessAnalyzer.AccessChecker(account.Region, opts.actions, opts.resources)
            checker.run(plan)
            findings = checker.findings
    elif opts.subparser == 'check-no-public-access':
        checker = iamcheck_AccessAnalyzer.PublicAccessChecker(account.Region)
        checker.run(plan)
        findings = checker.findings
    else:
        validator=iamcheck_AccessAnalyzer.Validator(account.Account, account.Region, account.Partition)
        validator.run(plan)
        findings = validator.findings
        
    treat_as_blocking = opts.treat_as_blocking if 'treat_as_blocking' in vars(opts) else default_finding_types_that_are_blocking
    allowed_external_principals = opts.allowed_external_principals if 'allowed_external_principals' in vars(opts) else None
    reporter = Reporter(opts.ignore_finding, treat_as_blocking, allowed_external_principals)
    report = reporter.build_report_from(findings)
    LOGGER.info('Printing findings to the console...')
    report.print()
            
    if report.has_blocking_findings():
        exit(2)
    else:
        exit(0)


def cli_parse_opts():
    parent_parser = argparse.ArgumentParser(add_help=False)

    parent_parser.add_argument('--template-path', metavar="TEMPLATE_PATH", dest="template_path", required=True,
                        help='Terraform plan file (JSON)')
    parent_parser.add_argument('--region', dest="region", required=True, type=validate_region,
                        help="The region the resources will be deployed to.")
    parent_parser.add_argument('--profile', help='The named profile to use for AWS API calls.')
    parent_parser.add_argument("--config", nargs="+", help='Config file for running this script', action='append')
    parent_parser.add_argument('--enable-logging', help='Enable detailed logging.', default=False, action='store_true')
    parent_parser.add_argument('--exclude-resource-types', dest="exclude_resource_type", default=[],
                                 help='Resource types to exclude from parsing. Specify as a comma separated list of Terraform resource types. '
                                     'Please see README for full list of possible types.',
                                 action=ParseListFromCLI)

    parser = argparse.ArgumentParser(description='Parses IAM identity-based and resource-based policies from Terraform templates.')

    subparsers = parser.add_subparsers(dest='subparser')
    subparsers.required = True
    validate_parser = subparsers.add_parser('validate', help='Parses IAM identity-based and resource-based policies from Terraform templates '
                                                           'and runs them through IAM Access Analyzer for validation.  Returns the findings from '
                                                           'validation in JSON format.', parents=[parent_parser])
    validate_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                 help='Allow validation failures to be ignored.\n'
                             'Specify as a comma separated list of findings to be ignored. Can be individual '
                             'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                             '(e.g. "MyResource"), or a combination of both separated by a period.'
                             '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                 action=ParseFindingsToIgnoreFromCLI)
    validate_parser.add_argument('--treat-finding-type-as-blocking', dest="treat_as_blocking", metavar="ERROR,SECURITY_WARNING",
                                 help='Specify which finding types should be treated as blocking. Other finding types are treated '
                                     'as non-blocking. Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated '
                                     'list of finding types that should be blocking.  Possible values are "ERROR", '
                                     '"SECURITY_WARNING", "SUGGESTION", and "WARNING".  Pass "NONE" to ignore all errors.',
                                 default=default_finding_types_that_are_blocking, type=validate_finding_types_from_cli)

    validate_parser.add_argument('--allow-external-principals', dest='allowed_external_principals', metavar="ACCOUNT,ARN",
                                 help='A comma separated list of external principals that should be ignored.  Specify as '
                                     'a comma separated list of a 12 digit AWS account ID, a federated web identity '
                                     'user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. '
                                     '(e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com)',
                                 action=ParseAllowExternalPrincipalsFromCLI)

    def add_policy_analysis_subparsers():
        # check-no-new-access command
        compare_parser = subparsers.add_parser('check-no-new-access', help='Parses IAM identity-based and resource-based policies from AWS Terraform templates '
                                                            'and runs them through IAM Access Analyzer for comparison with a reference policy.  Returns the response '
                                                            'in JSON format.', parents=[parent_parser])

        compare_parser.add_argument('--reference-policy', dest="reference_policy", required=True,
                                    help='Reference policy to be compared to.\n')

        compare_parser.add_argument('--reference-policy-type', dest="reference_policy_type", required=True,
                                    type=str, help='The type of the reference policy (identity or resource)')

        
        compare_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                    help='Allow findings to be ignored.\n'
                                        'Specify as a comma separated list of findings to be ignored. Can be individual '
                                        'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                                        '(e.g. "MyResource"), or a combination of both separated by a period.'
                                        '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                        action=ParseFindingsToIgnoreFromCLI)
        compare_parser.add_argument('--treat-findings-as-non-blocking', dest="findings_are_blocking", 
                                    help='If set, all findings will be treated as non-blocking',
                                    default=True, action='store_false')
        
        # check-access-not-granted command
        check_access_parser = subparsers.add_parser('check-access-not-granted', help='Parses IAM identity-based and resource-based policies from AWS CloudFormation '
                                                              'templates and runs them through IAM Access Analyzer to check that access to a list of actions and/or '
                                                              'resources is not granted. Returns the response in JSON format.', parents=[parent_parser])

        check_access_parser.add_argument('--resources', dest="resources",
                                         help= 'Resources that policies should not grant access to. '
                                               'Specify as a comma-separated list of resource ARNs to be checked. '
                                               'A maximum of 100 resources can be specified for a single request. '
                                               'The tool will not make multiple requests if you provide more resources than the allowed quota. '
                                               'At least one of --actions or --resources must be specified.', action=ParseListFromCLI)

        check_access_parser.add_argument('--actions', dest="actions",
                                         help= 'Actions that policies should not grant. '
                                               'Specify as a comma separated list of actions to be checked. '
                                               'A maximum of 100 actions can be specified for a single request. '
                                               'The tool will make multiple requests if you provide more actions than the allowed quota. '
                                               'At least one of --actions or --resources must be specified.', action=ParseListFromCLI)

        check_access_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                    help='Allow findings to be ignored.\n'
                                        'Specify as a comma separated list of findings to be ignored. Can be individual '
                                        'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                                        '(e.g. "MyResource"), or a combination of both separated by a period.'
                                        '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                        action=ParseFindingsToIgnoreFromCLI)
        check_access_parser.add_argument('--treat-findings-as-non-blocking', dest="findings_are_blocking", 
                                    help='If set, all findings will be treated as non-blocking',
                                    default=True, action='store_false')
        #check-no-public-access command
        check_no_public_access_parser = subparsers.add_parser('check-no-public-access', help='Parses resource-based policies from AWS Terraform templates and runs them through '
                                                            'IAM Access Analyzer to check that public access to resources of supported types is not granted.  Returns the response '
                                                            'in JSON format.', parents=[parent_parser])
        
        check_no_public_access_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                    help='Allow findings to be ignored.\n'
                                        'Specify as a comma separated list of findings to be ignored. Can be individual '
                                        'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                                        '(e.g. "MyResource"), or a combination of both separated by a period.'
                                        '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                        action=ParseFindingsToIgnoreFromCLI)
        check_no_public_access_parser.add_argument('--treat-findings-as-non-blocking', dest="findings_are_blocking", 
                                    help='If set, all findings will be treated as non-blocking',
                                    default=True, action='store_false')

    
    add_policy_analysis_subparsers()

    args = parser.parse_args()

    #load yaml config
    if args.config is not None:
        for conf in [fileName for arg in args.config for fileName in arg]:
            LOGGER.debug(f'Config file: {conf}')
            config.load_config_yaml(conf, args.exclude_resource_type)

    #Make sure there is at least one policy to look for
    if len(config.iamPolicyAttributes) == 0:
        raise ValueError(f'No IAM policies defined!')
    
    set_profile(args.profile)
    validate_credentials(args.region)
    config.configure_logging(args.enable_logging)
    return args


if  __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        print(f'ERROR: Unexpected error occurred. {str(e)}', file=sys.stderr)
        exit(1)

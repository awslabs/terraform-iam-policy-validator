#!/usr/bin/env python3

import argparse
import logging
import json
import sys
import traceback

from .config import loadConfigYaml, iamPolicyAttributes, configure_logging
from .client import get_account_and_partition, set_profile
from .parameters import validate_region, validate_finding_types_from_cli, validate_credentials
from .argument_actions import ParseFindingsToIgnoreFromCLI, ParseAllowExternalPrincipalsFromCLI
from .lib import iamcheck_AccessAnalyzer, account_config, reporter, tfPlan
from .lib.reporter import default_finding_types_that_are_blocking, Reporter

# Global Variables
LOGGER = logging.getLogger('iam-policy-validator-for-terraform')

def main():
    global policy_checks
    opts = cli_parse_opts()

    account_id, partition = get_account_and_partition(opts.region)
    account = account_config.AccountConfig(partition, opts.region, account_id)
    validator=iamcheck_AccessAnalyzer.Validator(account.Account, account.Region, account.Partition)

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
    validator.run(plan)
        
    findings = validator.findings    
    reporter = Reporter(opts.ignore_finding, opts.treat_as_blocking, opts.allowed_external_principals)
    report = reporter.build_report_from(findings)
    LOGGER.info('Printing findings to the console...')
    report.print()
            
    if report.has_blocking_findings():
        exit(2)
    else:
        exit(0)


def cli_parse_opts():
    parser = argparse.ArgumentParser()

    parser.add_argument('--template-path', metavar="TEMPLATE_PATH", dest="template_path", required=True,
                        help='Terraform plan file (JSON)')
    parser.add_argument('--region', dest="region", required=True, type=validate_region,
                        help="The region the resources will be deployed to.")
    parser.add_argument('--profile', help='The named profile to use for AWS API calls.')
    parser.add_argument("--config", nargs="+", help='Config file for running this script', action='append')
    parser.add_argument('--enable-logging', help='Enable detailed logging.', default=False, action='store_true')
    parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                 help='Allow validation failures to be ignored.\n'
                             'Specify as a comma separated list of findings to be ignored. Can be individual '
                             'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                             '(e.g. "MyResource"), or a combination of both separated by a period.'
                             '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                 action=ParseFindingsToIgnoreFromCLI)
    parser.add_argument('--treat-finding-type-as-blocking', dest="treat_as_blocking", metavar="ERROR,SECURITY_WARNING",
                                 help='Specify which finding types should be treated as blocking. Other finding types are treated '
                                     'as non-blocking. Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated '
                                     'list of finding types that should be blocking.  Possible values are "ERROR", '
                                     '"SECURITY_WARNING", "SUGGESTION", and "WARNING".  Pass "NONE" to ignore all errors.',
                                 default=default_finding_types_that_are_blocking, type=validate_finding_types_from_cli)

    parser.add_argument('--allow-external-principals', dest='allowed_external_principals', metavar="ACCOUNT,ARN",
                                 help='A comma separated list of external principals that should be ignored.  Specify as '
                                     'a comma separated list of a 12 digit AWS account ID, a federated web identity '
                                     'user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. '
                                     '(e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com)',
                                 action=ParseAllowExternalPrincipalsFromCLI)
    args = parser.parse_args()

    #load yaml config
    if args.config is not None:
        for conf in [fileName for arg in args.config for fileName in arg]:
            LOGGER.debug(f'Config file: {conf}')
            loadConfigYaml(conf)

    #Make sure there is at least one policy to look for
    if len(iamPolicyAttributes) == 0:
        raise ValueError(f'No IAM policies defined!')
    
    set_profile(args.profile)
    validate_credentials(args.region)
    configure_logging(args.enable_logging)
    return args


if  __name__ == "__main__":
    try:
        main()
    except Exception as e:
        traceback.print_exc()
        print(f'ERROR: Unexpected error occurred. {str(e)}', file=sys.stderr)
        exit(1)
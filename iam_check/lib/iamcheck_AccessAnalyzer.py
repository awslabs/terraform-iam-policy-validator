import json
import logging
from iam_check import application_error
from iam_check.client import build
from .findings import Findings
from . import iamPolicy
import iam_check.config as config
from botocore.exceptions import ClientError
from botocore.config import Config
from iam_check.application_error import ApplicationError as ApplicationError

LOGGER = logging.getLogger('iam-policy-validator-for-terraform')
ACTIONS_MAX_ITEMS = 100
RESOURCES_MAX_ITEMS = 100
POLICY_ANALYSIS_PREFIX = 'policy-analysis-'
# Mapping of terraform resource type to supported official types
# This list needs to be kept in sync as IAM custom policy checks supports additional resource types.
RESOURCE_TYPE_MAP = {
    "aws_efs_file_system_policy": "AWS::EFS::FileSystem",
    "aws_opensearch_domain": "AWS::OpenSearchService::Domain",
    "aws_opensearch_domain_policy": "AWS::OpenSearchService::Domain",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_s3_bucket_policy": "AWS::S3::Bucket",
    "aws_s3_access_point": "AWS::S3::AccessPoint",
    "aws_s3control_access_point_policy": "AWS::S3::AccessPoint",
    "aws_glacier_vault": "AWS::S3::Glacier",
    "aws_glacier_vault_lock": "AWS::S3::Glacier",
    "aws_s3control_bucket_policy": "AWS::S3Outposts::Bucket",
    "aws_secretsmanager_secret": "AWS::SecretsManager::Secret",
    "aws_secretsmanager_secret_policy:": "AWS::SecretsManager::Secret",
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_sns_topic_policy": "AWS::SNS::Topic",
    "aws_sqs_queue": "AWS::SQS::Queue",
    "aws_sqs_queue_policy": "AWS::SQS::Queue",
    "assume_role_policy": "AWS::IAM::AssumeRolePolicyDocument"
}

class Validator:
    def __init__(self, account_id, region, partition):
        self.findings = Findings()
        self.access_analyzer_name = 'AnalyzerCreatedByTfIAMPolicyValidator'
        self.analyzer_arn = None
        self.client = build('accessanalyzer', region)
		# preview builders are used to build the access preview configuration for an individual resource type
		# a preview builder must be added to add support for access previews for a given resource
#         self.preview_builders = {
# 			'AWS::SQS::Queue': SqsQueuePreviewBuilder(account_id, region, partition),
# 			'AWS::KMS::Key': KmsKeyPreviewBuilder(account_id, region, partition),
# 			'AWS::S3::AccessPoint': S3SingleRegionAccessPointPreviewBuilder(account_id, region, partition),
# 			'AWS::S3::MultiRegionAccessPoint': S3MultiRegionAccessPointPreviewBuilder(account_id, partition),
# 			'AWS::S3::Bucket': S3BucketPreviewBuilder(region, partition),
# 			'AWS::IAM::Role::TrustPolicy': RoleTrustPolicyPreviewBuilder(account_id, partition),
# 			'AWS::SecretsManager::Secret': SecretsManagerSecretPreviewBuilder(account_id, region, partition)
# 		}
		# maps the resource type to the parameter for validate_policy that enables service specific policy validation
		# not all services have service specific policy validation.  The names may be identical for now, but we don't
		# want to rely on that
		#to move this to config file
        self.maximum_number_of_access_preview_attempts = 150

    def run(self, plan):
        policies = plan.findPolicies()
        for ref, policy in policies.items():
            LOGGER.info(f'check policy at: {ref}')
            policy_resource_type=ref.split('.')[0]
            policy_name = '.'.join(ref.split('.')[0:-1])
            resource_name = plan.getResourceName(policy_name)
            p = iamPolicy.Policy(json=policy)
            LOGGER.info(f'start checking policy:{p}')
            policyType='IDENTITY_POLICY'
            for statement in p.getStatement():
                if statement.getPrincipal() != None or statement.getNotPrincipal() != None:
                    policyType='RESOURCE_POLICY'
                    continue
            if policy_resource_type not in config.validatePolicyResourceType :
                response = self.client.validate_policy(policyDocument=str(p),policyType=policyType)
            else:
                policy_resource_type = config.validatePolicyResourceType[policy_resource_type]
                response = self.client.validate_policy(
                    policyDocument=str(p),
                    policyType=policyType,
                    validatePolicyResourceType=policy_resource_type
                )
            validation_findings = response['findings']
            self.findings.add_validation_finding(validation_findings, resource_name, policy_name)

def get_policy_type(resource_type, resource_attribute_name = None):
        # https://registry.terraform.io/providers/hashicorp/aws/latest/docs
        if resource_type in [
            "aws_iam_group_policy",
            "aws_iam_policy",
            "aws_iam_role",
            "aws_iam_role_policy",
            "aws_iam_user_policy"
        ]:
            if resource_type == "aws_iam_role" and resource_attribute_name == "assume_role_policy":
                return "RESOURCE_POLICY"
            return "IDENTITY_POLICY"
        else:
            return "RESOURCE_POLICY"

class PolicyAnalysis:
    def __init__(self, region):
        self.findings = Findings()
        self.client = build('accessanalyzer', region, client_config=Config(
            retries={
                # this number was chosen arbitrarily, tweak as necessary
                'max_attempts': 3,
                'mode': 'standard'
            }
        ))
        self.findings = Findings()
        self.identity_policy_cache = {}
        self.resource_policy_cache = {}


    def _handle_response(self, response, resource_name, policy_name, operation_name):
        """
        Builds a list of raw findings based on the API response
        """
        # check-access passes in a list as it does batching and calling for more than 50 actions
        if isinstance(response, list):
            findings = [self._build_policy_analysis_finding(r, operation_name) for r in response if r.get('result') != 'PASS']
        elif response.get('result') != 'PASS':
            findings = [self._build_policy_analysis_finding(response, operation_name)]
        else:
            findings = []
        self.findings.add_policy_analysis_finding(findings, resource_name, policy_name)

    def _build_policy_analysis_finding(self, response, operation_name):
        """
        Create a raw finding for non 'PASS' results
        """
        code = f'{POLICY_ANALYSIS_PREFIX}{operation_name}'
        response_code = response['ResponseMetadata']['HTTPStatusCode']
        if response_code != 200:
            # error response shape https://boto3.amazonaws.com/v1/documentation/api/latest/guide/error-handling.html
            # response['Error']['Code'] returns literal exception name such as ValidationException, UnprocessableEntityException
            # Raise error for non 400 errors
            if (response_code < 400 or response_code > 499):
                raise application_error(response.get('message'))
            # Add finding for 400 errors
            else:
                code += response['Error']['Code']
                finding_type = "ERROR"
        else:
            finding_type = "SECURITY_WARNING"
        response_no_metadata = response.copy()
        rawFinding = {
            'message': response.get('message'),
            'findingType': finding_type,
            'response': response_no_metadata,
            'code': code
        }
        del response_no_metadata['ResponseMetadata']
        return rawFinding

    def _call_api(self, policy_as_json, policy_type):
        pass

    def _get_policy_type():
        pass

    def run(self, plan):
        policies = plan.findPolicies()
        for ref, policy_str in policies.items():
            LOGGER.info(f'check policy at: {ref}')
            policy_resource_type=ref.split('.')[0]
            LOGGER.info(f'resource type = {policy_resource_type}')
            policy_attribute_type=ref.split('.')[-1]
            LOGGER.info(f'policy attribute type = {policy_resource_type}')
            policy_name = '.'.join(ref.split('.')[0:-1])
            resource_name = plan.getResourceName(policy_name)
            LOGGER.info(f'start checking policy:{policy_str}')
            policy_type = get_policy_type(policy_resource_type, policy_attribute_type)
            cache = self.identity_policy_cache if policy_type == "IDENTITY_POLICY" else self.resource_policy_cache
            response = cache.get(policy_str)
            if response is None:
                response = self._call_api(policy_str, policy_type)
                cache[policy_str] = response
            self._handle_response(response, resource_name, policy_name, self.operation_name)


class Comparator(PolicyAnalysis):

    def __init__(self, region, reference_policy, reference_policy_type):
        PolicyAnalysis.__init__(self, region)
        self.reference_policy = reference_policy
        self.operation_name = "CheckNoNewAccess"
        self.reference_policy_type = reference_policy_type

    def _call_api(self, policy, policy_type):
        if self.reference_policy_type == "identity" and policy_type != "IDENTITY_POLICY":
            return []
        if self.reference_policy_type == "resource" and policy_type != "RESOURCE_POLICY":
            return []
        try:
            response = self.client.check_no_new_access(
                policyType=policy_type,
                existingPolicyDocument=self.reference_policy,
                newPolicyDocument=policy,
            )
        except ClientError as error:
            return error.response

        return response

class AccessChecker(PolicyAnalysis):

    def __init__(self, region, actions=[], resources=[]):
        #add resources to this, copy paste from cfn files
        PolicyAnalysis.__init__(self, region)
        self.accesses = []
        if actions:
            for i in range (0, len(actions), ACTIONS_MAX_ITEMS):
                access = [self.create_access(actions, resources)]
                self.accesses.append(access)
        elif resources:
            self.accesses.append([self.create_access(actions, resources)])
        self.operation_name = "CheckAccessNotGranted"

    def create_access(self, actions, resources):
        access = {}
        if actions:
            access["actions"] = actions
        if resources:
            if len(resources) > RESOURCES_MAX_ITEMS:
                raise ApplicationError("Too many resource ARNs were specified. You may only specify up to 100 resource ARNs.")
            access["resources"] = resources
        return access


    def _call_api(self, policy, policy_type):
        responses = []
        failed_response = {
            "result": "FAIL",
            "reasons": []
        }
        for access in self.accesses:
            LOGGER.info(f'Batching actions {access}')
            try:
                response = self.client.check_access_not_granted(
                    policyType=policy_type,
                    policyDocument=policy,
                    access=access
                )
            except ClientError as error:
                response = error.response
            if response.get('result') == 'FAIL':
                failed_response['message'] = response.get('message')
                reasons = response.get('reasons')
                if reasons is not None:
                    for r in reasons:
                        r['accessInput'] = access
                    failed_response['reasons'].extend(reasons)
                else:
                    failed_response['reasons'].append({
                        'accessInput': access
                    })
                failed_response['ResponseMetadata'] = response['ResponseMetadata']
            else:
                response['accessInput'] = access
                responses.append(response)
        if failed_response.get('ResponseMetadata'): # There were fail responses
            responses.append(failed_response)
        return responses

class PublicAccessChecker(PolicyAnalysis):

    def __init__(self, region):
        PolicyAnalysis.__init__(self, region)
        self.operation_name = "CheckNoPublicAccess"

    def _call_api(self, policy, resource_type):
        try:
            response = self.client.check_no_public_access(
                policyDocument=policy,
                resourceType=resource_type
            )
        except ClientError as error:
            return error.response

        return response

    def run(self, plan):
        # Override default plan run behavior since CheckNoPublicAccess only takes resource policies.
        # We also want to account for resource type as well in caching results
        policies = plan.findPolicies()
        # See tfPlan.findPolicies() for how reference is constructed. Example reference: aws_s3_bucket.example.policy
        for ref, policy_str in policies.items():
            LOGGER.info(f'check policy at: {ref}')
            policy_resource_type=ref.split('.')[0]
            policy_attribute_type=ref.split('.')[-1]
            policy_type = get_policy_type(policy_resource_type, policy_attribute_type)
            # Skip non resource policies
            if policy_type != "RESOURCE_POLICY":
                continue
            # Get the official AWS resource type. assume_role_policy is under policy_attribute_type
            aws_resource_type = RESOURCE_TYPE_MAP.get(policy_resource_type, RESOURCE_TYPE_MAP.get(policy_attribute_type))
            # Skip resource type if it is not one of the officially supported types
            if not aws_resource_type:
                LOGGER.info(f'Resource type {policy_resource_type} not found in the mapping of terraform to official AWS types')
                continue
            policy_name = '.'.join(ref.split('.')[0:-1])
            resource_name = plan.getResourceName(policy_name)
            LOGGER.info(f'start checking policy:{policy_str}')

            # Include resource type in cache key, since resources of different types might have the same policy but
            # use different BPA check
            cache = self.resource_policy_cache
            response = cache.get((policy_str, aws_resource_type))
            if response is None:
                response = self._call_api(policy_str, aws_resource_type)
                cache[(policy_str, aws_resource_type)] = response
            self._handle_response(response, resource_name, policy_name, self.operation_name)
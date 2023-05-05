import logging

import iam_check.config as config

from ..client import build
from . import iamPolicy
from .findings import Findings

LOGGER = logging.getLogger("iam-policy-validator-for-terraform")

# class AccessAnalyzer(iamCheck.IamCheck):
class Validator:
    def __init__(self, account_id, region, partition):
        self.findings = Findings()
        self.access_analyzer_name = "AnalyzerCreatedByCfnIAMPolicyValidator"
        self.analyzer_arn = None
        self.client = build("accessanalyzer", region)
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
        # to move this to config file
        self.maximum_number_of_access_preview_attempts = 150

    def run(self, plan):
        policies = plan.findPolicies()
        for ref, policy in policies.items():
            LOGGER.info(f"check policy at: {ref}")
            policy_resource_type = ref.split(".")[0]
            policy_name = ".".join(ref.split(".")[0:-1])
            resource_name = plan.getResourceName(policy_name)
            p = iamPolicy.Policy(json=policy)
            LOGGER.info(f"start checking policy:{p}")
            policyType = "IDENTITY_POLICY"
            for statement in p.getStatement():
                if (
                    statement.getPrincipal() != None
                    or statement.getNotPrincipal() != None
                ):
                    policyType = "RESOURCE_POLICY"
                    continue
            if policy_resource_type not in config.validatePolicyResourceType:
                response = self.client.validate_policy(
                    policyDocument=str(p), policyType=policyType
                )
            else:
                policy_resource_type = config.validatePolicyResourceType[
                    policy_resource_type
                ]
                response = self.client.validate_policy(
                    policyDocument=str(p),
                    policyType=policyType,
                    validatePolicyResourceType=policy_resource_type,
                )
            validation_findings = response["findings"]
            self.findings.add_validation_finding(
                validation_findings, resource_name, policy_name
            )

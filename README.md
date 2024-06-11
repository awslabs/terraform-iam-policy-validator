## IAM Policy Validator for Terraform
A command line tool that takes a Terraform template, parses IAM identity-based and resource-based policies, then runs them through [IAM Access Analyzer policy validation checks](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html) and (optionally) through IAM Access Analyzer custom policy checks. Note that a charge is associated with each custom policy check. For more details about pricing, see [IAM Access Analyzer pricing](https://aws.amazon.com/iam/access-analyzer/pricing/).

## Table of Contents<!-- omit in toc -->

- [Pre-requisites](#pre-requisites)
- [Getting Started](#getting-started)
- [Limitations](#limitations)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Contributors](#contributors)

## Pre-requisites
An analyzer needs to exist in the account. To create an analyzer with the account as the zone of trust, see AWS documentation [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling).

## Getting Started

### Installation
Python 3+ is supported.
```
$ pip install tf-policy-validator
$ tf-policy-validator -h
```
### Credentials
The tool should be run using credentials from the AWS account that you plan to deploy terraform template to. The tool uses boto3 to interact with your AWS account. You can use one of the following methods to specify credentials:

- Environment variables
- Shared credential file (~/.aws/credentials)
- AWS config file (~/.aws/config)
- Assume Role provider
- Instance metadata service on an Amazon EC2 instance that has an IAM role configured.

[Read more about these options](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)

The principal used to execute the tool requires the following permissions.
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AccessAnalyzerValidatePolicy",
            "Effect": "Allow",
            "Action": [
                "access-analyzer:ValidatePolicy",
                "access-analyzer:CheckNoNewAccess",
                "access-analyzer:CheckAccessNotGranted",
                "access-analyzer:CheckNoPublicAccess"
            ],
            "Resource": "*"
        }
    ]
}
```
| Action Name| Justificiation |
| ---------- | ------------- |
| access-analyzer:ValidatePolicy | Called for each policy to validate against IAM policy best practices. |
| access-analyzer:CheckNoNewAccess | Called for each policy to validate against a reference policy to compare permissions. |
| access-analyzer:CheckAccessNotGranted | Called for each policy to validate that it does not grant access to a list of IAM actions, considered as critical permissions, provided as input. |
| access-analyzer:CheckNoPublicAccess | Called for each policy to validate that it does not grant public access to supported resource types. |


### Basic usage
```
tf-policy-validator validate --config iam_check/config/default.yaml --template-path ./my-template.json --region us-east-1
```

### Commands
**validate**
```
tf-policy-validator validate --config iam_check/config/default.yaml --template-path ./my-template.json --region us-east-1
```
Parses IAM identity-based and resource-based policies from Terraform templates. Then runs the policies through IAM Access Analyzer for validation. Returns the findings from validation in JSON format. Exits with a non-zero error code if any findings categorized as blocking are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings.

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --help  | | | show this help message and exit |
| --template-path | | FILE_NAME | The path to the Terraform plan file (JSON). |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE, RESOURCE_NAME, RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time.
| --treat-finding-type-as-blocking | | ERROR, SECURITY_WARNING, WARNING, SUGGESTION, NONE | Specify which finding types should be treated as blocking. Other finding types are treated as nonblocking.  If the tool detects any blocking finding types, it will exit with a non-zero exit code.  If all findings are nonblocking or there are no findings, the tool exits with an exit code of 0.  Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated list of finding types that should be blocking. Pass "NONE" to ignore all findings. |
| --allow-external-principals | | ACCOUNT,ARN | A comma separated list of external principals that should be ignored.  Specify as a comma separated list of a 12 digit AWS account ID, a federated web identity user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. (e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com) |
| --config |Yes | FILE_NAME1, FILE_NAME2, ... | A list of config files for running this script |
**check-no-new-access**
```
tf-policy-validator check-no-new-access --config iam_check/config/default.yaml --template-path iam_check/test/test_policy_accessanalyzer.json --region us-west-2 --reference-policy-type identity --reference-policy iam_check/test/test_policy.json
```
Parses IAM identity-based and resource-based policies from Terraform templates. Then runs the policies through IAM Access Analyzer for a custom check against a reference policy. Returns the findings from the custom check in JSON format. Exits with a non-zero error code if any findings categorized as blocking, based on new access, are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings. You can find examples for reference policies and learn how to set up and run a custom policy check for new access in the [IAM Access Analyzer custom policy checks samples](https://github.com/aws-samples/iam-access-analyzer-custom-policy-check-samples) repository on GitHub.

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --help  | | | show this help message and exit |
| --template-path | | FILE_NAME | The path to the Terraform plan file (JSON). |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE, RESOURCE_NAME, RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time. |
| --reference-policy | Yes | FILE_PATH.json | A JSON formatted file that specifies the path to the reference policy that is used for a permissions comparison.   |
| --reference-policy-type | Yes | IDENTITY or RESOURCE | The policy type associated with the IAM policy under analysis and the reference policy.  |
| --treat-findings-as-non-blocking | | | When not specified, the tool detects any findings, it will exit with a non-zero exit code. When specified, the tool exits with an exit code of 0. |
| --exclude-resource-types | | aws_resource_type, aws_resource_type | List of comma-separated resource types. Resource types should be the same as terraform template resource names such as aws_iam_group_policy, aws_iam_role |
| --config |Yes | FILE_NAME1, FILE_NAME2, ... | A list of config files for running this script |

**check-access-not-granted**
```
tf-policy-validator check-access-not-granted --config iam_check/config/default.yaml --template-path iam_check/test/test_policy_accessanalyzer.json --region us-west-2 --actions lambda:invokeFunction
```
Parses IAM identity-based and resource-based policies from AWS Terraform templates. Then runs the policies through IAM Access Analyzer for a custom check against a list of IAM actions and/or resource ARNs. If both actions and resources are provided, a custom check will be run to determine whether access is granted to allow the specified actions on the specified resources. Returns the findings from the custom check in JSON format. Exits with a non-zero error code if any findings categorized as blocking, based on access granted to at least one of the listed IAM actions and/or resources, are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings.

| Arguments | Required |  Options | Description |
| --------- | ----- | ---------| ----------- |
| --help  | | | show this help message and exit |
| --template-path | | FILE_NAME | The path to the Terraform plan file (JSON). |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time. |
| --actions | At least one of actions or resources is required. | ACTION,ACTION,ACTION | List of comma-separated actions. |
| --resources | At least one of actions or resources is required. | RESOURCE,RESOURCE,RESOURCE | List of comma-separated resource ARNs, maximum 100 resource ARNs.  
| --treat-findings-as-non-blocking | | | When not specified, the tool detects any findings, it will exit with a non-zero exit code. When specified, the tool exits with an exit code of 0. |
| --exclude-resource-types | | aws_resource_type, aws_resource_type | List of comma-separated resource types. Resource types should be the same as terraform template resource names such as aws_iam_group_policy, aws_iam_role |
| --config |Yes | FILE_NAME1, FILE_NAME2, ... | A list of config files for running this script |

**check-no-public-access**
```
tf-policy-validator check-no-public-access --config iam_check/config/default.yaml --template-path iam_check/test/test_policy_accessanalyzer.json --region us-west-2
```
Parses resource-based policies from Terraform templates. Then runs the policies through IAM Access Analyzer for a custom check for public access to resources. Returns the findings from the custom check in JSON format. Exits with a non-zero error code if any findings categorized as blocking, based on whether public access is granted to at least one of the resources, are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings.

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --help  | | | show this help message and exit |
| --template-path | | FILE_NAME | The path to the Terraform plan file (JSON). |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE, RESOURCE_NAME, RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time. |
| --treat-findings-as-non-blocking | | | When not specified, the tool detects any findings, it will exit with a non-zero exit code. When specified, the tool exits with an exit code of 0. |
| --exclude-resource-types | | aws_resource_type, aws_resource_type | List of comma-separated resource types. Resource types should be the same as terraform template resource names such as aws_iam_group_policy, aws_iam_role |
| --config |Yes | FILE_NAME1, FILE_NAME2, ... | A list of config files for running this script |

Resource-based policies that can be checked with `check-no-public-access` are limited to the resource types currently supported by IAM Policy Validator for Terraform. The following resource types are supported:
- AWS::EFS::FileSystem
- AWS::OpenSearchService::Domain
- AWS::KMS::Key
- AWS::S3::Bucket
- AWS::S3::AccessPoint
- AWS::S3::Glacier
- AWS::S3Outposts::Bucket
- AWS::SecretsManager::Secret
- AWS::SNS::Topic
- AWS::SQS::Queue
- Role trust policies (AWS::IAM::AssumeRolePolicyDocument)


### Example to check Terraform template
```
$ cd iam_check/test/
$ terraform init
$ terraform plan -out tf.plan ## generate terraform plan file
$ terraform show -json -no-color tf.plan > tf.json ## convert plan files to machine-readable JSON files. For TF 0.12 and prior, use command `terraform show tf.plan > tf.out`
$ cd ../..
$ tf-policy-validator --config iam_check/config/default.yaml --template-path iam_check/test/tf.json --region us-east-1 --treat-finding-type-as-blocking ERROR # For TF 0.12 and prior, replace tf.json with tf.out
$ tf-policy-validator check-no-new-access --config iam_check/config/default.yaml --template-path iam_check/test/test_policy_accessanalyzer.json --region us-west-2 --reference-policy-type identity --reference-policy iam_check/test/test_policy.json
$ tf-policy-validator check-access-not-granted --config iam_check/config/default.yaml --template-path iam_check/test/test_policy_accessanalyzer.json --region us-west-2 --actions lambda:invokeFunction
$ tf-policy-validator check-no-public-access --config iam_check/config/default.yaml --template-path iam_check/test/test_policy_accessanalyzer.json --region us-west-2
```

_More examples can be found [here](iam_check/doc/)_.

## Limitations

1. Does not support Terraform [computed resources](https://www.terraform.io/plugin/sdkv2/schemas/schema-behaviors).
For example, the tool will report no IAM policy found for the following Terraform template. The policy json string is a computed resource. The plan output doesn't contain information of IAM policy document. 

```
resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
        ]
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.b.id}"
      }
    ]
  })
}
```

## Frequently Asked Questions
**How to run unit tests**
```
$ python3 -m pip install pipenv
$ pipenv install --dev
$ pipenv shell
$ cd iam_check
$ python3 -m pytest
```

## Contributors
[Contributors](CONTRIBUTORS)
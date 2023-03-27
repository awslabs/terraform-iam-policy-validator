## IAM Policy Validator for Terraform
A command line tool that takes a Terraform template, parses IAM identity-based and resource-based policies, then runs them through [IAM Access Analyzer policy validation checks](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).

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
                "access-analyzer:ValidatePolicy"
            ],
            "Resource": "*"
        }
    ]
}
```
| Action Name| Justificiation |
| ---------- | ------------- |
| access-analyzer:ValidatePolicy | Called for each policy to validate against IAM policy best practices. |


### Basic usage
```
tf-policy-validator --config iam_check/config/default.yaml --template-path ./my-template.json --region us-east-1
```

### Avaliable commands

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --help  | | | show this help message and exit |
| --template-path | | FILE_NAME | The path to the Terraform plan file (JSON). |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time.
| --treat-finding-type-as-blocking | | ERROR,SECURITY_WARNING,WARNING,SUGGESTION,NONE | Specify which finding types should be treated as blocking. Other finding types are treated as nonblocking.  If the tool detects any blocking finding types, it will exit with a non-zero exit code.  If all findings are nonblocking or there are no findings, the tool exits with an exit code of 0.  Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated list of finding types that should be blocking. Pass "NONE" to ignore all findings. |
| --allow-external-principals | | ACCOUNT,ARN | A comma separated list of external principals that should be ignored.  Specify as a comma separated list of a 12 digit AWS account ID, a federated web identity user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. (e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com) |
| --config |Yes | FILE_NAME1, FILE_NAME2, ... | A list of config files for running this script |

### Example to check Terraform template
```
$ cd iam_check/test/
$ terraform init
$ terraform plan -out tf.plan ## generate terraform plan file
$ terraform show -json -no-color tf.plan > tf.json ## convert plan files to machine-readable JSON files. For TF 0.12 and prior, use command `terraform show tf.plan > tf.out`
$ cd ../..
$ tf-policy-validator --config iam_check/config/default.yaml --template-path iam_check/test/tf.json --region us-east-1 --treat-finding-type-as-blocking ERROR # For TF 0.12 and prior, replace tf.json with tf.out
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
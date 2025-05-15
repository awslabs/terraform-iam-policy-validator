***main.tf***
```
terraform {
  required_version = "= 1.2.4"
}

data "aws_iam_policy_document" "demo_bucket_policy" {
  statement {
    sid = "ListBucket"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    effect = "Allow"
    actions = [
      "s3:ListBuckets"
    ]
    resources = ["*"]
  }
}

resource "aws_s3_bucket_policy" "demo_bucket_policy" {
  bucket = "demo-bucket"
  policy = data.aws_iam_policy_document.demo_bucket_policy.json
}
```

***commands***
```bash
$ terraform init
$ terraform plan -out tf.plan
$ terraform show -json -no-color tf.plan > tf.json

$ python3 -m pip install pipenv
$ pipenv install
$ pipenv run python iam_check/iam_check.py --config iam_check/config/default.yaml --template-path tf.json --region us-east-1
```

***report***
```json
{
    "BlockingFindings": [
        {
            "findingType": "ERROR",
            "code": "INVALID_ACTION",
            "message": "The action s3:ListBuckets does not exist. Did you mean s3:ListAllMyBuckets? The API called ListBuckets authorizes against the IAM action s3:ListAllMyBuckets.",
            "resourceName": "demo-bucket",
            "policyName": "aws_s3_bucket_policy.demo_bucket_policy",
            "details": {
                "findingDetails": "The action s3:ListBuckets does not exist. Did you mean s3:ListAllMyBuckets? The API called ListBuckets authorizes against the IAM action s3:ListAllMyBuckets.",
                "findingType": "ERROR",
                "issueCode": "INVALID_ACTION",
                "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-error-invalid-action",
                "locations": [
                    {
                        "path": [
                            {
                                "value": "Statement"
                            },
                            {
                                "value": "Action"
                            }
                        ],
                        "span": {
                            "start": {
                                "line": 9,
                                "column": 18,
                                "offset": 181
                            },
                            "end": {
                                "line": 9,
                                "column": 34,
                                "offset": 197
                            }
                        }
                    }
                ]
            }
        },
        {
            "findingType": "ERROR",
            "code": "UNSUPPORTED_RESOURCE_ARN_IN_POLICY",
            "message": "The resource ARN is not supported for the resource-based policy attached to resource type S3 Bucket.",
            "resourceName": "demo-bucket",
            "policyName": "aws_s3_bucket_policy.demo_bucket_policy",
            "details": {
                "findingDetails": "The resource ARN is not supported for the resource-based policy attached to resource type S3 Bucket.",
                "findingType": "ERROR",
                "issueCode": "UNSUPPORTED_RESOURCE_ARN_IN_POLICY",
                "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-error-unsupported-resource-arn-in-policy",
                "locations": [
                    {
                        "path": [
                            {
                                "value": "Statement"
                            },
                            {
                                "value": "Resource"
                            }
                        ],
                        "span": {
                            "start": {
                                "line": 10,
                                "column": 20,
                                "offset": 219
                            },
                            "end": {
                                "line": 10,
                                "column": 23,
                                "offset": 222
                            }
                        }
                    }
                ]
            }
        }
    ],
    "NonBlockingFindings": []
}
```

***main.tf***
```
terraform {
  required_version = "= 1.2.4"
}

data "aws_iam_policy_document" "demo_bucket_policy" {
  statement {
    sid = "ListBucket"
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
                            "end": {
                                "column": 34,
                                "line": 6,
                                "offset": 140
                            },
                            "start": {
                                "column": 18,
                                "line": 6,
                                "offset": 124
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
***main.tf***
```
terraform {
  required_version = "= 1.2.4"
}

data "aws_iam_policy_document" "demo_policy" {
  statement {
    sid = "PassExecutionRole"
    effect = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
  
  statement {
    sid = "ReadOnlyPermissions"
    effect = "Allow"
    actions   = [
      "iam:ListRoles",
      "lambda:GetAccountSettings",
      "lambda:ListEventSourceMappings",
      "lambda:ListFunctions"
    ]
    resources =["*"]
  }
  statement {
    sid = "ViewAndConfigureFunctions"
    effect = "Allow"
    actions   = [                
      "lambda:CreateFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:GetFunctionEventInvokeConfig",
      "lambda:GetPolicy",
      "lambda:ListAliases",
      "lambda:ListProvisionedConcurrencyConfigs",
      "lambda:ListTags",
      "lambda:ListVersionsByFunction",
      "lambda:UpdateFunctionCode",
      "lambda:invokeFunction" 
    ]
    resources = ["arn:aws:lambda:us-east-1:123456789012:function:pizza-*"]
  }
}

resource "aws_iam_policy" "demo_policy" {
  name        = "demo-policy"
  description = "This is a problematic IAM policy for demo purpose"
  policy = data.aws_iam_policy_document.demo_policy.json
}

resource "aws_iam_role" "demo_role" {
  name = "demo-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "demo-attach" {
  name       = "demo-attachment"
  roles      = [aws_iam_role.demo_role.name]
  policy_arn = aws_iam_policy.demo_policy.arn
}
```
***commands***
```bash
$ terraform init
$ terraform plan -out tf.plan 
$ terraform show -json -no-color tf.plan > tf.json

$ python3 -m pip install pipenv
$ pipenv install 
$ pipenv run python iam_check/iam_check.py --config iam_check/config/default.yaml --template-path tf.json --region us-east-1 --ignore-finding demo-policy
OR
$ pipenv run python iam_check/iam_check.py --config iam_check/config/default.yaml --template-path tf.json --region us-east-1 --ignore-finding PASS_ROLE_WITH_STAR_IN_RESOURCE
```

***report***
```json
{
    "BlockingFindings": [],
    "NonBlockingFindings": [
        {
            "findingType": "SUGGESTION",
            "code": "EMPTY_ARRAY_RESOURCE",
            "message": "This statement includes no resources and does not affect the policy. Specify resources.",
            "resourceName": "demo-role",
            "policyName": "aws_iam_role.demo_role",
            "details": {
                "findingDetails": "This statement includes no resources and does not affect the policy. Specify resources.",
                "findingType": "SUGGESTION",
                "issueCode": "EMPTY_ARRAY_RESOURCE",
                "learnMoreLink": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html#access-analyzer-reference-policy-checks-suggestion-empty-array-resource",
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
                            "end": {
                                "column": 22,
                                "line": 9,
                                "offset": 221
                            },
                            "start": {
                                "column": 20,
                                "line": 9,
                                "offset": 219
                            }
                        }
                    }
                ]
            }
        }
    ]
}
```
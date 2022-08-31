terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

data "aws_iam_policy_document" "demo_policy" {
  statement {
    sid = "PassExecutionRole"
    effect = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::123456789012:role/topping-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
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
  description = "This is a demo policy"
  policy = data.aws_iam_policy_document.demo_policy.json
}


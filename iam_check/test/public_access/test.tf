terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.98.0"
    }
  }
}

provider "aws" {
  region = "us-east-2"
}

resource "aws_s3_bucket" "example" {
  bucket = "my-tf-test-bucket"
}

resource "aws_s3_bucket_policy" "allow_public_access" {
  bucket = "my-tf-test-bucket"
  policy = data.aws_iam_policy_document.allow_access_from_another_account.json
}

data "aws_iam_policy_document" "allow_access_from_another_account" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::my-tf-test-bucket"
    ]
  }
}

resource "aws_s3_bucket" "private_bucket" {
  bucket = "my-private-test-bucket"
}

resource "aws_s3_bucket_policy" "no_public_access_bucket" {
  bucket = "my-private-test-bucket"
  policy = data.aws_iam_policy_document.no_public_access_bucket_policy.json
}

data "aws_iam_policy_document" "no_public_access_bucket_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["123456789012"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::my-private-test-bucket"
    ]
  }
}

resource "aws_sns_topic" "test" {
  name = "my-topic-with-policy"
}

resource "aws_sns_topic_policy" "default" {
  arn = "arn:aws:sns:us-east-2:123456789012:my-topic-with-policy"

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      "arn:aws:sns:us-east-2:123456789012:my-topic-with-policy"
    ]

    sid = "__default_statement_ID"
  }
}

resource "aws_iam_role" "test_role" {
  name = "test_role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "*"
        }
      },
    ]
  })

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_opensearch_domain" "example" {
  domain_name    = "tf-test"
  engine_version = "OpenSearch_1.1"
}

data "aws_iam_policy_document" "opensearch" {
  statement {
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["es:*"]
    resources = ["*"]
  }
}

resource "aws_opensearch_domain_policy" "main" {
  domain_name     = aws_opensearch_domain.example.domain_name
  access_policies = data.aws_iam_policy_document.opensearch.json
}

resource "aws_s3tables_table_bucket" "example" {
  name = "example-bucket"
}

data "aws_iam_policy_document" "aws_s3tables_table_bucket_policy_example" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = ["*"]
  }
}

resource "aws_s3tables_table_bucket_policy" "example" {
  resource_policy  = data.aws_iam_policy_document.aws_s3tables_table_bucket_policy_example.json
  table_bucket_arn = "arn:aws:s3tables:us-east-2:123456789012:bucket/example-bucket"
}

resource "aws_api_gateway_rest_api" "test" {
  name = "example-rest-api"
}

data "aws_iam_policy_document" "rest_api_test" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["execute-api:Invoke"]
    resources = ["arn:aws:execute-api:us-east-2:123456789012:*/*"]

    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = ["10.23.166.155/32"]
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "test" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  policy      = data.aws_iam_policy_document.rest_api_test.json
}


resource "aws_codeartifact_domain" "example" {
  domain         = "example"
}

data "aws_iam_policy_document" "aws_codeartifact_domain_test" {
  statement {
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["codeartifact:CreateRepository"]
    resources = ["arn:aws:codeartifact:us-east-2:123456789012:domain/*"]
  }
}
resource "aws_codeartifact_domain_permissions_policy" "test" {
  domain          = aws_codeartifact_domain.example.domain
  policy_document = data.aws_iam_policy_document.aws_codeartifact_domain_test.json
}

resource "aws_backup_vault" "example" {
  name = "example"
}

data "aws_iam_policy_document" "aws_backup_vault_example" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "backup:DescribeBackupVault",
      "backup:DeleteBackupVault",
      "backup:PutBackupVaultAccessPolicy",
      "backup:DeleteBackupVaultAccessPolicy",
      "backup:GetBackupVaultAccessPolicy",
      "backup:StartBackupJob",
      "backup:GetBackupVaultNotifications",
      "backup:PutBackupVaultNotifications"
    ]

    resources = ["arn:aws:backup:us-east-1:123456789012:backup-vault:example"]
  }
}

resource "aws_backup_vault_policy" "example" {
  backup_vault_name = aws_backup_vault.example.name
  policy            = data.aws_iam_policy_document.aws_backup_vault_example.json
}

resource "aws_s3tables_table_policy" "example" {
  resource_policy  = data.aws_iam_policy_document.aws_s3tables_table_policy_example.json
  name             = aws_s3tables_table.test.name
  namespace        = aws_s3tables_table.test.namespace
  table_bucket_arn = aws_s3tables_table.test.table_bucket_arn
}

data "aws_iam_policy_document" "aws_s3tables_table_policy_example" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3tables:DeleteTable",
      "s3tables:UpdateTableMetadataLocation",
      "s3tables:PutTableData",
      "s3tables:GetTableMetadataLocation"
    ]

    resources = ["arn:aws:s3tables:us-east-1:123456789012:bucket/example-bucket/table/*"]
  }
}

resource "aws_s3tables_table" "test" {
  name             = "test_table"
  namespace        = aws_s3tables_namespace.example_namespace.namespace
  table_bucket_arn = aws_s3tables_namespace.example_namespace.table_bucket_arn
  format           = "ICEBERG"
}

resource "aws_s3tables_namespace" "example_namespace" {
  namespace        = "example_namespace"
  table_bucket_arn = "arn:aws:s3tables:us-east-2:123456789012:bucket/example-bucket"
}
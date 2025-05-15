terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

resource "aws_organizations_policy" "demo_scp" {
  name        = "demo-scp"
  description = "This is a demo Service Control Policy"
  content     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptList",
      "Effect": "Deny",
      "NotAction": [
        "organizations:List*",
        "organizations:Describe*"
      ],
      "NotResource": "*"
    }
  ]
}
POLICY
  type        = "SERVICE_CONTROL_POLICY"
}
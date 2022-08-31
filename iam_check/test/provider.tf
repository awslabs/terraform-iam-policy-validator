## Specifies the Region your Terraform Provider will create resources
provider "aws" {
  region = "us-east-1"
}

terraform {
    backend "s3" {
      encrypt = true
      bucket = "123456789012-statefile"
      key = "iam305_demo_terraform_templates/dev/terraform.tfstate"
      region = "us-east-1"
  }
}
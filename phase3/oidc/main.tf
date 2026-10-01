terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_oidc_trust" {
  statement {
    sid     = "GitHubActionsOIDC"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [var.github_oidc_subject]
    }
  }
}

resource "aws_iam_role" "drift_remediation" {
  name               = "GitHubActions-Terraform-DriftRemediation"
  assume_role_policy = data.aws_iam_policy_document.github_oidc_trust.json

  description = "Phase 3 GitHub Actions OIDC role for gated Terraform drift remediation."
}

data "aws_iam_policy_document" "drift_remediation" {
  statement {
    sid       = "ReadTerraformStateBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [var.terraform_state_bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["drift-demo/*"]
    }
  }

  statement {
    sid    = "ManageTerraformStateObject"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]

    resources = [
      "${var.terraform_state_bucket_arn}/drift-demo/terraform.tfstate"
    ]
  }

  statement {
    sid       = "DescribeSSMParameters"
    effect    = "Allow"
    actions   = ["ssm:DescribeParameters"]
    resources = ["*"]
  }

  statement {
    sid    = "ReadDriftDemoParameter"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:ListTagsForResource"
    ]

    resources = [var.drift_parameter_arn]
  }

  statement {
    sid    = "RemediateDriftDemoParameter"
    effect = "Allow"

    actions = [
      "ssm:PutParameter",
      "ssm:AddTagsToResource",
      "ssm:RemoveTagsFromResource"
    ]

    resources = [var.drift_parameter_arn]
  }
}

resource "aws_iam_role_policy" "drift_remediation" {
  name   = "Phase3TerraformDriftRemediation"
  role   = aws_iam_role.drift_remediation.name
  policy = data.aws_iam_policy_document.drift_remediation.json
}

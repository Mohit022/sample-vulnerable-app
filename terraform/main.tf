# Security-hardened Terraform configuration
# FIX (CWE-284):  Removed public-read ACL; added S3 Block Public Access
# FIX (CWE-269):  Replaced wildcard IAM Action/Resource with least-privilege policy
# FIX (CWE-923):  Restricted security group ingress — no more 0.0.0.0/0 all-ports
# FIX (CWE-1357): Added lifecycle prevent_destroy on S3 bucket

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "allowed_cidr" {
  description = "CIDR block allowed to reach the application (e.g. corporate VPN)"
  type        = string
}

# -----------------------------------------------------------------------
# S3 Bucket — FIX (CWE-284, CWE-1357)
# -----------------------------------------------------------------------
resource "aws_s3_bucket" "app_bucket" {
  bucket = "sample-app-terraform-bucket-12345"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "app_bucket_public_access" {
  bucket = aws_s3_bucket.app_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_sse" {
  bucket = aws_s3_bucket.app_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "app_bucket_versioning" {
  bucket = aws_s3_bucket.app_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# -----------------------------------------------------------------------
# IAM Policy — FIX (CWE-269): Least-privilege, no wildcard Action/Resource
# -----------------------------------------------------------------------
resource "aws_iam_policy" "app_policy" {
  name        = "app-least-privilege"
  description = "Least-privilege policy for sample-app instances"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:us-east-1:*:log-group:/app/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:us-east-1:*:secret:sample-app/*"
      }
    ]
  })
}

# -----------------------------------------------------------------------
# Security Group — FIX (CWE-923): Restrict ingress; no all-ports 0.0.0.0/0
# -----------------------------------------------------------------------
resource "aws_security_group" "app_sg" {
  name        = "app-restricted-sg"
  description = "Security group with restricted access"

  ingress {
    description = "App port from known CIDR"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  ingress {
    description = "SSH from known CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP outbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

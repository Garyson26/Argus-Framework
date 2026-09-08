"""
Test configuration for Argus.
"""

import pytest


@pytest.fixture
def sample_secret_content():
    """Sample content with various secrets for testing."""
    return '''
# Test file with secrets
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789"

# Slack webhook
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Database URL
DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"

# Private key
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyX...
-----END RSA PRIVATE KEY-----

# JWT Token
API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
'''


@pytest.fixture
def sample_terraform_content():
    """Sample Terraform content with security issues."""
    return '''
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_sg" {
  name = "allow_all"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "public_rds" {
  identifier           = "my-database"
  publicly_accessible  = true
  storage_encrypted    = false
}
'''


@pytest.fixture
def sample_cloudformation_content():
    """Sample CloudFormation content with security issues."""
    return '''
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-public-bucket
      AccessControl: PublicReadWrite
      
  OpenSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow all traffic
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 0
          ToPort: 65535
          CidrIp: 0.0.0.0/0
'''


@pytest.fixture
def mock_s3_buckets():
    """Mock S3 bucket data for testing."""
    return [
        {
            "Name": "secure-bucket",
            "CreationDate": "2024-01-01T00:00:00Z",
        },
        {
            "Name": "public-bucket",
            "CreationDate": "2024-01-02T00:00:00Z",
        },
    ]


@pytest.fixture
def mock_iam_users():
    """Mock IAM user data for testing."""
    return [
        {
            "UserName": "admin-user",
            "Arn": "arn:aws:iam::123456789012:user/admin-user",
            "CreateDate": "2024-01-01T00:00:00Z",
        },
        {
            "UserName": "service-user",
            "Arn": "arn:aws:iam::123456789012:user/service-user",
            "CreateDate": "2024-01-02T00:00:00Z",
        },
    ]


@pytest.fixture
def mock_overly_permissive_policy():
    """Mock overly permissive IAM policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }


@pytest.fixture
def mock_escalation_policy():
    """Mock policy with privilege escalation risk."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:AttachUserPolicy",
                    "iam:PassRole"
                ],
                "Resource": "*"
            }
        ]
    }

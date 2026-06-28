locals {

  fake_findings = merge(

    {
      for i in range(1, 151) :
      "wildcard-${i}" => {
        resource_name = "FinanceAdminRole-${i}"
        severity      = "CRITICAL"
        finding_type  = "WildcardAdmin"
        message       = "Action=* Resource=* grants unrestricted administrative access"
      }
    },

    {
      for i in range(1, 201) :
      "passrole-${i}" => {
        resource_name = "GitHubActionsRole-${i}"
        severity      = "HIGH"
        finding_type  = "PassRoleRisk"
        message       = "iam:PassRole permission may allow privilege escalation"
      }
    },

    {
      for i in range(1, 101) :
      "roottrust-${i}" => {
        resource_name = "CrossAccountRole-${i}"
        severity      = "HIGH"
        finding_type  = "RootTrust"
        message       = "Role trust policy allows AWS account root principal"
      }
    },

    {
      for i in range(1, 151) :
      "federated-${i}" => {
        resource_name = "OktaFederatedRole-${i}"
        severity      = "MEDIUM"
        finding_type  = "FederatedTrust"
        message       = "Federated identity provider configured without restrictive conditions"
      }
    },

    {
      for i in range(1, 151) :
      "adminpolicy-${i}" => {
        resource_name = "OperationsAdminRole-${i}"
        severity      = "CRITICAL"
        finding_type  = "AdminPolicy"
        message       = "AdministratorAccess policy attached"
      }
    },

    {
      for i in range(1, 101) :
      "unused-${i}" => {
        resource_name = "LegacyDeveloperRole-${i}"
        severity      = "LOW"
        finding_type  = "UnusedPermissions"
        message       = "Permissions unused for more than 90 days"
      }
    },

    {
      for i in range(1, 76) :
      "accesskey-${i}" => {
        resource_name = "IAMUser-${i}"
        severity      = "MEDIUM"
        finding_type  = "AccessKeyStale"
        message       = "Access key age exceeds 180 days"
      }
    },

    {
      for i in range(1, 76) :
      "privesc-${i}" => {
        resource_name = "LambdaExecutionRole-${i}"
        severity      = "HIGH"
        finding_type  = "PrivilegeEscalation"
        message       = "Role contains privilege escalation attack path"
      }
    },

    #############################
    # EC2
    #############################

    {
      for i in range(1, 101) :
      "ec2-public-${i}" => {
        resource_name = "i-public-${i}"
        severity      = "HIGH"
        finding_type  = "PublicInstance"
        message       = "EC2 instance has public IP and unrestricted SSH access."
      }
    },

    {
      for i in range(1, 81) :
      "ec2-imdsv1-${i}" => {
        resource_name = "i-imdsv1-${i}"
        severity      = "MEDIUM"
        finding_type  = "IMDSv1Enabled"
        message       = "Instance Metadata Service v1 is enabled."
      }
    },

    #############################
    # S3
    #############################

    {
      for i in range(1, 101) :
      "s3-public-${i}" => {
        resource_name = "public-bucket-${i}"
        severity      = "CRITICAL"
        finding_type  = "PublicBucket"
        message       = "Bucket allows anonymous public access."
      }
    },

    {
      for i in range(1, 81) :
      "s3-encryption-${i}" => {
        resource_name = "bucket-${i}"
        severity      = "HIGH"
        finding_type  = "EncryptionDisabled"
        message       = "Default bucket encryption is disabled."
      }
    },

    #############################
    # VPC
    #############################

    {
      for i in range(1, 81) :
      "vpc-open-${i}" => {
        resource_name = "sg-${i}"
        severity      = "HIGH"
        finding_type  = "OpenSecurityGroup"
        message       = "Security group exposes 0.0.0.0/0."
      }
    },

    #############################
    # RDS
    #############################

    {
      for i in range(1, 61) :
      "rds-public-${i}" => {
        resource_name = "rds-${i}"
        severity      = "HIGH"
        finding_type  = "PublicRDS"
        message       = "RDS instance is publicly accessible."
      }
    },

    #############################
    # EKS
    #############################

    {
      for i in range(1, 61) :
      "eks-public-${i}" => {
        resource_name = "eks-${i}"
        severity      = "HIGH"
        finding_type  = "PublicEndpoint"
        message       = "EKS API endpoint is publicly accessible."
      }
    },

    #############################
    # CloudTrail
    #############################

    {
      for i in range(1, 31) :
      "ct-disabled-${i}" => {
        resource_name = "trail-${i}"
        severity      = "CRITICAL"
        finding_type  = "CloudTrailDisabled"
        message       = "CloudTrail logging is disabled."
      }
    },

    #############################
    # Root Monitor
    #############################

    {
      for i in range(1, 26) :
      "root-login-${i}" => {
        resource_name = "RootAccount"
        severity      = "CRITICAL"
        finding_type  = "RootConsoleLogin"
        message       = "Root user logged into AWS console."
      }
    },

    #############################
    # Access Keys
    #############################

    {
      for i in range(1, 76) :
      "accesskey-${i}" => {
        resource_name = "IAMUser-${i}"
        severity      = "MEDIUM"
        finding_type  = "AccessKeyStale"
        message       = "Access key is older than 180 days."
      }
    },

    #############################
    # Privilege Escalation
    #############################

    {
      for i in range(1, 76) :
      "privesc-${i}" => {
        resource_name = "LambdaRole-${i}"
        severity      = "CRITICAL"
        finding_type  = "PrivilegeEscalation"
        message       = "Role contains privilege escalation path."
      }
    },

    #############################
    # Trust Analyzer
    #############################

    {
      for i in range(1, 81) :
      "trust-${i}" => {
        resource_name = "CrossAccountRole-${i}"
        severity      = "HIGH"
        finding_type  = "CrossAccountTrust"
        message       = "Role trusts another AWS account."
      }
    },

    #############################
    # Risk Analyzer
    #############################

    {
      for i in range(1, 151) :
      "risk-${i}" => {
        resource_name = "CriticalAsset-${i}"
        severity      = "CRITICAL"
        finding_type  = "HighRiskResource"
        message       = "Composite risk score exceeds threshold."
      }
    }

  )
}

resource "aws_dynamodb_table_item" "seed_findings" {
  for_each = local.fake_findings

  table_name = aws_dynamodb_table.findings.name
  hash_key   = "resource_id"
  range_key  = "finding_type"

  item = jsonencode({
    resource_id = {
      S = each.key
    }

    finding_type = {
      S = each.value.finding_type
    }

    resource_name = {
      S = each.value.resource_name
    }

    severity = {
      S = each.value.severity
    }

    message = {
      S = each.value.message
    }

    detected_at = {
      S = "2026-06-18T00:00:00Z"
    }
  })
}

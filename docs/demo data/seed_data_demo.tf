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
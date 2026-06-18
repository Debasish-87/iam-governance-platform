resource "aws_cloudwatch_dashboard" "iam_governance" {

dashboard_name = "IAM-Governance"

dashboard_body = jsonencode({


widgets = [

  # --------------------------------------------------
  # HEADER
  # --------------------------------------------------

  {
    type   = "text"
    x      = 0
    y      = 0
    width  = 24
    height = 2

    properties = {
      markdown = "# IAM Governance Security Operations Dashboard"
    }
  },

  # --------------------------------------------------
  # EXECUTIVE KPIs
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 0
    y      = 2
    width  = 4
    height = 6

    properties = {
      title  = "Security Score"
      view   = "singleValue"
      region = "ap-south-1"
      stat   = "Maximum"

      metrics = [
        ["IAMGovernance","SecurityScore"]
      ]
    }
  },

  {
    type   = "metric"
    x      = 4
    y      = 2
    width  = 5
    height = 6

    properties = {
      title  = "Total Findings"
      view   = "singleValue"
      region = "ap-south-1"
      stat   = "Maximum"

      metrics = [
        ["IAMGovernance","TotalFindings"]
      ]
    }
  },

  {
    type   = "metric"
    x      = 9
    y      = 2
    width  = 5
    height = 6

    properties = {
      title  = "Critical Findings"
      view   = "singleValue"
      region = "ap-south-1"
      stat   = "Maximum"

      metrics = [
        ["IAMGovernance","CriticalFindings"]
      ]
    }
  },

  {
    type   = "metric"
    x      = 14
    y      = 2
    width  = 5
    height = 6

    properties = {
      title  = "High Findings"
      view   = "singleValue"
      region = "ap-south-1"
      stat   = "Maximum"

      metrics = [
        ["IAMGovernance","HighFindings"]
      ]
    }
  },

  {
    type   = "metric"
    x      = 19
    y      = 2
    width  = 5
    height = 6

    properties = {
      title  = "Medium Findings"
      view   = "singleValue"
      region = "ap-south-1"
      stat   = "Maximum"

      metrics = [
        ["IAMGovernance","MediumFindings"]
      ]
    }
  },

  # --------------------------------------------------
  # SECURITY SCORE TREND
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 0
    y      = 9
    width  = 12
    height = 8

    properties = {
      title  = "Security Score Trend"
      region = "ap-south-1"
      view   = "timeSeries"

      metrics = [
        ["IAMGovernance","SecurityScore"]
      ]
    }
  },

  # --------------------------------------------------
  # FINDINGS GROWTH
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 12
    y      = 9
    width  = 12
    height = 8

    properties = {
      title  = "Findings Growth Rate"
      region = "ap-south-1"
      view   = "timeSeries"

      metrics = [
        ["IAMGovernance","TotalFindings"]
      ]
    }
  },

  # --------------------------------------------------
  # SEVERITY DISTRIBUTION
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 0
    y      = 18
    width  = 24
    height = 8

    properties = {
      title  = "Severity Distribution"

      region = "ap-south-1"
      view   = "bar"

      metrics = [
        ["IAMGovernance","CriticalFindings"],
        ["IAMGovernance","HighFindings"],
        ["IAMGovernance","MediumFindings"],
        ["IAMGovernance","LowFindings"]
      ]
    }
  },

  # --------------------------------------------------
  # PRIVILEGE ESCALATION RISKS
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 0
    y      = 27
    width  = 12
    height = 8

    properties = {
      title  = "Privilege Escalation Risks"

      region = "ap-south-1"
      view   = "pie"

      metrics = [
        ["IAMGovernance","PassRoleCount"],
        ["IAMGovernance","AdminPolicyCount"],
        ["IAMGovernance","WildcardAdminCount"]
      ]
    }
  },

  # --------------------------------------------------
  # TRUST POLICY RISKS
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 12
    y      = 27
    width  = 12
    height = 8

    properties = {
      title  = "Trust Policy Risks"

      region = "ap-south-1"
      view   = "pie"

      metrics = [
        ["IAMGovernance","RootTrustCount"],
        ["IAMGovernance","FederatedTrustCount"]
      ]
    }
  },

  # --------------------------------------------------
  # IAM ATTACK SURFACE
  # --------------------------------------------------

  {
    type   = "metric"
    x      = 0
    y      = 36
    width  = 24
    height = 8

    properties = {
      title  = "IAM Attack Surface"

      region = "ap-south-1"
      view   = "bar"

      metrics = [
        ["IAMGovernance","WildcardAdminCount"],
        ["IAMGovernance","PassRoleCount"],
        ["IAMGovernance","RootTrustCount"],
        ["IAMGovernance","FederatedTrustCount"],
        ["IAMGovernance","AdminPolicyCount"]
      ]
    }
  }
]


})
}


resource "aws_cloudwatch_event_rule" "report_every_2min" {

  name                = "iam-governance-2min"
  schedule_expression = "rate(2 minutes)"
}

resource "aws_cloudwatch_event_target" "report_target" {

  rule = aws_cloudwatch_event_rule.report_every_2min.name
  arn  = aws_lambda_function.report_generator.arn
}

resource "aws_lambda_permission" "allow_eventbridge_report" {

  statement_id  = "Allow2MinReport"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report_generator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.report_every_2min.arn
}


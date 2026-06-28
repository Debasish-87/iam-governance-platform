##########################################
# Privilege Escalation Scanner
##########################################

resource "aws_lambda_function" "privilege_escalation" {

  function_name = "csp-privilege-escalation"

  filename         = "${path.module}/../artifacts/privilege-escalation.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/privilege-escalation.zip")

  role    = aws_iam_role.lambda_role.arn
  handler = "bootstrap"
  runtime = "provided.al2023"

  timeout     = 300
  memory_size = 256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Project = "CSP"
    Service = "IAM"
  }
}

##########################################
# EventBridge Schedule
##########################################

resource "aws_cloudwatch_event_rule" "privilege_escalation_schedule" {

  name = "csp-privilege-escalation"

  description = "Run Privilege Escalation Scanner"

  schedule_expression = "rate(6 hours)"
}

##########################################
# Event Target
##########################################

resource "aws_cloudwatch_event_target" "privilege_escalation_target" {

  rule = aws_cloudwatch_event_rule.privilege_escalation_schedule.name

  arn = aws_lambda_function.privilege_escalation.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_privilege_escalation" {

  statement_id = "AllowExecutionFromEventBridgePrivilegeEscalation"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.privilege_escalation.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.privilege_escalation_schedule.arn
}

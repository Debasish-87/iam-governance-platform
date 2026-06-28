##########################################
# IAM Access Key Audit Lambda
##########################################

resource "aws_lambda_function" "access_key_audit" {

  function_name = "csp-access-key-audit"

  filename         = "${path.module}/../artifacts/access-key-audit.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/access-key-audit.zip")

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

resource "aws_cloudwatch_event_rule" "access_key_audit_schedule" {

  name = "csp-access-key-audit"

  description = "Run IAM Access Key Audit"

  schedule_expression = "rate(6 hours)"
}

##########################################
# Event Target
##########################################

resource "aws_cloudwatch_event_target" "access_key_audit_target" {

  rule = aws_cloudwatch_event_rule.access_key_audit_schedule.name

  arn = aws_lambda_function.access_key_audit.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_access_key_audit" {

  statement_id = "AllowExecutionFromEventBridgeAccessKeyAudit"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.access_key_audit.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.access_key_audit_schedule.arn
}
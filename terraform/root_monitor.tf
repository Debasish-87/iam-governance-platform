##########################################
# Root Monitor Lambda
##########################################

resource "aws_lambda_function" "root_monitor" {

  function_name = "csp-root-monitor"

  filename         = "${path.module}/../artifacts/root-monitor.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/root-monitor.zip")

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

resource "aws_cloudwatch_event_rule" "root_monitor_schedule" {

  name = "csp-root-monitor"

  description = "Run Root Activity Monitor"

  schedule_expression = "rate(6 hours)"
}

##########################################
# Event Target
##########################################

resource "aws_cloudwatch_event_target" "root_monitor_target" {

  rule = aws_cloudwatch_event_rule.root_monitor_schedule.name

  arn = aws_lambda_function.root_monitor.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_root_monitor" {

  statement_id = "AllowExecutionFromEventBridgeRootMonitor"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.root_monitor.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.root_monitor_schedule.arn
}

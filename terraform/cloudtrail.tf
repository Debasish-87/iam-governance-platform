##########################################
# CloudTrail Security Scanner Lambda
##########################################

resource "aws_lambda_function" "cloudtrail_scanner" {

  function_name = "csp-cloudtrail-scanner"

  filename         = "${path.module}/../artifacts/cloudtrail-scanner.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/cloudtrail-scanner.zip")

  role    = aws_iam_role.lambda_role.arn
  handler = "bootstrap"
  runtime = "provided.al2023"

  timeout     = 120
  memory_size = 256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Project = "CSP"
    Service = "CloudTrail"
  }
}

##########################################
# EventBridge Schedule
##########################################

resource "aws_cloudwatch_event_rule" "cloudtrail_scan_schedule" {

  name = "csp-cloudtrail-scan"

  description = "Run CloudTrail Security Scanner"

  schedule_expression = "rate(6 hours)"
}

##########################################
# EventBridge Target
##########################################

resource "aws_cloudwatch_event_target" "cloudtrail_scan_target" {

  rule = aws_cloudwatch_event_rule.cloudtrail_scan_schedule.name

  arn = aws_lambda_function.cloudtrail_scanner.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_cloudtrail" {

  statement_id = "AllowExecutionFromEventBridgeCloudTrail"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.cloudtrail_scanner.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.cloudtrail_scan_schedule.arn
}
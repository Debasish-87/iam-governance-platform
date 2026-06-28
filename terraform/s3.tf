##########################################
# S3 Security Scanner Lambda
##########################################

resource "aws_lambda_function" "s3_scanner" {

  function_name = "csp-s3-scanner"

  filename         = "${path.module}/../artifacts/s3-scanner.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/s3-scanner.zip")

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
    Service = "S3"
  }
}

##########################################
# EventBridge Schedule
##########################################

resource "aws_cloudwatch_event_rule" "s3_scan_schedule" {

  name = "csp-s3-scan"

  description = "Run S3 Security Scanner"

  schedule_expression = "rate(6 hours)"
}

##########################################
# EventBridge Target
##########################################

resource "aws_cloudwatch_event_target" "s3_scan_target" {

  rule = aws_cloudwatch_event_rule.s3_scan_schedule.name

  arn = aws_lambda_function.s3_scanner.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_s3" {

  statement_id = "AllowExecutionFromEventBridgeS3"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.s3_scanner.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.s3_scan_schedule.arn
}
##########################################
# EC2 Security Scanner Lambda
##########################################

resource "aws_lambda_function" "ec2_scanner" {

  function_name = "csp-ec2-scanner"

  filename         = "${path.module}/../artifacts/ec2-scanner.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/ec2-scanner.zip")

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
    Service = "EC2"
  }
}

##########################################
# EventBridge Schedule
##########################################

resource "aws_cloudwatch_event_rule" "ec2_scan_schedule" {

  name = "csp-ec2-scan"

  description = "Run EC2 Security Scanner"

  schedule_expression = "rate(6 hours)"
}

##########################################
# Event Target
##########################################

resource "aws_cloudwatch_event_target" "ec2_scan_target" {

  rule = aws_cloudwatch_event_rule.ec2_scan_schedule.name

  arn = aws_lambda_function.ec2_scanner.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_ec2" {

  statement_id = "AllowExecutionFromEventBridgeEC2"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.ec2_scanner.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.ec2_scan_schedule.arn
}

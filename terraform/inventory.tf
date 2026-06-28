##########################################
# IAM Inventory Lambda
##########################################

resource "aws_lambda_function" "inventory" {

  function_name = "csp-iam-inventory"

  filename         = "${path.module}/../artifacts/inventory.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/inventory.zip")

  role    = aws_iam_role.lambda_role.arn
  handler = "bootstrap"
  runtime = "provided.al2023"

  timeout     = 300
  memory_size = 256

  tags = {
    Project = "CSP"
    Service = "IAM"
  }
}

##########################################
# EventBridge Schedule
##########################################

resource "aws_cloudwatch_event_rule" "inventory_schedule" {

  name = "csp-iam-inventory"

  description = "Run IAM Inventory"

  schedule_expression = "rate(12 hours)"
}

##########################################
# Event Target
##########################################

resource "aws_cloudwatch_event_target" "inventory_target" {

  rule = aws_cloudwatch_event_rule.inventory_schedule.name

  arn = aws_lambda_function.inventory.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_inventory" {

  statement_id = "AllowExecutionFromEventBridgeInventory"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.inventory.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.inventory_schedule.arn
}
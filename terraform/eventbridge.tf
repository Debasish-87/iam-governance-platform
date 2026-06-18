resource "aws_cloudwatch_event_rule" "daily_report" {

  name = "iam-governance-daily-report"

  description = "Runs report generator every day"

  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "daily_report_target" {

  rule = aws_cloudwatch_event_rule.daily_report.name

  arn = aws_lambda_function.report_generator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {

  statement_id = "AllowExecutionFromEventBridge"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.report_generator.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.daily_report.arn
}

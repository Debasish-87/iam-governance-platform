resource "aws_lambda_function" "risk_analyzer" {

  function_name = "risk-analyzer"

  role = aws_iam_role.lambda_role.arn

  runtime = "provided.al2023"

  handler = "bootstrap"

  filename = "../lambda/scanners/iam/risk_analyzer/risk_analyzer.zip"

  source_code_hash = filebase64sha256(
    "../lambda/scanners/iam/risk_analyzer/risk_analyzer.zip"
  )

  timeout = 60

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }
}

resource "aws_lambda_permission" "allow_eventbridge_risk" {

  statement_id = "AllowEventBridgeRiskAnalyzer"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.risk_analyzer.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.daily_report.arn
}

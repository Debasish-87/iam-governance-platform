resource "aws_lambda_function" "trust_analyzer" {

  function_name = "trust-analyzer"

  role = aws_iam_role.lambda_role.arn

  runtime = "provided.al2023"

  handler = "bootstrap"

  filename = "../lambda/trust_analyzer/trust_analyzer.zip"

  source_code_hash = filebase64sha256(
    "../lambda/trust_analyzer/trust_analyzer.zip"
  )

  timeout = 60
}
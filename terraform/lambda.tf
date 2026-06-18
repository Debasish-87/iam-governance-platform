resource "aws_iam_role" "lambda_role" {

  name = "iam-governance-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"

      Principal = {
        Service = "lambda.amazonaws.com"
      }

      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {

  role = aws_iam_role.lambda_role.name

  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "report_generator" {

  function_name = "report-generator"

  role = aws_iam_role.lambda_role.arn

  runtime = "provided.al2023"

  handler = "bootstrap"

  filename = "../lambda/report_generator/report_generator.zip"

  source_code_hash = filebase64sha256(
    "../lambda/report_generator/report_generator.zip"
  )

  timeout = 30
}


resource "aws_iam_role_policy" "lambda_dynamodb_access" {

  name = "lambda-dynamodb-access"

  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]

        Resource = [
          aws_dynamodb_table.findings.arn
        ]
      }
    ]
  })
}


resource "aws_iam_role_policy" "lambda_sns_access" {

  name = "lambda-sns-access"

  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Action = [
          "sns:Publish"
        ]

        Resource = "*"
      },

      {
        Effect = "Allow"

        Action = [
          "dynamodb:Scan"
        ]

        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "sns_alerts" {

  function_name = "sns-alerts"

  role = aws_iam_role.lambda_role.arn

  runtime = "provided.al2023"

  handler = "bootstrap"

  filename = "../lambda/sns_alerts/sns_alerts.zip"

  source_code_hash = filebase64sha256(
    "../lambda/sns_alerts/sns_alerts.zip"
  )

  timeout = 60
}



##########################################
# EKS Security Scanner Lambda
##########################################

resource "aws_lambda_function" "eks_scanner" {

  function_name = "csp-eks-scanner"

  filename         = "${path.module}/../artifacts/eks-scanner.zip"
  source_code_hash = filebase64sha256("${path.module}/../artifacts/eks-scanner.zip")

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
    Service = "EKS"
  }
}

##########################################
# EventBridge Schedule
##########################################

resource "aws_cloudwatch_event_rule" "eks_scan_schedule" {

  name = "csp-eks-scan"

  description = "Run EKS Security Scanner"

  schedule_expression = "rate(6 hours)"
}

##########################################
# EventBridge Target
##########################################

resource "aws_cloudwatch_event_target" "eks_scan_target" {

  rule = aws_cloudwatch_event_rule.eks_scan_schedule.name

  arn = aws_lambda_function.eks_scanner.arn
}

##########################################
# Lambda Permission
##########################################

resource "aws_lambda_permission" "allow_eventbridge_eks" {

  statement_id = "AllowExecutionFromEventBridgeEKS"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.eks_scanner.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.eks_scan_schedule.arn
}
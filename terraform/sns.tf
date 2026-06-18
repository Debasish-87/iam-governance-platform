resource "aws_sns_topic" "alerts" {
  name = "iam-security-alerts"

  tags = {
    Project = var.project_name
  }
}

resource "aws_sns_topic" "iam_alerts" {
  name = "iam-governance-alerts"
}


resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.iam_alerts.arn
  protocol  = "email"
  endpoint  = "debasishm8765@gmail.com"
}


resource "aws_dynamodb_table" "findings" {
  name         = "iam-security-findings"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "resource_id"
  range_key = "finding_type"

  attribute {
    name = "resource_id"
    type = "S"
  }

  attribute {
    name = "finding_type"
    type = "S"
  }

  tags = {
    Project = var.project_name
  }
}
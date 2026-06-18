package main

type Finding struct {
	ResourceID   string `dynamodbav:"resource_id"`
	ResourceName string `dynamodbav:"resource_name"`
	FindingType  string `dynamodbav:"finding_type"`
	Severity     string `dynamodbav:"severity"`
	Message      string `dynamodbav:"message"`
}
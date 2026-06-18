package main

import "time"

type Finding struct {
	ResourceID  string `dynamodbav:"resource_id"`
	FindingType string `dynamodbav:"finding_type"`

	ResourceName string `dynamodbav:"resource_name"`
	Severity     string `dynamodbav:"severity"`

	Message string `dynamodbav:"message"`

	PolicyName string `dynamodbav:"policy_name,omitempty"`

	DetectedAt time.Time `dynamodbav:"detected_at"`
}

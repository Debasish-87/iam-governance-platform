package main

import "time"

type Finding struct {
	ResourceID string `dynamodbav:"resource_id"`

	ResourceType string `dynamodbav:"resource_type"`

	ResourceName string `dynamodbav:"resource_name"`

	Service string `dynamodbav:"service"`

	FindingType string `dynamodbav:"finding_type"`

	Severity string `dynamodbav:"severity"`

	Message string `dynamodbav:"message"`

	Recommendation string `dynamodbav:"recommendation"`

	Region string `dynamodbav:"region"`

	DetectedAt time.Time `dynamodbav:"detected_at"`
}
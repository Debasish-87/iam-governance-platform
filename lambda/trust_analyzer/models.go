package main

import "time"

type Finding struct {
	ResourceID   string    `dynamodbav:"resource_id"`
	FindingType  string    `dynamodbav:"finding_type"`
	ResourceName string    `dynamodbav:"resource_name"`
	Severity     string    `dynamodbav:"severity"`
	Message      string    `dynamodbav:"message"`
	DetectedAt   time.Time `dynamodbav:"detected_at"`
}

type TrustPolicy struct {
	Version   string           `json:"Version"`
	Statement []TrustStatement `json:"Statement"`
}

type TrustStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Principal interface{} `json:"Principal"`
}
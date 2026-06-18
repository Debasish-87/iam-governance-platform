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

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

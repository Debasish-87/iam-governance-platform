package main

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

func AnalyzeTrail(trail types.Trail) []Finding {

	var findings []Finding

	findings = append(findings, checkMultiRegion(trail)...)
	findings = append(findings, checkLogValidation(trail)...)
	findings = append(findings, checkKMSEncryption(trail)...)
	findings = append(findings, checkCloudWatchLogs(trail)...)
	findings = append(findings, checkS3Bucket(trail)...)

	return findings
}

func checkMultiRegion(trail types.Trail) []Finding {

	if trail.IsMultiRegionTrail != nil &&
		*trail.IsMultiRegionTrail {

		return nil
	}

	return []Finding{
		newFinding(
			trail,
			"MultiRegionDisabled",
			"HIGH",
			"CloudTrail is not configured as a multi-region trail.",
			"Enable multi-region CloudTrail.",
		),
	}
}

func checkLogValidation(trail types.Trail) []Finding {

	if trail.LogFileValidationEnabled != nil &&
		*trail.LogFileValidationEnabled {

		return nil
	}

	return []Finding{
		newFinding(
			trail,
			"LogValidationDisabled",
			"MEDIUM",
			"Log file validation is disabled.",
			"Enable CloudTrail log file validation.",
		),
	}
}

func checkKMSEncryption(trail types.Trail) []Finding {

	if trail.KmsKeyId != nil &&
		*trail.KmsKeyId != "" {

		return nil
	}

	return []Finding{
		newFinding(
			trail,
			"KMSEncryptionDisabled",
			"HIGH",
			"CloudTrail logs are not encrypted with AWS KMS.",
			"Configure a KMS key for CloudTrail.",
		),
	}
}

func checkCloudWatchLogs(trail types.Trail) []Finding {

	if trail.CloudWatchLogsLogGroupArn != nil &&
		*trail.CloudWatchLogsLogGroupArn != "" {

		return nil
	}

	return []Finding{
		newFinding(
			trail,
			"CloudWatchLogsDisabled",
			"MEDIUM",
			"CloudTrail is not integrated with CloudWatch Logs.",
			"Enable CloudWatch Logs integration.",
		),
	}
}

func checkS3Bucket(trail types.Trail) []Finding {

	if trail.S3BucketName != nil &&
		*trail.S3BucketName != "" {

		return nil
	}

	return []Finding{
		newFinding(
			trail,
			"S3BucketMissing",
			"CRITICAL",
			"No S3 bucket is configured for CloudTrail logs.",
			"Configure an S3 bucket for CloudTrail.",
		),
	}
}

func newFinding(
	trail types.Trail,
	findingType string,
	severity string,
	message string,
	recommendation string,
) Finding {

	name := ""
	if trail.Name != nil {
		name = *trail.Name
	}

	homeRegion := ""
	if trail.HomeRegion != nil {
		homeRegion = *trail.HomeRegion
	}

	return Finding{
		ResourceID:     name,
		ResourceType:   "CloudTrail",
		ResourceName:   name,
		Service:        "CloudTrail",
		FindingType:    findingType,
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
		Region:         homeRegion,
		DetectedAt:     time.Now(),
	}
}
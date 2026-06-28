package main

import "time"

type BucketMetadata struct {
	Name              string
	Region            string
	Encrypted         bool
	VersioningEnabled bool
	PublicAccessBlock bool
	LoggingEnabled    bool
}

func AnalyzeBucket(bucket BucketMetadata) []Finding {

	var findings []Finding

	findings = append(findings, checkEncryption(bucket)...)
	findings = append(findings, checkVersioning(bucket)...)
	findings = append(findings, checkPublicAccessBlock(bucket)...)
	findings = append(findings, checkLogging(bucket)...)

	return findings
}

func checkEncryption(bucket BucketMetadata) []Finding {

	if bucket.Encrypted {
		return nil
	}

	return []Finding{
		newFinding(
			bucket,
			"EncryptionDisabled",
			"HIGH",
			"Bucket encryption is disabled.",
			"Enable SSE-S3 or SSE-KMS encryption.",
		),
	}
}

func checkVersioning(bucket BucketMetadata) []Finding {

	if bucket.VersioningEnabled {
		return nil
	}

	return []Finding{
		newFinding(
			bucket,
			"VersioningDisabled",
			"MEDIUM",
			"Bucket versioning is disabled.",
			"Enable bucket versioning.",
		),
	}
}

func checkPublicAccessBlock(bucket BucketMetadata) []Finding {

	if bucket.PublicAccessBlock {
		return nil
	}

	return []Finding{
		newFinding(
			bucket,
			"PublicAccessBlockDisabled",
			"CRITICAL",
			"Public Access Block is disabled.",
			"Enable Block Public Access for this bucket.",
		),
	}
}

func checkLogging(bucket BucketMetadata) []Finding {

	if bucket.LoggingEnabled {
		return nil
	}

	return []Finding{
		newFinding(
			bucket,
			"LoggingDisabled",
			"LOW",
			"Server Access Logging is disabled.",
			"Enable Server Access Logging.",
		),
	}
}

func newFinding(
	bucket BucketMetadata,
	findingType string,
	severity string,
	message string,
	recommendation string,
) Finding {

	return Finding{
		ResourceID:     bucket.Name,
		ResourceType:   "S3",
		ResourceName:   bucket.Name,
		Service:        "S3",
		FindingType:    findingType,
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
		Region:         bucket.Region,
		DetectedAt:     time.Now(),
	}
}

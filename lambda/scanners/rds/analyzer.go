package main

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func AnalyzeDBInstance(db types.DBInstance) []Finding {

	var findings []Finding

	findings = append(findings, checkPublicAccess(db)...)
	findings = append(findings, checkEncryption(db)...)
	findings = append(findings, checkBackupRetention(db)...)
	findings = append(findings, checkDeletionProtection(db)...)
	findings = append(findings, checkMultiAZ(db)...)

	return findings
}

func checkPublicAccess(db types.DBInstance) []Finding {

	if db.PubliclyAccessible == nil || !*db.PubliclyAccessible {
		return nil
	}

	return []Finding{
		newFinding(
			db,
			"PubliclyAccessible",
			"CRITICAL",
			"RDS instance is publicly accessible.",
			"Disable public accessibility unless explicitly required.",
		),
	}
}

func checkEncryption(db types.DBInstance) []Finding {

	if db.StorageEncrypted == nil || *db.StorageEncrypted {
		return nil
	}

	return []Finding{
		newFinding(
			db,
			"EncryptionDisabled",
			"HIGH",
			"Storage encryption is disabled.",
			"Enable RDS storage encryption using AWS KMS.",
		),
	}
}

func checkBackupRetention(db types.DBInstance) []Finding {

	if db.BackupRetentionPeriod == nil || *db.BackupRetentionPeriod > 0 {
		return nil
	}

	return []Finding{
		newFinding(
			db,
			"BackupDisabled",
			"HIGH",
			"Backup retention period is 0 days.",
			"Configure automated backups.",
		),
	}
}

func checkDeletionProtection(db types.DBInstance) []Finding {

	if db.DeletionProtection == nil || *db.DeletionProtection {
		return nil
	}

	return []Finding{
		newFinding(
			db,
			"DeletionProtectionDisabled",
			"MEDIUM",
			"Deletion protection is disabled.",
			"Enable deletion protection.",
		),
	}
}

func checkMultiAZ(db types.DBInstance) []Finding {

	if db.MultiAZ == nil || *db.MultiAZ {
		return nil
	}

	return []Finding{
		newFinding(
			db,
			"MultiAZDisabled",
			"LOW",
			"Multi-AZ deployment is disabled.",
			"Enable Multi-AZ for higher availability.",
		),
	}
}

func newFinding(
	db types.DBInstance,
	findingType string,
	severity string,
	message string,
	recommendation string,
) Finding {

	dbID := ""
	if db.DBInstanceIdentifier != nil {
		dbID = *db.DBInstanceIdentifier
	}

	region := ""
	if db.AvailabilityZone != nil {
		region = *db.AvailabilityZone
	}

	return Finding{
		ResourceID:     dbID,
		ResourceType:   "RDS",
		ResourceName:   dbID,
		Service:        "RDS",
		FindingType:    findingType,
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
		Region:         region,
		DetectedAt:     time.Now(),
	}
}
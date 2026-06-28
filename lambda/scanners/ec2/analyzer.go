package main

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func AnalyzeInstance(instance types.Instance) []Finding {

	var findings []Finding

	findings = append(findings, checkPublicIP(instance)...)
	findings = append(findings, checkIAMRole(instance)...)
	findings = append(findings, checkEncryption(instance)...)
	findings = append(findings, checkIMDS(instance)...)
	findings = append(findings, checkTags(instance)...)
	findings = append(findings, checkStopped(instance)...)

	return findings
}

func checkPublicIP(instance types.Instance) []Finding {

	if instance.PublicIpAddress == nil {
		return nil
	}

	return []Finding{
		newFinding(
			instance,
			"PublicInstance",
			"HIGH",
			"Instance has a public IP address.",
			"Remove the public IP or place the instance behind a Load Balancer.",
		),
	}
}

func checkIAMRole(instance types.Instance) []Finding {

	if instance.IamInstanceProfile != nil {
		return nil
	}

	return []Finding{
		newFinding(
			instance,
			"NoInstanceProfile",
			"MEDIUM",
			"EC2 instance has no IAM Instance Profile attached.",
			"Attach an IAM Role using the principle of least privilege.",
		),
	}
}

func checkEncryption(instance types.Instance) []Finding {

	var findings []Finding

	for _, mapping := range instance.BlockDeviceMappings {

		if mapping.Ebs == nil {
			continue
		}

		if mapping.Ebs.VolumeId == nil {
			continue
		}

		/*
			Future Improvement:

			Call DescribeVolumes()
			and verify whether the EBS volume
			is encrypted.

			Currently skipped because
			DescribeInstances() does not
			return encryption status.
		*/
	}

	return findings
}

func checkIMDS(instance types.Instance) []Finding {

	if instance.MetadataOptions == nil {
		return nil
	}

	if instance.MetadataOptions.HttpTokens ==
		types.HttpTokensStateOptional {

		return []Finding{
			newFinding(
				instance,
				"IMDSv1Enabled",
				"HIGH",
				"IMDSv1 is enabled on this instance.",
				"Require IMDSv2 by setting HttpTokens=required.",
			),
		}
	}

	return nil
}

func checkTags(instance types.Instance) []Finding {

	for _, tag := range instance.Tags {

		if tag.Key != nil &&
			*tag.Key == "Name" {

			return nil
		}
	}

	return []Finding{
		newFinding(
			instance,
			"MissingNameTag",
			"LOW",
			"Instance does not contain a Name tag.",
			"Add a Name tag for easier identification.",
		),
	}
}

func checkStopped(instance types.Instance) []Finding {

	if instance.State == nil {
		return nil
	}

	if instance.State.Name != types.InstanceStateNameStopped {
		return nil
	}

	return []Finding{
		newFinding(
			instance,
			"StoppedInstance",
			"LOW",
			"EC2 instance is stopped.",
			"Remove unused instances or start them if required.",
		),
	}
}

func newFinding(
	instance types.Instance,
	findingType string,
	severity string,
	message string,
	recommendation string,
) Finding {

	instanceID := ""

	if instance.InstanceId != nil {
		instanceID = *instance.InstanceId
	}

	name := instanceID

	for _, tag := range instance.Tags {

		if tag.Key != nil &&
			*tag.Key == "Name" &&
			tag.Value != nil {

			name = *tag.Value
			break
		}
	}

	region := ""

	if instance.Placement.AvailabilityZone != nil {

		az := *instance.Placement.AvailabilityZone

		if len(az) > 1 {
			region = az[:len(az)-1]
		}
	}

	return Finding{
		ResourceID:     instanceID,
		ResourceType:   "EC2",
		ResourceName:   name,
		Service:        "EC2",
		FindingType:    findingType,
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
		Region:         region,
		DetectedAt:     time.Now(),
	}
}

func PrintFinding(f Finding) {

	fmt.Println("----------------------------------------")
	fmt.Printf("Resource       : %s\n", f.ResourceName)
	fmt.Printf("Type           : %s\n", f.FindingType)
	fmt.Printf("Severity       : %s\n", f.Severity)
	fmt.Printf("Message        : %s\n", f.Message)
	fmt.Printf("Recommendation : %s\n", f.Recommendation)
}
package main

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func AnalyzeSecurityGroup(sg types.SecurityGroup) []Finding {

	var findings []Finding

	for _, permission := range sg.IpPermissions {

		findings = append(findings, analyzeIPv4(sg, permission)...)
		findings = append(findings, analyzeIPv6(sg, permission)...)

	}

	return findings
}

func analyzeIPv4(
	sg types.SecurityGroup,
	permission types.IpPermission,
) []Finding {

	var findings []Finding

	for _, ip := range permission.IpRanges {

		if ip.CidrIp == nil {
			continue
		}

		if *ip.CidrIp != "0.0.0.0/0" {
			continue
		}

		findings = append(findings, checkPort(sg, permission)...)

	}

	return findings
}

func analyzeIPv6(
	sg types.SecurityGroup,
	permission types.IpPermission,
) []Finding {

	var findings []Finding

	for _, ip := range permission.Ipv6Ranges {

		if ip.CidrIpv6 == nil {
			continue
		}

		if *ip.CidrIpv6 != "::/0" {
			continue
		}

		findings = append(findings, checkPort(sg, permission)...)

	}

	return findings
}

func checkPort(
	sg types.SecurityGroup,
	permission types.IpPermission,
) []Finding {

	var findings []Finding

	if permission.IpProtocol != nil &&
		*permission.IpProtocol == "-1" {

		findings = append(findings,
			newFinding(
				sg,
				"AllTrafficOpen",
				"CRITICAL",
				"Security Group allows all inbound traffic.",
				"Restrict inbound access using least privilege.",
			),
		)

		return findings
	}

	if permission.FromPort == nil {
		return findings
	}

	switch *permission.FromPort {

	case 22:

		findings = append(findings,
			newFinding(
				sg,
				"OpenSSH",
				"CRITICAL",
				"SSH port (22) is open to the Internet.",
				"Restrict SSH access to trusted IPs.",
			),
		)

	case 3389:

		findings = append(findings,
			newFinding(
				sg,
				"OpenRDP",
				"CRITICAL",
				"RDP port (3389) is open to the Internet.",
				"Restrict RDP access.",
			),
		)

	case 3306:

		findings = append(findings,
			newFinding(
				sg,
				"OpenMySQL",
				"HIGH",
				"MySQL port (3306) is publicly accessible.",
				"Restrict MySQL access.",
			),
		)

	case 5432:

		findings = append(findings,
			newFinding(
				sg,
				"OpenPostgres",
				"HIGH",
				"PostgreSQL port (5432) is publicly accessible.",
				"Restrict PostgreSQL access.",
			),
		)
	}

	return findings
}

func newFinding(
	sg types.SecurityGroup,
	findingType string,
	severity string,
	message string,
	recommendation string,
) Finding {

	groupID := ""
	groupName := ""

	if sg.GroupId != nil {
		groupID = *sg.GroupId
	}

	if sg.GroupName != nil {
		groupName = *sg.GroupName
	}

	return Finding{
		ResourceID:     groupID,
		ResourceType:   "SecurityGroup",
		ResourceName:   groupName,
		Service:        "VPC",
		FindingType:    findingType,
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
		Region:         "",
		DetectedAt:     time.Now(),
	}
}
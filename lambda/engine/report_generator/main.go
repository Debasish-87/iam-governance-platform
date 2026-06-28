package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const FindingsTable = "iam-security-findings"

type ReportResponse struct {
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	SecurityScore int `json:"security_score"`
}

func handler(
	ctx context.Context,
) (ReportResponse, error) {

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		return ReportResponse{}, err
	}

	dynamoClient := dynamodb.NewFromConfig(cfg)
	cloudwatchClient := cloudwatch.NewFromConfig(cfg)

	output, err := dynamoClient.Scan(
		ctx,
		&dynamodb.ScanInput{
			TableName: stringPtr(
				FindingsTable,
			),
		},
	)

	if err != nil {
		return ReportResponse{}, err
	}

	var findings []Finding

	err = attributevalue.UnmarshalListOfMaps(
		output.Items,
		&findings,
	)

	if err != nil {
		return ReportResponse{}, err
	}

	var critical int
	var high int
	var medium int
	var low int

	var wildcardAdmin int
	var passRole int
	var rootTrust int
	var federatedTrust int
	var adminPolicy int

	var ec2Findings int
	var s3Findings int
	var vpcFindings int
	var rdsFindings int
	var eksFindings int
	var cloudTrailFindings int

	var publicBucket int
	var publicInstance int
	var publicRDS int
	var publicEKS int

	var openSecurityGroup int
	var imdsv1Enabled int

	var rootLogin int
	var oldAccessKey int
	var privilegeEscalation int

	var s3EncryptionDisabled int
	var rdsEncryptionDisabled int

	for _, f := range findings {

		switch f.Severity {

		case "CRITICAL":
			critical++

		case "HIGH":
			high++

		case "MEDIUM":
			medium++

		case "LOW":
			low++
		}

		switch f.FindingType {

		//
		// IAM
		//

		case "WildcardAdmin":
			wildcardAdmin++

		case "PassRoleRisk":
			passRole++

		case "RootTrust":
			rootTrust++

		case "FederatedTrust":
			federatedTrust++

		case "AdminPolicy":
			adminPolicy++

		//
		// EC2
		//

		case "PublicInstance":
			ec2Findings++
			publicInstance++

		case "IMDSv1Enabled":
			ec2Findings++
			imdsv1Enabled++

		//
		// S3
		//

		case "PublicBucket":
			s3Findings++
			publicBucket++

		case "EncryptionDisabled":
			s3Findings++
			s3EncryptionDisabled++

		//
		// VPC
		//

		case "OpenSecurityGroup":
			vpcFindings++
			openSecurityGroup++

		//
		// RDS
		//

		case "PublicRDS":
			rdsFindings++
			publicRDS++

		case "RDSEncryptionDisabled":
			rdsFindings++
			rdsEncryptionDisabled++

		//
		// EKS
		//

		case "PublicEndpoint":
			eksFindings++
			publicEKS++

		//
		// CloudTrail
		//

		case "CloudTrailDisabled":
			cloudTrailFindings++

		//
		// Root
		//

		case "RootConsoleLogin":
			rootLogin++

		//
		// Access Keys
		//

		case "AccessKeyStale", "OldAccessKey":
			oldAccessKey++

		//
		// Privilege Escalation
		//

		case "PrivilegeEscalation":
			privilegeEscalation++
		}
	}

	score := 100

	score -= critical * 20
	score -= high * 10
	score -= medium * 5
	score -= low * 2

	if score < 0 {
		score = 0
	}

	fmt.Println("====================================")
	fmt.Println(" IAM GOVERNANCE REPORT")
	fmt.Println("====================================")

	fmt.Printf("Total Findings : %d\n", len(findings))
	fmt.Printf("Critical       : %d\n", critical)
	fmt.Printf("High           : %d\n", high)
	fmt.Printf("Medium         : %d\n", medium)
	fmt.Printf("Low            : %d\n", low)
	fmt.Printf("Security Score : %d/100\n", score)

	fmt.Println("====================================")
	fmt.Println(" RISK BREAKDOWN")
	fmt.Println("====================================")

	fmt.Printf("Wildcard Admin : %d\n", wildcardAdmin)
	fmt.Printf("PassRole Risk  : %d\n", passRole)
	fmt.Printf("Root Trust     : %d\n", rootTrust)
	fmt.Printf("Federated      : %d\n", federatedTrust)
	fmt.Printf("Admin Policy   : %d\n", adminPolicy)

	err = publishMetrics(
		ctx,
		cloudwatchClient,

		score,
		critical,
		high,
		medium,
		low,
		len(findings),

		wildcardAdmin,
		passRole,
		rootTrust,
		federatedTrust,
		adminPolicy,

		ec2Findings,
		s3Findings,
		vpcFindings,
		rdsFindings,
		eksFindings,
		cloudTrailFindings,

		publicBucket,
		publicInstance,
		publicRDS,
		publicEKS,

		openSecurityGroup,
		imdsv1Enabled,

		rootLogin,
		oldAccessKey,
		privilegeEscalation,

		s3EncryptionDisabled,
		rdsEncryptionDisabled,
	)

	if err != nil {
		fmt.Println(
			"CloudWatch Metric Error:",
			err,
		)
	}

	return ReportResponse{
		TotalFindings: len(findings),
		Critical:      critical,
		High:          high,
		Medium:        medium,
		Low:           low,
		SecurityScore: score,
	}, nil
}

func main() {
	lambda.Start(handler)
}

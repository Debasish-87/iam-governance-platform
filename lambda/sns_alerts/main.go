package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

const (
	FindingsTable = "iam-security-findings"
	TopicArn = "arn:aws:sns:ap-south-1:409837635702:iam-governance-alerts"
)

func handler(
	ctx context.Context,
) error {

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		return err
	}

	dynamoClient := dynamodb.NewFromConfig(cfg)
	snsClient := sns.NewFromConfig(cfg)

	output, err := dynamoClient.Scan(
		ctx,
		&dynamodb.ScanInput{
			TableName: &[]string{
				FindingsTable,
			}[0],
		},
	)

	if err != nil {
		return err
	}

	var findings []Finding

	err = attributevalue.UnmarshalListOfMaps(
		output.Items,
		&findings,
	)

	if err != nil {
		return err
	}

	for _, finding := range findings {

		if finding.Severity != "CRITICAL" {
			continue
		}

		message := fmt.Sprintf(
			"Resource: %s\nFinding: %s\nSeverity: %s\nMessage: %s",
			finding.ResourceName,
			finding.FindingType,
			finding.Severity,
			finding.Message,
		)

		_, err := snsClient.Publish(
			ctx,
			&sns.PublishInput{
				TopicArn: &[]string{
					TopicArn,
				}[0],
				Subject: &[]string{
					"[CRITICAL] IAM Governance Alert",
				}[0],
				Message: &message,
			},
		)

		if err != nil {
			fmt.Println(err)
			continue
		}

		fmt.Printf(
			"Alert sent for %s\n",
			finding.ResourceName,
		)
	}

	return nil
}

func main() {
	lambda.Start(handler)
}

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const FindingsTable = "iam-security-findings"

func saveFinding(
	client *dynamodb.Client,
	finding Finding,
) error {

	item, err := attributevalue.MarshalMap(finding)

	if err != nil {
		return err
	}

	_, err = client.PutItem(
		context.Background(),
		&dynamodb.PutItemInput{
			TableName: aws.String(FindingsTable),
			Item:      item,
		},
	)

	return err
}

func storeFinding(
	dynamoClient *dynamodb.Client,
	findingType string,
	severity string,
	message string,
) {

	finding := Finding{
		ResourceID: fmt.Sprintf(
			"root-%d",
			time.Now().UnixNano(),
		),
		ResourceName: "RootAccount",
		FindingType:  findingType,
		Severity:     severity,
		Message:      message,
		DetectedAt:   time.Now(),
	}

	err := saveFinding(
		dynamoClient,
		finding,
	)

	if err != nil {
		fmt.Printf(
			"Dynamo Error: %v\n",
			err,
		)
	}

	fmt.Println("-----------------------------------")
	fmt.Printf("Severity : %s\n", severity)
	fmt.Printf("Reason   : %s\n", message)
}
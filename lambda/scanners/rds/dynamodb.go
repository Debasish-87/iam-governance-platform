package main

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

var FindingsTable = os.Getenv("FINDINGS_TABLE")

func saveFinding(client *dynamodb.Client, finding Finding) error {

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

func saveFindings(client *dynamodb.Client, findings []Finding) error {

	for _, finding := range findings {

		if err := saveFinding(client, finding); err != nil {
			return err
		}
	}

	return nil
}
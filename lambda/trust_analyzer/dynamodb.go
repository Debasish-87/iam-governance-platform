package main

import (
	"context"

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
			Item: item,
		},
	)

	return err
}
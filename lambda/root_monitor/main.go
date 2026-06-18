package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func main() {

	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		panic(err)
	}

	ctClient := cloudtrail.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	fmt.Println("===================================")
	fmt.Println(" ROOT ACTIVITY MONITOR")
	fmt.Println("===================================")

	output, err := ctClient.LookupEvents(
		context.Background(),
		&cloudtrail.LookupEventsInput{
			MaxResults: aws.Int32(50),
		},
	)

	if err != nil {
		panic(err)
	}

	for _, event := range output.Events {

		if event.CloudTrailEvent == nil {
			continue
		}

		var raw map[string]interface{}

		err := json.Unmarshal(
			[]byte(*event.CloudTrailEvent),
			&raw,
		)

		if err != nil {
			continue
		}

		userIdentity, ok :=
			raw["userIdentity"].(map[string]interface{})

		if !ok {
			continue
		}

		userType := fmt.Sprintf(
			"%v",
			userIdentity["type"],
		)

		// Only Root events
		if userType != "Root" {
			continue
		}

		if event.EventName == nil {
			continue
		}

		switch *event.EventName {

		case "ConsoleLogin":

			storeFinding(
				dynamoClient,
				"RootConsoleLogin",
				"CRITICAL",
				"Root console login detected",
			)

		case "DeleteTrail":

			storeFinding(
				dynamoClient,
				"DeleteTrail",
				"CRITICAL",
				"Root deleted CloudTrail trail",
			)

		case "CreateUser":

			storeFinding(
				dynamoClient,
				"CreateUser",
				"CRITICAL",
				"Root created IAM user",
			)

		case "CreateAccessKey":

			storeFinding(
				dynamoClient,
				"CreateAccessKey",
				"CRITICAL",
				"Root created access key",
			)

		case "AttachRolePolicy":

			storeFinding(
				dynamoClient,
				"AttachRolePolicy",
				"CRITICAL",
				"Root attached IAM policy",
			)
		}
	}
}
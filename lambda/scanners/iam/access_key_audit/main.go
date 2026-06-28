package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	fmt.Println("===================================")
	fmt.Println(" ACCESS KEY AUDIT ENGINE")
	fmt.Println("===================================")

	users, err := iamClient.ListUsers(
		ctx,
		&iam.ListUsersInput{},
	)

	if err != nil {
		return err
	}

	for _, user := range users.Users {

		keys, err := iamClient.ListAccessKeys(
			ctx,
			&iam.ListAccessKeysInput{
				UserName: user.UserName,
			},
		)

		if err != nil {
			continue
		}

		// Multiple active keys
		if len(keys.AccessKeyMetadata) > 1 {

			storeFinding(
				dynamoClient,
				*user.UserName,
				"MultipleKeys",
				"MEDIUM",
				"User has multiple active access keys",
			)
		}

		for _, key := range keys.AccessKeyMetadata {

			checkKeyAge(
				ctx,
				iamClient,
				dynamoClient,
				*user.UserName,
				key,
			)

			checkKeyUsage(
				ctx,
				iamClient,
				dynamoClient,
				*user.UserName,
				key,
			)
		}
	}

	fmt.Println("IAM Access Key Audit Completed.")

	return nil
}

func main() {
	lambda.Start(handler)
}

func checkKeyAge(
	ctx context.Context,
	iamClient *iam.Client,
	dynamoClient *dynamodb.Client,
	userName string,
	key types.AccessKeyMetadata,
) {

	if key.CreateDate == nil {
		return
	}

	ageDays := int(time.Since(*key.CreateDate).Hours() / 24)

	if ageDays > 90 {

		storeFinding(
			dynamoClient,
			userName,
			"OldAccessKey",
			"HIGH",
			fmt.Sprintf(
				"Access key is %d days old",
				ageDays,
			),
		)
	}
}

func checkKeyUsage(
	ctx context.Context,
	iamClient *iam.Client,
	dynamoClient *dynamodb.Client,
	userName string,
	key types.AccessKeyMetadata,
) {

	output, err := iamClient.GetAccessKeyLastUsed(
		ctx,
		&iam.GetAccessKeyLastUsedInput{
			AccessKeyId: key.AccessKeyId,
		},
	)

	if err != nil {
		return
	}

	if output.AccessKeyLastUsed == nil ||
		output.AccessKeyLastUsed.LastUsedDate == nil {

		storeFinding(
			dynamoClient,
			userName,
			"UnusedAccessKey",
			"HIGH",
			"Access key has never been used",
		)

		return
	}

	lastUsedDays := int(
		time.Since(
			*output.AccessKeyLastUsed.LastUsedDate,
		).Hours() / 24,
	)

	if lastUsedDays > 60 {

		storeFinding(
			dynamoClient,
			userName,
			"InactiveAccessKey",
			"HIGH",
			fmt.Sprintf(
				"Access key unused for %d days",
				lastUsedDays,
			),
		)
	}
}

func storeFinding(
	dynamoClient *dynamodb.Client,
	userName string,
	findingType string,
	severity string,
	message string,
) {

	fmt.Println("-----------------------------------")
	fmt.Printf("User       : %s\n", userName)
	fmt.Printf("Severity   : %s\n", severity)
	fmt.Printf("Reason     : %s\n", message)

	finding := Finding{
		ResourceID: fmt.Sprintf(
			"%s-%d",
			userName,
			time.Now().UnixNano(),
		),

		ResourceName: userName,
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
}

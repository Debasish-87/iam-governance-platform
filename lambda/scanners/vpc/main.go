package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	ec2Client := ec2.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	output, err := ec2Client.DescribeSecurityGroups(
		ctx,
		&ec2.DescribeSecurityGroupsInput{},
	)

	if err != nil {
		return err
	}

	log.Println("===================================")
	log.Println("VPC SECURITY SCANNER")
	log.Println("===================================")

	for _, sg := range output.SecurityGroups {

		findings := AnalyzeSecurityGroup(sg)

		if len(findings) == 0 {
			continue
		}

		if err := saveFindings(
			dynamoClient,
			findings,
		); err != nil {

			log.Printf(
				"failed to save findings for %s: %v",
				*sg.GroupId,
				err,
			)
		}
	}

	log.Println("VPC Scan Completed")

	return nil
}

func main() {
	lambda.Start(handler)
}
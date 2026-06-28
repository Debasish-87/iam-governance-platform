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

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		return err
	}

	ec2Client := ec2.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	paginator := ec2.NewDescribeInstancesPaginator(
		ec2Client,
		&ec2.DescribeInstancesInput{},
	)

	log.Println("====================================")
	log.Println(" EC2 SECURITY SCANNER")
	log.Println("====================================")

	for paginator.HasMorePages() {

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, reservation := range page.Reservations {

			for _, instance := range reservation.Instances {

				findings := AnalyzeInstance(instance)

				if len(findings) == 0 {
					continue
				}

				if err := saveFindings(
					dynamoClient,
					findings,
				); err != nil {
					log.Printf(
						"failed to save findings: %v",
						err,
					)
				}
			}
		}
	}

	log.Println("EC2 Scan Completed")

	return nil
}

func main() {
	lambda.Start(handler)
}

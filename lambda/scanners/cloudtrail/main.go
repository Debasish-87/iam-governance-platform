package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	cloudTrailClient := cloudtrail.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	output, err := cloudTrailClient.DescribeTrails(
		ctx,
		&cloudtrail.DescribeTrailsInput{
			IncludeShadowTrails: aws.Bool(true),
		},
	)

	if err != nil {
		return err
	}

	log.Println("===================================")
	log.Println("CLOUDTRAIL SECURITY SCANNER")
	log.Println("===================================")

	for _, trail := range output.TrailList {

		findings := AnalyzeTrail(trail)

		if len(findings) == 0 {
			continue
		}

		if err := saveFindings(
			dynamoClient,
			findings,
		); err != nil {

			trailName := "unknown"

			if trail.Name != nil {
				trailName = *trail.Name
			}

			log.Printf(
				"failed to save findings for %s: %v",
				trailName,
				err,
			)
		}
	}

	log.Println("CloudTrail Scan Completed")

	return nil
}

func main() {
	lambda.Start(handler)
}

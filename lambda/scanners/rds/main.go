package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	rdsClient := rds.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	paginator := rds.NewDescribeDBInstancesPaginator(
		rdsClient,
		&rds.DescribeDBInstancesInput{},
	)

	log.Println("===================================")
	log.Println("RDS SECURITY SCANNER")
	log.Println("===================================")

	for paginator.HasMorePages() {

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, db := range page.DBInstances {

			findings := AnalyzeDBInstance(db)

			if len(findings) == 0 {
				continue
			}

			if err := saveFindings(
				dynamoClient,
				findings,
			); err != nil {

				dbID := "unknown"

				if db.DBInstanceIdentifier != nil {
					dbID = *db.DBInstanceIdentifier
				}

				log.Printf(
					"failed to save findings for %s: %v",
					dbID,
					err,
				)
			}
		}
	}

	log.Println("RDS Scan Completed")

	return nil
}

func main() {
	lambda.Start(handler)
}
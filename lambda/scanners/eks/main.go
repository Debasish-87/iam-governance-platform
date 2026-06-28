package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	eksClient := eks.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	output, err := eksClient.ListClusters(
		ctx,
		&eks.ListClustersInput{},
	)

	if err != nil {
		return err
	}

	log.Println("===================================")
	log.Println("EKS SECURITY SCANNER")
	log.Println("===================================")

	for _, clusterName := range output.Clusters {

		clusterOutput, err := eksClient.DescribeCluster(
			ctx,
			&eks.DescribeClusterInput{
				Name: &clusterName,
			},
		)

		if err != nil {
			log.Printf(
				"failed to describe cluster %s: %v",
				clusterName,
				err,
			)
			continue
		}

		findings := AnalyzeCluster(*clusterOutput.Cluster)

		if len(findings) == 0 {
			continue
		}

		if err := saveFindings(
			dynamoClient,
			findings,
		); err != nil {

			log.Printf(
				"failed to save findings for %s: %v",
				clusterName,
				err,
			)
		}
	}

	log.Println("EKS Scan Completed")

	return nil
}

func main() {
	lambda.Start(handler)
}
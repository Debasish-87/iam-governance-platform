package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const FindingsTable = "iam-security-findings"

func calculateScore(
	findings []Finding,
) int {

	score := 100

	for _, finding := range findings {

		switch finding.Severity {

		case "CRITICAL":
			score -= 30

		case "HIGH":
			score -= 15

		case "MEDIUM":
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

func main() {

	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		panic(err)
	}

	client := dynamodb.NewFromConfig(cfg)

	output, err := client.Scan(
		context.Background(),
		&dynamodb.ScanInput{
			TableName: &[]string{FindingsTable}[0],
		},
	)

	if err != nil {
		panic(err)
	}

	var findings []Finding

	err = attributevalue.UnmarshalListOfMaps(
		output.Items,
		&findings,
	)

	if err != nil {
		panic(err)
	}

	score := calculateScore(findings)

	fmt.Println("===================================")
	fmt.Println(" IAM SECURITY SCORE")
	fmt.Println("===================================")
	fmt.Printf("Score : %d / 100\n", score)
	fmt.Printf("Findings : %d\n", len(findings))
}

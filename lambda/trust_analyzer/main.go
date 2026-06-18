package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func handler(
	ctx context.Context,
) error {

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
	fmt.Println(" TRUST POLICY ANALYZER")
	fmt.Println("===================================")

	roles, err := iamClient.ListRoles(
		ctx,
		&iam.ListRolesInput{},
	)

	if err != nil {
		return err
	}

	for _, role := range roles.Roles {

		if strings.HasPrefix(
			*role.RoleName,
			"AWSServiceRoleFor",
		) {
			continue
		}

		if role.AssumeRolePolicyDocument == nil {
			continue
		}

		doc, err := url.QueryUnescape(
			*role.AssumeRolePolicyDocument,
		)

		if err != nil {
			continue
		}

		var trustPolicy TrustPolicy

		err = json.Unmarshal(
			[]byte(doc),
			&trustPolicy,
		)

		if err != nil {
			continue
		}

		analyzeTrustPolicy(
			dynamoClient,
			*role.RoleName,
			trustPolicy,
		)
	}

	return nil
}

func analyzeTrustPolicy(
	dynamoClient *dynamodb.Client,
	roleName string,
	policy TrustPolicy,
) {

	for _, stmt := range policy.Statement {

		principalText := fmt.Sprintf(
			"%v",
			stmt.Principal,
		)

		fmt.Printf(
			"Role: %s\nPrincipal: %s\n",
			roleName,
			principalText,
		)

		// Wildcard Principal

		if strings.Contains(
			principalText,
			"*",
		) {

			storeFinding(
				dynamoClient,
				roleName,
				"WildcardPrincipal",
				"CRITICAL",
				"Trust policy allows Principal=*",
			)
		}

		// Root Trust

		if strings.Contains(
			principalText,
			":root",
		) {

			storeFinding(
				dynamoClient,
				roleName,
				"RootTrust",
				"HIGH",
				"Role can be assumed by AWS root account",
			)
		}

		// Federated Trust

		if strings.Contains(
			principalText,
			"Federated",
		) {

			storeFinding(
				dynamoClient,
				roleName,
				"FederatedTrust",
				"MEDIUM",
				"Federated principal detected",
			)
		}
	}
}

func storeFinding(
	dynamoClient *dynamodb.Client,
	roleName string,
	findingType string,
	severity string,
	message string,
) {

	fmt.Println("-----------------------------------")
	fmt.Printf("Role       : %s\n", roleName)
	fmt.Printf("Severity   : %s\n", severity)
	fmt.Printf("Reason     : %s\n", message)

	finding := Finding{
		ResourceID: fmt.Sprintf(
			"%s-%d",
			roleName,
			time.Now().UnixNano(),
		),
		ResourceName: roleName,
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

func main() {
	lambda.Start(handler)
}
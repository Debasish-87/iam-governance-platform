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

	roles, err := iamClient.ListRoles(
		ctx,
		&iam.ListRolesInput{},
	)

	if err != nil {
		return err
	}

	fmt.Println("===================================")
	fmt.Println(" IAM POLICY ANALYZER V3")
	fmt.Println("===================================")

	for _, role := range roles.Roles {

		if strings.HasPrefix(
			*role.RoleName,
			"AWSServiceRoleFor",
		) {
			continue
		}

		policies, err := iamClient.ListAttachedRolePolicies(
			ctx,
			&iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			},
		)

		if err != nil {
			continue
		}

		for _, policy := range policies.AttachedPolicies {

			policyOutput, err := iamClient.GetPolicy(
				ctx,
				&iam.GetPolicyInput{
					PolicyArn: policy.PolicyArn,
				},
			)

			if err != nil {
				continue
			}

			versionOutput, err := iamClient.GetPolicyVersion(
				ctx,
				&iam.GetPolicyVersionInput{
					PolicyArn: policy.PolicyArn,
					VersionId: policyOutput.Policy.DefaultVersionId,
				},
			)

			if err != nil {
				continue
			}

			decodedDoc, err := url.QueryUnescape(
				*versionOutput.PolicyVersion.Document,
			)

			if err != nil {
				continue
			}

			var policyDoc PolicyDocument

			err = json.Unmarshal(
				[]byte(decodedDoc),
				&policyDoc,
			)

			if err != nil {
				continue
			}

			for _, stmt := range policyDoc.Statement {

				actions := extractActions(
					stmt.Action,
				)

				resources := extractActions(
					stmt.Resource,
				)

				// Wildcard Admin

				if stmt.Effect == "Allow" &&
					contains(actions, "*") &&
					contains(resources, "*") {

					storeFinding(
						dynamoClient,
						*role.RoleName,
						*policy.PolicyName,
						"WildcardAdmin",
						"CRITICAL",
						"Action=* Resource=*",
					)
				}

				// IAM Admin

				if contains(
					actions,
					"iam:*",
				) {

					storeFinding(
						dynamoClient,
						*role.RoleName,
						*policy.PolicyName,
						"IAMAdminPermissions",
						"HIGH",
						"Role contains iam:*",
					)
				}

				// PassRole

				if contains(
					actions,
					"iam:PassRole",
				) {

					storeFinding(
						dynamoClient,
						*role.RoleName,
						*policy.PolicyName,
						"PassRoleRisk",
						"HIGH",
						"Privilege escalation via PassRole",
					)
				}

				// Administrator Policy

				if strings.Contains(
					*policy.PolicyName,
					"Administrator",
				) {

					storeFinding(
						dynamoClient,
						*role.RoleName,
						*policy.PolicyName,
						"AdminPolicy",
						"CRITICAL",
						"Administrator level permissions detected",
					)
				}
			}
		}
	}

	return nil
}

func storeFinding(
	dynamoClient *dynamodb.Client,
	roleName string,
	policyName string,
	findingType string,
	severity string,
	message string,
) {

	fmt.Println("-----------------------------------")
	fmt.Printf("Role       : %s\n", roleName)
	fmt.Printf("Policy     : %s\n", policyName)
	fmt.Printf("Severity   : %s\n", severity)
	fmt.Printf("Reason     : %s\n", message)

	finding := Finding{
		ResourceID:   roleName,
		ResourceName: roleName,
		FindingType:  findingType,
		Severity:     severity,
		PolicyName:   policyName,
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

func extractActions(
	value interface{},
) []string {

	switch v := value.(type) {

	case string:
		return []string{v}

	case []interface{}:

		var result []string

		for _, item := range v {

			if s, ok := item.(string); ok {
				result = append(
					result,
					s,
				)
			}
		}

		return result
	}

	return []string{}
}

func contains(
	values []string,
	target string,
) bool {

	for _, value := range values {

		if value == target {
			return true
		}
	}

	return false
}

func main() {
	lambda.Start(handler)
}

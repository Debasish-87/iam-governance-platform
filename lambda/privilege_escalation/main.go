package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func main() {

	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion("ap-south-1"),
	)

	if err != nil {
		panic(err)
	}

	iamClient := iam.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	fmt.Println("===================================")
	fmt.Println(" PRIVILEGE ESCALATION ENGINE")
	fmt.Println("===================================")

	roles, err := iamClient.ListRoles(
		context.Background(),
		&iam.ListRolesInput{},
	)

	if err != nil {
		panic(err)
	}

	for _, role := range roles.Roles {

		// Skip AWS managed service roles
		if strings.HasPrefix(
			*role.RoleName,
			"AWSServiceRoleFor",
		) {
			continue
		}

		actionSet := map[string]bool{}

		policies, err := iamClient.ListAttachedRolePolicies(
			context.Background(),
			&iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			},
		)

		if err != nil {
			continue
		}

		for _, policy := range policies.AttachedPolicies {

			policyOutput, err := iamClient.GetPolicy(
				context.Background(),
				&iam.GetPolicyInput{
					PolicyArn: policy.PolicyArn,
				},
			)

			if err != nil {
				continue
			}

			versionOutput, err := iamClient.GetPolicyVersion(
				context.Background(),
				&iam.GetPolicyVersionInput{
					PolicyArn: policy.PolicyArn,
					VersionId: policyOutput.Policy.DefaultVersionId,
				},
			)

			if err != nil {
				continue
			}

			doc, err := url.QueryUnescape(
				*versionOutput.PolicyVersion.Document,
			)

			if err != nil {
				continue
			}

			var policyDoc PolicyDocument

			err = json.Unmarshal(
				[]byte(doc),
				&policyDoc,
			)

			if err != nil {
				continue
			}

			for _, stmt := range policyDoc.Statement {

				actions := extractActions(stmt.Action)

				for _, action := range actions {
					actionSet[action] = true
				}
			}
		}

		fmt.Printf(
			"Role: %s Actions: %d\n",
			*role.RoleName,
			len(actionSet),
		)

		detectEscalationPaths(
			dynamoClient,
			*role.RoleName,
			actionSet,
		)
	}
}

func detectEscalationPaths(
	dynamoClient *dynamodb.Client,
	roleName string,
	actions map[string]bool,
) {

	if actions["*"] {

		storeFinding(
			dynamoClient,
			roleName,
			"FullAdminAccess",
			"CRITICAL",
			"Role has wildcard administrative permissions",
		)
	}

	// PassRole + Lambda

	if actions["iam:PassRole"] &&
		actions["lambda:CreateFunction"] {

		storeFinding(
			dynamoClient,
			roleName,
			"PrivilegeEscalation",
			"CRITICAL",
			"iam:PassRole + lambda:CreateFunction",
		)
	}

	// PassRole + EC2

	if actions["iam:PassRole"] &&
		actions["ec2:RunInstances"] {

		storeFinding(
			dynamoClient,
			roleName,
			"PrivilegeEscalation",
			"CRITICAL",
			"iam:PassRole + ec2:RunInstances",
		)
	}

	// Policy version abuse

	if actions["iam:AttachRolePolicy"] &&
		actions["iam:CreatePolicyVersion"] {

		storeFinding(
			dynamoClient,
			roleName,
			"PrivilegeEscalation",
			"CRITICAL",
			"AttachRolePolicy + CreatePolicyVersion",
		)
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
		fmt.Printf("Dynamo Error: %v\n", err)
	}
}

func extractActions(value interface{}) []string {

	switch v := value.(type) {

	case string:
		return []string{v}

	case []interface{}:

		var result []string

		for _, item := range v {

			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}

		return result
	}

	return []string{}
}

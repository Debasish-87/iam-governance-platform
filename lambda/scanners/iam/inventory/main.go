package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion("ap-south-1"),
	)
	if err != nil {
		return err
	}

	client := iam.NewFromConfig(cfg)

	fmt.Println("===================================")
	fmt.Println(" IAM GOVERNANCE PLATFORM")
	fmt.Println(" Inventory Engine")
	fmt.Println("===================================")

	printInventory(ctx, client)

	fmt.Println("\n===================================")
	fmt.Println(" ROLE ANALYSIS")
	fmt.Println("===================================")

	analyzeRoles(ctx, client)

	fmt.Println("Inventory Scan Completed.")

	return nil
}

func main() {
	lambda.Start(handler)
}

func printInventory(
	ctx context.Context,
	client *iam.Client,
) {

	users, err := client.ListUsers(
		ctx,
		&iam.ListUsersInput{},
	)
	if err != nil {
		panic(err)
	}

	roles, err := client.ListRoles(
		ctx,
		&iam.ListRolesInput{},
	)
	if err != nil {
		panic(err)
	}

	policies, err := client.ListPolicies(
		ctx,
		&iam.ListPoliciesInput{},
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Users           : %d\n", len(users.Users))
	fmt.Printf("Roles           : %d\n", len(roles.Roles))
	fmt.Printf("Policies        : %d\n", len(policies.Policies))

	fmt.Println("\n--- USERS ---")

	for _, user := range users.Users {
		fmt.Printf("- %s\n", *user.UserName)
	}
}

func analyzeRoles(
	ctx context.Context,
	client *iam.Client,
) {

	roles, err := client.ListRoles(
		ctx,
		&iam.ListRolesInput{},
	)

	if err != nil {
		panic(err)
	}

	for _, role := range roles.Roles {

		fmt.Println("\n-----------------------------------")
		fmt.Printf("Role Name : %s\n", *role.RoleName)

		if role.RoleLastUsed != nil &&
			role.RoleLastUsed.LastUsedDate != nil {

			fmt.Printf(
				"Last Used : %s\n",
				role.RoleLastUsed.LastUsedDate.Format(
					"2006-01-02 15:04:05",
				),
			)

		} else {
			fmt.Println("Last Used : Never/Unknown")
		}

		policies, err := client.ListAttachedRolePolicies(
			ctx,
			&iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			},
		)

		if err != nil {
			fmt.Printf("Policy Error: %v\n", err)
			continue
		}

		fmt.Println("Attached Policies:")

		if len(policies.AttachedPolicies) == 0 {
			fmt.Println("  None")
		}

		for _, policy := range policies.AttachedPolicies {
			fmt.Printf("  - %s\n", *policy.PolicyName)
		}
	}
}

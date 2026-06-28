package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
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

	client := iam.NewFromConfig(cfg)

	graph := AttackGraph{}

	roles, err := client.ListRoles(
		context.Background(),
		&iam.ListRolesInput{},
	)

	if err != nil {
		panic(err)
	}

	fmt.Println("===================================")
	fmt.Println(" ATTACK GRAPH ENGINE")
	fmt.Println("===================================")

	for _, role := range roles.Roles {

		fmt.Printf(
			"Found Role: %s\n",
			*role.RoleName,
		)

		if strings.HasPrefix(
			*role.RoleName,
			"AWSServiceRoleFor",
		) {
			continue
		}

		roleName := *role.RoleName

		actions := collectActions(
			client,
			roleName,
		)

		buildGraph(
			&graph,
			roleName,
			actions,
		)
	}

	saveGraph(graph)
}

func collectActions(
	client *iam.Client,
	roleName string,
) map[string]bool {

	actionSet := map[string]bool{}

	policies, err := client.ListAttachedRolePolicies(
		context.Background(),
		&iam.ListAttachedRolePoliciesInput{
			RoleName: &roleName,
		},
	)

	if err != nil {
		return actionSet
	}

	for _, policy := range policies.AttachedPolicies {

		policyOutput, err := client.GetPolicy(
			context.Background(),
			&iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			},
		)

		if err != nil {
			continue
		}

		versionOutput, err := client.GetPolicyVersion(
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

			for _, action := range extractActions(
				stmt.Action,
			) {
				actionSet[action] = true
			}
		}
	}

	return actionSet
}

func buildGraph(
	graph *AttackGraph,
	roleName string,
	actions map[string]bool,
) {

	graph.Nodes = append(
		graph.Nodes,
		GraphNode{
			ID:   roleName,
			Type: "Role",
		},
	)

	if actions["*"] {

		graph.Edges = append(
			graph.Edges,
			GraphEdge{
				Source: roleName,
				Target: "AdministratorAccess",
				Reason: "Wildcard Admin",
				Risk:   "CRITICAL",
			},
		)
	}

	if actions["iam:PassRole"] &&
		actions["lambda:CreateFunction"] {

		graph.Edges = append(
			graph.Edges,
			GraphEdge{
				Source: roleName,
				Target: "AdministratorAccess",
				Reason: "PassRole + Lambda",
				Risk:   "CRITICAL",
			},
		)

		fmt.Println("-----------------------------------")
		fmt.Printf("Role : %s\n", roleName)
		fmt.Println(
			"Path : PassRole -> Lambda -> Admin",
		)
		fmt.Println("Risk : CRITICAL")
	}

	if actions["iam:PassRole"] &&
		actions["ec2:RunInstances"] {

		graph.Edges = append(
			graph.Edges,
			GraphEdge{
				Source: roleName,
				Target: "AdministratorAccess",
				Reason: "PassRole + EC2",
				Risk:   "CRITICAL",
			},
		)

		fmt.Println("-----------------------------------")
		fmt.Printf("Role : %s\n", roleName)
		fmt.Println(
			"Path : PassRole -> EC2 -> Admin",
		)
		fmt.Println("Risk : CRITICAL")
	}
}

func saveGraph(
	graph AttackGraph,
) {

	data, err := json.MarshalIndent(
		graph,
		"",
		"  ",
	)

	if err != nil {
		return
	}

	err = os.WriteFile(
		"attack-graph.json",
		data,
		0644,
	)

	if err != nil {
		return
	}

	fmt.Println()

	fmt.Printf(
		"Nodes: %d\n",
		len(graph.Nodes),
	)

	fmt.Printf(
		"Edges: %d\n",
		len(graph.Edges),
	)

	fmt.Println(
		"Attack graph saved: attack-graph.json",
	)
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

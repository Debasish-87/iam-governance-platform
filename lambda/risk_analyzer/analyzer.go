package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func analyzePolicy(
	client *iam.Client,
	roleName string,
	policyArn string,
	policyName string,
) {

	policyOutput, err := client.GetPolicy(
		context.Background(),
		&iam.GetPolicyInput{
			PolicyArn: &policyArn,
		},
	)

	if err != nil {
		return
	}

	versionOutput, err := client.GetPolicyVersion(
		context.Background(),
		&iam.GetPolicyVersionInput{
			PolicyArn: &policyArn,
			VersionId: policyOutput.Policy.DefaultVersionId,
		},
	)

	if err != nil {
		return
	}

	decodedDoc, err :=
		url.QueryUnescape(
			*versionOutput.PolicyVersion.Document,
		)

	if err != nil {
		return
	}

	var policyDoc PolicyDocument

	err = json.Unmarshal(
		[]byte(decodedDoc),
		&policyDoc,
	)

	if err != nil {
		return
	}

	for _, stmt := range policyDoc.Statement {

		action := fmt.Sprintf("%v", stmt.Action)
		resource := fmt.Sprintf("%v", stmt.Resource)

		if stmt.Effect == "Allow" &&
			action == "*" &&
			resource == "*" {

			fmt.Println("-----------------------------------")
			fmt.Printf("Role       : %s\n", roleName)
			fmt.Printf("Policy     : %s\n", policyName)
			fmt.Printf("Severity   : CRITICAL\n")
			fmt.Printf("Reason     : Action=* Resource=*\n")
		}
	}
}

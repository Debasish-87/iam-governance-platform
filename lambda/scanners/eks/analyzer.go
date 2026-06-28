package main

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eks/types"
)

func AnalyzeCluster(cluster types.Cluster) []Finding {

	var findings []Finding

	findings = append(findings, checkPublicEndpoint(cluster)...)
	findings = append(findings, checkPrivateEndpoint(cluster)...)
	findings = append(findings, checkSecretsEncryption(cluster)...)
	findings = append(findings, checkLogging(cluster)...)
	findings = append(findings, checkVersion(cluster)...)

	return findings
}

func checkPublicEndpoint(cluster types.Cluster) []Finding {

	if cluster.ResourcesVpcConfig != nil &&
		cluster.ResourcesVpcConfig.EndpointPublicAccess {

		return []Finding{
			newFinding(
				cluster,
				"PublicAPIEnabled",
				"HIGH",
				"EKS public API endpoint is enabled.",
				"Disable public endpoint or restrict CIDRs.",
			),
		}
	}

	return nil
}

func checkPrivateEndpoint(cluster types.Cluster) []Finding {

	if cluster.ResourcesVpcConfig != nil &&
		!cluster.ResourcesVpcConfig.EndpointPrivateAccess {

		return []Finding{
			newFinding(
				cluster,
				"PrivateAPIDisabled",
				"MEDIUM",
				"EKS private API endpoint is disabled.",
				"Enable private endpoint access.",
			),
		}
	}

	return nil
}

func checkSecretsEncryption(cluster types.Cluster) []Finding {

	if cluster.EncryptionConfig == nil ||
		len(cluster.EncryptionConfig) == 0 {

		return []Finding{
			newFinding(
				cluster,
				"SecretsEncryptionDisabled",
				"HIGH",
				"Kubernetes secrets encryption is disabled.",
				"Enable envelope encryption using AWS KMS.",
			),
		}
	}

	return nil
}

func checkLogging(cluster types.Cluster) []Finding {

	if cluster.Logging == nil ||
		cluster.Logging.ClusterLogging == nil {

		return []Finding{
			newFinding(
				cluster,
				"ControlPlaneLoggingDisabled",
				"MEDIUM",
				"Control plane logging is disabled.",
				"Enable API, Audit, Authenticator and Scheduler logs.",
			),
		}
	}

	return nil
}

func checkVersion(cluster types.Cluster) []Finding {

	if cluster.Version == nil {
		return nil
	}

	if strings.HasPrefix(*cluster.Version, "1.2") {

		return []Finding{
			newFinding(
				cluster,
				"OldKubernetesVersion",
				"LOW",
				"Cluster is running an older Kubernetes version.",
				"Upgrade to the latest supported EKS version.",
			),
		}
	}

	return nil
}

func newFinding(
	cluster types.Cluster,
	findingType string,
	severity string,
	message string,
	recommendation string,
) Finding {

	clusterName := ""

	if cluster.Name != nil {
		clusterName = *cluster.Name
	}

	region := ""

	if cluster.Arn != nil {

		parts := strings.Split(*cluster.Arn, ":")

		if len(parts) > 3 {
			region = parts[3]
		}
	}

	return Finding{
		ResourceID:     clusterName,
		ResourceType:   "EKS",
		ResourceName:   clusterName,
		Service:        "EKS",
		FindingType:    findingType,
		Severity:       severity,
		Message:        message,
		Recommendation: recommendation,
		Region:         region,
		DetectedAt:     time.Now(),
	}
}
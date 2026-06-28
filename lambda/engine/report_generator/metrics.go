package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

const Namespace = "IAMGovernance"

func publishMetrics(
	ctx context.Context,
	client *cloudwatch.Client,

	score int,
	critical int,
	high int,
	medium int,
	low int,
	total int,

	wildcardAdmin int,
	passRole int,
	rootTrust int,
	federatedTrust int,
	adminPolicy int,

	ec2Findings int,
	s3Findings int,
	vpcFindings int,
	rdsFindings int,
	eksFindings int,
	cloudTrailFindings int,

	publicBucket int,
	publicInstance int,
	publicRDS int,
	publicEKS int,

	openSecurityGroup int,
	imdsv1Enabled int,

	rootLogin int,
	oldAccessKey int,
	privilegeEscalation int,

	s3EncryptionDisabled int,
	rdsEncryptionDisabled int,
) error {

	attackSurface :=
		wildcardAdmin +
			passRole +
			adminPolicy

	trustPolicyRisk :=
		rootTrust +
			federatedTrust

	_, err := client.PutMetricData(
		ctx,
		&cloudwatch.PutMetricDataInput{
			Namespace: stringPtr(
				Namespace,
			),

			MetricData: []cwtypes.MetricDatum{

				// Executive Metrics

				{
					MetricName: stringPtr(
						"SecurityScore",
					),
					Value: float64Ptr(
						float64(score),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"AttackSurface",
					),
					Value: float64Ptr(
						float64(attackSurface),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"PrivilegeEscalationRisk",
					),
					Value: float64Ptr(
						float64(passRole),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"TrustPolicyRisk",
					),
					Value: float64Ptr(
						float64(trustPolicyRisk),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				// Severity Metrics

				{
					MetricName: stringPtr(
						"TotalFindings",
					),
					Value: float64Ptr(
						float64(total),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"CriticalFindings",
					),
					Value: float64Ptr(
						float64(critical),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"HighFindings",
					),
					Value: float64Ptr(
						float64(high),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"MediumFindings",
					),
					Value: float64Ptr(
						float64(medium),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"LowFindings",
					),
					Value: float64Ptr(
						float64(low),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				// Risk Type Metrics

				{
					MetricName: stringPtr(
						"WildcardAdminCount",
					),
					Value: float64Ptr(
						float64(wildcardAdmin),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"PassRoleCount",
					),
					Value: float64Ptr(
						float64(passRole),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"RootTrustCount",
					),
					Value: float64Ptr(
						float64(rootTrust),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"FederatedTrustCount",
					),
					Value: float64Ptr(
						float64(federatedTrust),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr(
						"AdminPolicyCount",
					),
					Value: float64Ptr(
						float64(adminPolicy),
					),
					Unit: cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("EC2Findings"),
					Value:      float64Ptr(float64(ec2Findings)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("S3Findings"),
					Value:      float64Ptr(float64(s3Findings)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("VPCFindings"),
					Value:      float64Ptr(float64(vpcFindings)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("RDSFindings"),
					Value:      float64Ptr(float64(rdsFindings)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("EKSFindings"),
					Value:      float64Ptr(float64(eksFindings)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("CloudTrailFindings"),
					Value:      float64Ptr(float64(cloudTrailFindings)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("PublicBuckets"),
					Value:      float64Ptr(float64(publicBucket)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("PublicInstances"),
					Value:      float64Ptr(float64(publicInstance)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("PublicRDS"),
					Value:      float64Ptr(float64(publicRDS)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("PublicEKS"),
					Value:      float64Ptr(float64(publicEKS)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("OpenSecurityGroups"),
					Value:      float64Ptr(float64(openSecurityGroup)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("IMDSv1Enabled"),
					Value:      float64Ptr(float64(imdsv1Enabled)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("RootLogins"),
					Value:      float64Ptr(float64(rootLogin)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("OldAccessKeys"),
					Value:      float64Ptr(float64(oldAccessKey)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("PrivilegeEscalations"),
					Value:      float64Ptr(float64(privilegeEscalation)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("S3EncryptionDisabled"),
					Value:      float64Ptr(float64(s3EncryptionDisabled)),
					Unit:       cwtypes.StandardUnitCount,
				},

				{
					MetricName: stringPtr("RDSEncryptionDisabled"),
					Value:      float64Ptr(float64(rdsEncryptionDisabled)),
					Unit:       cwtypes.StandardUnitCount,
				},
			},
		},
	)

	return err
}

func float64Ptr(v float64) *float64 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

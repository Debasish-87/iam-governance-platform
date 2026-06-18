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
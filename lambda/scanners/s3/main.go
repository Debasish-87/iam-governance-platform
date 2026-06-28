package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func handler(ctx context.Context) error {

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	s3Client := s3.NewFromConfig(cfg)
	dynamoClient := dynamodb.NewFromConfig(cfg)

	output, err := s3Client.ListBuckets(
		ctx,
		&s3.ListBucketsInput{},
	)

	if err != nil {
		return err
	}

	log.Println("===================================")
	log.Println("S3 SECURITY SCANNER")
	log.Println("===================================")

	for _, bucket := range output.Buckets {

		bucketName := *bucket.Name

		meta := BucketMetadata{
			Name: bucketName,
		}

		// Region
		location, err := s3Client.GetBucketLocation(
			ctx,
			&s3.GetBucketLocationInput{
				Bucket: &bucketName,
			},
		)

		if err == nil {

			switch location.LocationConstraint {

			case types.BucketLocationConstraint(""):
				meta.Region = "us-east-1"

			default:
				meta.Region = string(location.LocationConstraint)
			}
		}

		// Encryption
		_, err = s3Client.GetBucketEncryption(
			ctx,
			&s3.GetBucketEncryptionInput{
				Bucket: &bucketName,
			},
		)

		meta.Encrypted = err == nil

		// Versioning
		versioning, err := s3Client.GetBucketVersioning(
			ctx,
			&s3.GetBucketVersioningInput{
				Bucket: &bucketName,
			},
		)

		if err == nil &&
			versioning.Status == types.BucketVersioningStatusEnabled {

			meta.VersioningEnabled = true
		}

		// Public Access Block
		publicAccess, err := s3Client.GetPublicAccessBlock(
			ctx,
			&s3.GetPublicAccessBlockInput{
				Bucket: &bucketName,
			},
		)

		if err == nil && publicAccess.PublicAccessBlockConfiguration != nil {

			pab := publicAccess.PublicAccessBlockConfiguration

			meta.PublicAccessBlock =
				aws.ToBool(pab.BlockPublicAcls) &&
					aws.ToBool(pab.IgnorePublicAcls) &&
					aws.ToBool(pab.BlockPublicPolicy) &&
					aws.ToBool(pab.RestrictPublicBuckets)
		}

		// Logging
		logging, err := s3Client.GetBucketLogging(
			ctx,
			&s3.GetBucketLoggingInput{
				Bucket: &bucketName,
			},
		)

		if err == nil &&
			logging.LoggingEnabled != nil {

			meta.LoggingEnabled = true
		}

		findings := AnalyzeBucket(meta)

		if len(findings) == 0 {
			continue
		}

		if err := saveFindings(
			dynamoClient,
			findings,
		); err != nil {

			log.Printf(
				"failed to save findings for %s: %v",
				bucketName,
				err,
			)
		}
	}

	log.Println("S3 Scan Completed")

	return nil
}

func main() {
	lambda.Start(handler)
}

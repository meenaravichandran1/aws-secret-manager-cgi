package secrets

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func New(secretManagerConfig *SecretManagerConfig) (*secretsmanager.Client, error) {
	ctx := context.Background()
	var awsConfig aws.Config
	var err error

	if secretManagerConfig.Region == "" {
		secretManagerConfig.Region = "us-east-1"
	}

	switch {
	case secretManagerConfig.AssumeIamRoleOnRunner:
		awsConfig, err = loadIAMRoleConfig(ctx, secretManagerConfig.Region)
	case secretManagerConfig.AssumeStsRoleOnRunner:
		awsConfig, err = loadSTSRoleConfig(ctx, secretManagerConfig)
	default:
		awsConfig, err = loadStaticCredentialsConfig(ctx, secretManagerConfig)
	}

	if err != nil {
		logrus.Errorf("Failed to configure AWS client: %v", err)
		return nil, err
	}
	logrus.Infof("Successfully configured AWS client for region: %s", secretManagerConfig.Region)
	return secretsmanager.NewFromConfig(awsConfig), nil
}

func loadIAMRoleConfig(ctx context.Context, region string) (aws.Config, error) {
	logrus.Info("Assuming IAM role on runner")
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

func loadSTSRoleConfig(ctx context.Context, secretManagerConfig *SecretManagerConfig) (aws.Config, error) {
	logrus.Infof("Assuming STS role on runner: %s", secretManagerConfig.RoleArn)
	credProvider, err := getSTSCredentialsProvider(ctx, *secretManagerConfig)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to get STS credentials: %w", err)
	}

	return config.LoadDefaultConfig(ctx,
		config.WithRegion(secretManagerConfig.Region),
		config.WithCredentialsProvider(credProvider),
	)
}

func loadStaticCredentialsConfig(ctx context.Context, secretManagerConfig *SecretManagerConfig) (aws.Config, error) {
	logrus.Info("Using static credentials")
	// TODO check if below checks are needed
	if secretManagerConfig.AccessKey == "" {
		return aws.Config{}, fmt.Errorf("AccessKey not provided")
	}
	if secretManagerConfig.SecretKey == "" {
		return aws.Config{}, fmt.Errorf("SecretKey not provided")
	}
	credProvider := credentials.NewStaticCredentialsProvider(secretManagerConfig.AccessKey, secretManagerConfig.SecretKey, "")
	return config.LoadDefaultConfig(ctx,
		config.WithRegion(secretManagerConfig.Region),
		config.WithCredentialsProvider(credProvider),
	)
}

func getSTSCredentialsProvider(ctx context.Context, secretManagerConfig SecretManagerConfig) (aws.CredentialsProvider, error) {
	if secretManagerConfig.RoleArn == "" {
		return nil, fmt.Errorf("RoleARN must be provided for STS role assumption")
	}

	defaultConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(secretManagerConfig.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load default configuration: %w", err)
	}

	stsClient := sts.NewFromConfig(defaultConfig)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(secretManagerConfig.RoleArn),
		RoleSessionName: aws.String(uuid.New().String()),
		ExternalId:      aws.String(secretManagerConfig.ExternalName),
	}

	if secretManagerConfig.AssumeStsRoleDuration > 0 {
		input.DurationSeconds = aws.Int32(int32(secretManagerConfig.AssumeStsRoleDuration))
	}

	output, err := stsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %w", err)
	}

	return credentials.NewStaticCredentialsProvider(
		*output.Credentials.AccessKeyId,
		*output.Credentials.SecretAccessKey,
		*output.Credentials.SessionToken,
	), nil
}
